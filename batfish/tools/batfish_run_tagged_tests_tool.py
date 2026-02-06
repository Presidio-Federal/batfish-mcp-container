"""
Batfish Run Tagged Tests Tool
Runs simple built-in Batfish queries mapped to tags.
"""

import os
import logging
import json
import pandas as pd
from typing import Dict, Any, List, Union
from pydantic import BaseModel, Field
from pybatfish.client.session import Session

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# No global Batfish session - will be created per request


class RunTaggedTestsInput(BaseModel):
    """Input model for running tagged Batfish tests."""
    network: str = Field(..., description="Logical network name")
    snapshot: str = Field(..., description="Snapshot identifier")
    tags: List[str] = Field(..., description="List of test tags to run")
    host: str = Field("localhost", description="Batfish host to connect to")


class TestResult(BaseModel):
    """Model for individual test result."""
    id: str = Field(..., description="Test identifier")
    status: str = Field(..., description="Test status (PASS, FAIL, UNKNOWN)")
    evidence: Any = Field(None, description="Test evidence or details")


class RunTaggedTestsOutput(BaseModel):
    """Output model for tagged tests results."""
    overall: str = Field(..., description="Overall test status (PASS or FAIL)")
    results: List[TestResult] = Field(..., description="Individual test results")


class BatfishEncoder(json.JSONEncoder):
    """Custom JSON encoder for Batfish objects."""
    def default(self, obj):
        # Convert any non-serializable objects to strings
        try:
            return super().default(obj)
        except TypeError:
            return str(obj)


def dataframe_to_serializable(df):
    """
    Convert a pandas DataFrame to a serializable format,
    handling Batfish-specific objects.
    """
    if df.empty:
        return []
    
    # First convert to dict
    records = df.to_dict(orient="records")
    
    # Then convert to JSON and back to handle any non-serializable objects
    json_str = json.dumps(records, cls=BatfishEncoder)
    return json.loads(json_str)


class RunTaggedTestsTool:
    """Tool for running tagged Batfish tests."""
    
    def _run_reachability_test(self, bf: Session) -> Dict[str, Any]:
        """Run reachability test using Batfish."""
        try:
            logger.info("Running reachability test")
            # Run reachability query
            result_df = bf.q.reachability().answer().frame()
            
            # Process results
            if result_df.empty:
                logger.info("Reachability test: No results found")
                return {
                    "id": "reachability",
                    "status": "FAIL",
                    "evidence": "No reachability data found"
                }
            
            # Check if there are any unreachable flows
            if "Flow" in result_df.columns and len(result_df) > 0:
                # Convert DataFrame to serializable format
                evidence = dataframe_to_serializable(result_df)
                logger.info(f"Reachability test: Found {len(evidence)} flows")
                return {
                    "id": "reachability",
                    "status": "PASS",
                    "evidence": evidence
                }
            else:
                return {
                    "id": "reachability",
                    "status": "FAIL",
                    "evidence": "Invalid reachability data format"
                }
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Reachability test error: {error_msg}")
            return {
                "id": "reachability",
                "status": "FAIL",
                "evidence": f"Error: {error_msg}"
            }
    
    def _run_ospf_test(self, bf: Session) -> Dict[str, Any]:
        """Run OSPF configuration test using Batfish."""
        try:
            logger.info("Running OSPF test")
            
            # First try ospfProcessConfiguration
            try:
                logger.info("Checking OSPF process configuration")
                ospf_process_df = bf.q.ospfProcessConfiguration().answer().frame()
                
                if not ospf_process_df.empty:
                    logger.info(f"Found {len(ospf_process_df)} OSPF processes")
                    
                    # Convert DataFrame to serializable format
                    evidence = dataframe_to_serializable(ospf_process_df)
                    
                    # Check if there are any OSPF areas configured
                    areas_configured = True
                    try:
                        for _, row in ospf_process_df.iterrows():
                            if not row.get("Areas") or len(row.get("Areas", [])) == 0:
                                areas_configured = False
                                break
                    except Exception as e:
                        logger.warning(f"Error checking OSPF areas: {str(e)}")
                        areas_configured = False
                    
                    if areas_configured:
                        status = "PASS"
                        summary = f"Found {len(ospf_process_df)} OSPF processes with areas configured"
                    else:
                        status = "FAIL"
                        summary = f"Found {len(ospf_process_df)} OSPF processes but some have no areas configured"
                    
                    logger.info(f"OSPF test: {summary}")
                    return {
                        "id": "ospf",
                        "status": status,
                        "evidence": {
                            "processes": evidence,
                            "summary": summary
                        }
                    }
            except Exception as e:
                logger.warning(f"Error checking OSPF process configuration: {str(e)}")
            
            # Fall back to checking interfaces
            try:
                logger.info("Checking for interfaces with OSPF enabled")
                interfaces_df = bf.q.interfaceProperties().answer().frame()
                
                # Filter for OSPF-enabled interfaces
                ospf_interfaces = []
                
                try:
                    # Try to find OSPF configuration in different ways
                    if "OSPF_Enabled" in interfaces_df.columns:
                        ospf_interfaces = interfaces_df[interfaces_df["OSPF_Enabled"] == True]
                    elif "OSPF_Area" in interfaces_df.columns:
                        ospf_interfaces = interfaces_df[interfaces_df["OSPF_Area"].notnull()]
                    else:
                        # Look for OSPF in the protocol dependencies
                        if "Protocol_Dependencies" in interfaces_df.columns:
                            ospf_interfaces = interfaces_df[interfaces_df["Protocol_Dependencies"].apply(
                                lambda x: isinstance(x, list) and any("OSPF" in str(dep) for dep in x)
                            )]
                except Exception as e:
                    logger.warning(f"Error filtering OSPF interfaces: {str(e)}")
                
                # If we found OSPF interfaces
                if len(ospf_interfaces) > 0:
                    logger.info(f"Found {len(ospf_interfaces)} interfaces with OSPF enabled")
                    
                    # Check for IP addresses on OSPF interfaces
                    interfaces_with_ip = ospf_interfaces[ospf_interfaces["Primary_Address"].notnull()]
                    
                    # Convert DataFrame to serializable format for evidence
                    evidence = dataframe_to_serializable(ospf_interfaces)
                    
                    if len(interfaces_with_ip) > 0:
                        status = "PASS"
                        summary = f"Found {len(interfaces_with_ip)} interfaces with OSPF enabled and IP addresses"
                    else:
                        status = "FAIL"
                        summary = "Found OSPF interfaces but none have IP addresses"
                    
                    logger.info(f"OSPF test: {summary}")
                    return {
                        "id": "ospf",
                        "status": status,
                        "evidence": {
                            "interfaces": evidence,
                            "summary": summary
                        }
                    }
            except Exception as e:
                logger.warning(f"Error checking OSPF interfaces: {str(e)}")
            
            # Fall back to checking node configuration
            try:
                logger.info("Checking node configuration for OSPF")
                nodes_df = bf.q.nodeProperties().answer().frame()
                
                # Look for OSPF in the configuration
                ospf_nodes = []
                
                if "Configuration" in nodes_df.columns:
                    ospf_nodes = nodes_df[nodes_df["Configuration"].apply(
                        lambda x: "ospf" in str(x).lower()
                    )]
                
                if len(ospf_nodes) > 0:
                    logger.info(f"Found {len(ospf_nodes)} nodes with OSPF configuration")
                    evidence = dataframe_to_serializable(ospf_nodes)
                    return {
                        "id": "ospf",
                        "status": "PASS",
                        "evidence": {
                            "nodes": evidence,
                            "summary": f"Found {len(ospf_nodes)} nodes with OSPF configuration"
                        }
                    }
            except Exception as e:
                logger.warning(f"Error checking OSPF in node configuration: {str(e)}")
            
            # If all checks failed, return failure
            logger.info("No OSPF configuration found")
            return {
                "id": "ospf",
                "status": "FAIL",
                "evidence": "No OSPF configuration found"
            }
        except Exception as e:
            error_msg = str(e)
            logger.error(f"OSPF test error: {error_msg}")
            return {
                "id": "ospf",
                "status": "FAIL",
                "evidence": f"Error: {error_msg}"
            }
    
    def _run_interfaces_test(self, bf: Session) -> Dict[str, Any]:
        """Run interface properties test using Batfish."""
        try:
            logger.info("Running interfaces test")
            # Run interface properties query
            result_df = bf.q.interfaceProperties().answer().frame()
            
            # Process results
            if result_df.empty:
                logger.info("Interfaces test: No results found")
                return {
                    "id": "interfaces",
                    "status": "FAIL",
                    "evidence": "No interface data found"
                }
            
            # Check if there are any valid interfaces
            if "Interface" in result_df.columns and len(result_df) > 0:
                # Convert DataFrame to serializable format
                evidence = dataframe_to_serializable(result_df)
                logger.info(f"Interfaces test: Found {len(evidence)} interfaces")
                return {
                    "id": "interfaces",
                    "status": "PASS",
                    "evidence": evidence
                }
            else:
                return {
                    "id": "interfaces",
                    "status": "FAIL",
                    "evidence": "Invalid interface data format"
                }
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Interfaces test error: {error_msg}")
            return {
                "id": "interfaces",
                "status": "FAIL",
                "evidence": f"Error: {error_msg}"
            }
    
    def execute(self, input_data: Union[Dict[str, Any], RunTaggedTestsInput]) -> Dict[str, Any]:
        """
        Run tagged Batfish tests.
        
        Args:
            input_data: Input parameters including network, snapshot, tags, and host
                        Can be either a dictionary or RunTaggedTestsInput object
            
        Returns:
            Dictionary containing overall status and individual test results
        """
        # Handle input as either dictionary or RunTaggedTestsInput object
        if isinstance(input_data, dict):
            try:
                # Convert dictionary to RunTaggedTestsInput
                input_model = RunTaggedTestsInput(**input_data)
            except Exception as e:
                return {
                    "overall": "FAIL",
                    "results": [],
                    "error": f"Invalid input parameters: {str(e)}"
                }
        else:
            input_model = input_data
        
        # Extract values from the model
        network = input_model.network
        snapshot = input_model.snapshot
        tags = input_model.tags
        host = input_model.host
        
        logger.info(f"Running tagged tests for network '{network}', snapshot '{snapshot}'")
        logger.info(f"Tags to run: {tags}")
        
        try:
            # Initialize Batfish session with the provided host
            logger.info(f"Using Batfish host: {host}")
            bf = Session(host=host)
            
            # Set network and snapshot in Batfish
            bf.set_network(network)
            logger.info(f"Set Batfish network to: {network}")
            
            bf.set_snapshot(snapshot)
            logger.info(f"Set Batfish snapshot to: {snapshot}")
            
            # Run tests for each tag
            results = []
            for tag in tags:
                if tag == "reachability":
                    results.append(self._run_reachability_test(bf))
                elif tag == "ospf":
                    results.append(self._run_ospf_test(bf))
                elif tag == "interfaces":
                    results.append(self._run_interfaces_test(bf))
                else:
                    # Skip unknown tags
                    logger.warning(f"Unknown tag: {tag}")
                    results.append({
                        "id": tag,
                        "status": "UNKNOWN",
                        "evidence": f"Unknown tag: {tag}"
                    })
            
            # Determine overall status
            has_failures = any(result["status"] == "FAIL" for result in results)
            overall = "FAIL" if has_failures else "PASS"
            
            logger.info(f"Tests completed with overall status: {overall}")
            
            # Return results
            return {
                "overall": overall,
                "results": results
            }
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error running tagged tests: {error_msg}")
            
            # Return error response
            return {
                "overall": "FAIL",
                "results": [],
                "error": error_msg
            }


# Create singleton instance for FastMCP
run_tagged_tests_tool = RunTaggedTestsTool()
