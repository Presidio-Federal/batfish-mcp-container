"""
Batfish Check Routing Tool
Check routing/control plane health (BGP sessions, OSPF adjacencies).
"""

import os
import logging
import json
import traceback
from typing import Dict, Any, Union, List
from enum import Enum
from pydantic import BaseModel, Field
from pybatfish.client.session import Session
import pandas as pd

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# No global Batfish session - will be created per request


class ProtocolType(str, Enum):
    """Enum for supported routing protocols."""
    OSPF = "ospf"
    BGP = "bgp"


class CheckRoutingInput(BaseModel):
    """Input model for routing health check."""
    network: str = Field(..., description="Logical network name")
    snapshot: str = Field(..., description="Snapshot identifier")
    protocols: List[ProtocolType] = Field(..., description="List of routing protocols to check")
    host: str = Field("localhost", description="Batfish host to connect to")


class ProtocolResult(BaseModel):
    """Model for individual protocol check result."""
    protocol: str = Field(..., description="Protocol name")
    status: str = Field(..., description="Check status (PASS or FAIL)")
    evidence: Any = Field(None, description="Check evidence or details")


class CheckRoutingOutput(BaseModel):
    """Output model for routing health check."""
    overall: str = Field(..., description="Overall check status (PASS or FAIL)")
    results: List[ProtocolResult] = Field(..., description="Individual protocol check results")


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


class CheckRoutingTool:
    """Tool for checking routing/control plane health."""
    
    def _check_ospf(self, bf: Session) -> Dict[str, Any]:
        """Check OSPF configuration and status using available questions."""
        logger.info("Checking OSPF configuration and status")
        
        try:
            # Use ospfProcessConfiguration as seen in your terminal output
            logger.info("Checking OSPF process configuration")
            ospf_process_df = bf.q.ospfProcessConfiguration().answer().frame()
            
            if not ospf_process_df.empty:
                logger.info(f"Found {len(ospf_process_df)} OSPF processes")
                
                # Convert DataFrame to serializable format for evidence
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
                
                logger.info(f"OSPF check: {summary}")
                return {
                    "protocol": "ospf",
                    "status": status,
                    "evidence": {
                        "processes": evidence,
                        "summary": summary
                    }
                }
            else:
                logger.info("No OSPF processes found")
                
                # Fall back to checking interfaces if no processes found
                return self._check_ospf_interfaces(bf)
        
        except Exception as e:
            logger.error(f"Error checking OSPF processes: {str(e)}")
            logger.error(traceback.format_exc())
            
            # Fall back to checking interfaces if process check fails
            return self._check_ospf_interfaces(bf)
    
    def _check_ospf_interfaces(self, bf: Session) -> Dict[str, Any]:
        """Check for OSPF-enabled interfaces."""
        logger.info("Falling back to checking interfaces with OSPF enabled")
        
        try:
            # Use interfaceProperties to find interfaces with OSPF enabled
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
                
                logger.info(f"OSPF check: {summary}")
                return {
                    "protocol": "ospf",
                    "status": status,
                    "evidence": {
                        "interfaces": evidence,
                        "summary": summary
                    }
                }
            else:
                logger.info("No OSPF interfaces found")
                
                # Fall back to checking node configuration
                return self._check_ospf_in_config(bf)
        
        except Exception as e:
            logger.error(f"Error checking OSPF interfaces: {str(e)}")
            logger.error(traceback.format_exc())
            
            # Fall back to checking node configuration
            return self._check_ospf_in_config(bf)
    
    def _check_ospf_in_config(self, bf: Session) -> Dict[str, Any]:
        """Check for OSPF in node configuration."""
        logger.info("Falling back to checking node configuration for OSPF")
        
        try:
            # Check node properties for OSPF configuration
            nodes_df = bf.q.nodeProperties().answer().frame()
            
            # Try to find nodes with OSPF configuration
            ospf_nodes = []
            try:
                if "OSPF_Process_ID" in nodes_df.columns:
                    ospf_nodes = nodes_df[nodes_df["OSPF_Process_ID"].notnull()]
                elif "Configuration" in nodes_df.columns:
                    # Look for OSPF in the configuration
                    ospf_nodes = nodes_df[nodes_df["Configuration"].apply(
                        lambda x: "ospf" in str(x).lower()
                    )]
            except Exception as e:
                logger.warning(f"Error checking for OSPF nodes: {str(e)}")
            
            if len(ospf_nodes) > 0:
                logger.info(f"Found {len(ospf_nodes)} nodes with OSPF configuration")
                evidence = dataframe_to_serializable(ospf_nodes)
                return {
                    "protocol": "ospf",
                    "status": "PASS",
                    "evidence": {
                        "nodes": evidence,
                        "summary": f"Found {len(ospf_nodes)} nodes with OSPF configuration"
                    }
                }
            else:
                logger.info("No OSPF configuration found in nodes")
                return {
                    "protocol": "ospf",
                    "status": "FAIL",
                    "evidence": "No OSPF configuration found"
                }
        
        except Exception as e:
            logger.error(f"Error checking OSPF in node configuration: {str(e)}")
            logger.error(traceback.format_exc())
            return {
                "protocol": "ospf",
                "status": "FAIL",
                "evidence": f"Error checking OSPF: {str(e)}"
            }
    
    def _check_bgp(self, bf: Session) -> Dict[str, Any]:
        """Check BGP configuration and status using available questions."""
        logger.info("Checking BGP configuration and status")
        
        try:
            # Try to use bgpProcessConfiguration if available
            try:
                logger.info("Checking BGP process configuration")
                bgp_process_df = bf.q.bgpProcessConfiguration().answer().frame()
                
                if not bgp_process_df.empty:
                    logger.info(f"Found {len(bgp_process_df)} BGP processes")
                    evidence = dataframe_to_serializable(bgp_process_df)
                    return {
                        "protocol": "bgp",
                        "status": "PASS",
                        "evidence": {
                            "processes": evidence,
                            "summary": f"Found {len(bgp_process_df)} BGP processes"
                        }
                    }
            except Exception as e:
                logger.warning(f"bgpProcessConfiguration not available: {str(e)}")
            
            # If bgpProcessConfiguration isn't available, try nodeProperties
            logger.info("Checking node properties for BGP configuration")
            nodes_df = bf.q.nodeProperties().answer().frame()
            
            # Try to find nodes with BGP configuration
            bgp_nodes = []
            try:
                if "BGP_Process_ID" in nodes_df.columns:
                    bgp_nodes = nodes_df[nodes_df["BGP_Process_ID"].notnull()]
                elif "Configuration" in nodes_df.columns:
                    # Look for BGP in the configuration
                    bgp_nodes = nodes_df[nodes_df["Configuration"].apply(
                        lambda x: "bgp" in str(x).lower()
                    )]
            except Exception as e:
                logger.warning(f"Error checking for BGP nodes: {str(e)}")
            
            if len(bgp_nodes) > 0:
                logger.info(f"Found {len(bgp_nodes)} nodes with BGP configuration")
                evidence = dataframe_to_serializable(bgp_nodes)
                return {
                    "protocol": "bgp",
                    "status": "PASS",
                    "evidence": {
                        "nodes": evidence,
                        "summary": f"Found {len(bgp_nodes)} nodes with BGP configuration"
                    }
                }
            else:
                logger.info("No BGP configuration found")
                return {
                    "protocol": "bgp",
                    "status": "FAIL",
                    "evidence": "No BGP configuration found"
                }
        
        except Exception as e:
            logger.error(f"Error checking BGP: {str(e)}")
            logger.error(traceback.format_exc())
            return {
                "protocol": "bgp",
                "status": "FAIL",
                "evidence": f"Error checking BGP: {str(e)}"
            }
    
    def execute(self, input_data: Union[Dict[str, Any], CheckRoutingInput]) -> Dict[str, Any]:
        """
        Check routing/control plane health.
        
        Args:
            input_data: Input parameters including network, snapshot, protocols, and host
                        Can be either a dictionary or CheckRoutingInput object
            
        Returns:
            Dictionary containing overall status and individual protocol check results
        """
        # Handle input as either dictionary or CheckRoutingInput object
        if isinstance(input_data, dict):
            try:
                # Convert dictionary to CheckRoutingInput
                input_model = CheckRoutingInput(**input_data)
            except Exception as e:
                return {
                    "overall": "FAIL",
                    "results": [],
                    "error": f"Invalid input parameters: {str(e)}"
                }
        else:
            # Assume it's already a CheckRoutingInput object
            input_model = input_data
        
        # Extract values from the model
        network = input_model.network
        snapshot = input_model.snapshot
        protocols = input_model.protocols
        host = input_model.host
        
        # Convert enum values to strings if needed
        protocol_names = [p if isinstance(p, str) else p.value for p in protocols]
        
        logger.info(f"Checking routing health for network '{network}', snapshot '{snapshot}'")
        logger.info(f"Protocols to check: {protocol_names}")
        
        try:
            # Initialize Batfish session with the provided host
            logger.info(f"Using Batfish host: {host}")
            bf = Session(host=host)
            
            # Set network and snapshot in Batfish
            bf.set_network(network)
            logger.info(f"Set Batfish network to: {network}")
            
            bf.set_snapshot(snapshot)
            logger.info(f"Set Batfish snapshot to: {snapshot}")
            
            # Check each protocol
            results = []
            for protocol in protocol_names:
                if protocol.lower() == "ospf":
                    results.append(self._check_ospf(bf))
                elif protocol.lower() == "bgp":
                    results.append(self._check_bgp(bf))
                else:
                    # This should not happen due to Pydantic validation, but just in case
                    logger.warning(f"Unsupported protocol: {protocol}")
                    results.append({
                        "protocol": protocol,
                        "status": "FAIL",
                        "evidence": f"Unsupported protocol: {protocol}"
                    })
            
            # Determine overall status
            overall = "PASS" if all(result["status"] == "PASS" for result in results) else "FAIL"
            
            logger.info(f"Routing health check completed with overall status: {overall}")
            
            # Return results
            return {
                "overall": overall,
                "results": results
            }
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error checking routing health: {error_msg}")
            logger.error(traceback.format_exc())
            
            # Return error response
            return {
                "overall": "FAIL",
                "results": [],
                "error": error_msg
            }


# Create singleton instance for FastMCP
check_routing_tool = CheckRoutingTool()
