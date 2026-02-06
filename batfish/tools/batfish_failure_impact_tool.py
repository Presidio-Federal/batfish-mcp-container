"""
Batfish Failure Impact Tool
Simulate node or interface failure and report traffic impact.
"""

import os
import logging
import json
import traceback
from typing import Dict, Any, Union, List
from enum import Enum
from pydantic import BaseModel, Field
from pybatfish.client.session import Session
from pybatfish.datamodel import HeaderConstraints
import pandas as pd

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# No global Batfish session - will be created per request


class FailureType(str, Enum):
    """Enum for failure types."""
    NODE = "node"
    INTERFACE = "interface"


class FailureImpactInput(BaseModel):
    """Input model for failure impact analysis."""
    network: str = Field(..., description="Logical network name")
    snapshot: str = Field(..., description="Snapshot identifier")
    failure_type: FailureType = Field(..., description="Type of failure to simulate (node or interface)")
    target: str = Field(..., description="Target node or interface to fail")
    host: str = Field("localhost", description="Batfish host to connect to")


class FailureImpactOutput(BaseModel):
    """Output model for failure impact analysis."""
    overall: str = Field(..., description="Overall impact assessment (IMPACT or NO_IMPACT)")
    results: List[Dict[str, Any]] = Field(..., description="Impact analysis results")


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


class FailureImpactTool:
    """Tool for simulating node or interface failures and reporting their impact."""
    
    def _parse_interface_spec(self, interface_spec: str) -> Dict[str, str]:
        """
        Parse an interface specification.
        
        Args:
            interface_spec: Interface specification in the format "node[interface]"
            
        Returns:
            Dictionary with node and interface
        """
        if "[" in interface_spec and "]" in interface_spec:
            parts = interface_spec.split("[")
            node = parts[0]
            interface = parts[1].rstrip("]")
            return {"node": node, "interface": interface}
        else:
            raise ValueError(f"Invalid interface specification: {interface_spec}. Expected format: node[interface]")
    
    def execute(self, input_data: Union[Dict[str, Any], FailureImpactInput]) -> Dict[str, Any]:
        """
        Simulate node or interface failure and report traffic impact.
        
        Args:
            input_data: Input parameters including network, snapshot, failure type, target, and host
                        Can be either a dictionary or FailureImpactInput object
            
        Returns:
            Dictionary containing overall impact assessment and detailed results
        """
        # Handle input as either dictionary or FailureImpactInput object
        if isinstance(input_data, dict):
            try:
                # Convert dictionary to FailureImpactInput
                input_model = FailureImpactInput(**input_data)
            except Exception as e:
                return {
                    "overall": "ERROR",
                    "results": [],
                    "error": f"Invalid input parameters: {str(e)}"
                }
        else:
            # Assume it's already a FailureImpactInput object
            input_model = input_data
        
        # Extract values from the model
        network = input_model.network
        snapshot = input_model.snapshot
        failure_type = input_model.failure_type
        target = input_model.target
        host = input_model.host
        
        logger.info(f"Analyzing failure impact for network '{network}', snapshot '{snapshot}'")
        logger.info(f"Failure type: {failure_type}, Target: {target}")
        
        try:
            # Initialize Batfish session with the provided host
            logger.info(f"Using Batfish host: {host}")
            bf = Session(host=host)
            
            # Set network and snapshot in Batfish
            bf.set_network(network)
            logger.info(f"Set Batfish network to: {network}")
            
            bf.set_snapshot(snapshot)
            logger.info(f"Set Batfish snapshot to: {snapshot}")
            
            # Use fork_snapshot to simulate the failure
            return self._fork_snapshot_failure_impact(bf, network, snapshot, failure_type, target)
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error analyzing failure impact: {error_msg}")
            logger.error(traceback.format_exc())
            
            # Return error response
            return {
                "overall": "ERROR",
                "results": [],
                "error": error_msg
            }
    
    def _get_reachability(self, bf: Session, network, snapshot):
        """Get reachability for a given snapshot"""
        try:
            bf.set_network(network)
            bf.set_snapshot(snapshot)
            
            # Run reachability analysis
            # Run reachability test for baseline (no failures) - use traceroute with no constraints
            reachability_q = bf.q.traceroute(
                headers=HeaderConstraints()
            )
            
            answer = reachability_q.answer()
            result_df = answer.frame()
            
            return result_df
        except Exception as e:
            logger.error(f"Error getting reachability: {str(e)}")
            logger.error(traceback.format_exc())
            return None
    
    def _compare_reachability(self, baseline_df, failure_df):
        """Compare baseline and failure reachability to determine impact"""
        if baseline_df is None or failure_df is None:
            return []
        
        try:
            # Convert DataFrames to serializable format
            baseline_results = dataframe_to_serializable(baseline_df)
            failure_results = dataframe_to_serializable(failure_df)
            
            # Extract flow information for comparison
            baseline_flows = {}
            for result in baseline_results:
                flow_str = result.get("Flow", "")
                baseline_flows[flow_str] = result
            
            failure_flows = {}
            for result in failure_results:
                flow_str = result.get("Flow", "")
                failure_flows[flow_str] = result
            
            # Find flows that are in baseline but not in failure (these are impacted)
            impact_results = []
            for flow_str, baseline_result in baseline_flows.items():
                if flow_str not in failure_flows:
                    # This flow is no longer reachable after failure
                    impact_result = {
                        "flow": self._parse_flow_info(flow_str),
                        "baseline": "REACHABLE",
                        "withFailure": "UNREACHABLE",
                        "evidence": {
                            "baselineTraces": baseline_result.get("Traces", [])
                        }
                    }
                    impact_results.append(impact_result)
            
            return impact_results
        except Exception as e:
            logger.error(f"Error comparing reachability: {str(e)}")
            logger.error(traceback.format_exc())
            return []
    
    def _parse_flow_info(self, flow_str: str) -> Dict[str, Any]:
        """
        Parse flow information from a string representation.
        
        Args:
            flow_str: String representation of a flow
            
        Returns:
            Dictionary with flow details
        """
        flow_info = {
            "src": "",
            "dst": "",
            "srcPort": "",
            "dstPort": "",
            "ipProtocol": ""
        }
        
        try:
            # Extract source node
            import re
            start_match = re.search(r'start=(\w+)', flow_str)
            if start_match:
                flow_info["src"] = start_match.group(1)
            
            # Extract IP addresses
            ip_match = re.search(r'\[([\d\.]+)->([\d\.]+)', flow_str)
            if ip_match:
                flow_info["srcIp"] = ip_match.group(1)
                flow_info["dstIp"] = ip_match.group(2)
            
            # Extract protocol and ports
            if "TCP" in flow_str:
                flow_info["ipProtocol"] = "TCP"
                port_match = re.search(r'TCP \((\d+)->(\d+)\)', flow_str)
                if port_match:
                    flow_info["srcPort"] = port_match.group(1)
                    flow_info["dstPort"] = port_match.group(2)
            elif "UDP" in flow_str:
                flow_info["ipProtocol"] = "UDP"
                port_match = re.search(r'UDP \((\d+)->(\d+)\)', flow_str)
                if port_match:
                    flow_info["srcPort"] = port_match.group(1)
                    flow_info["dstPort"] = port_match.group(2)
            elif "ICMP" in flow_str:
                flow_info["ipProtocol"] = "ICMP"
                icmp_match = re.search(r'ICMP \(type=(\d+), code=(\d+)\)', flow_str)
                if icmp_match:
                    flow_info["icmpType"] = icmp_match.group(1)
                    flow_info["icmpCode"] = icmp_match.group(2)
        except Exception as e:
            logger.error(f"Error parsing flow info: {str(e)}")
        
        return flow_info
    
    def _fork_snapshot_failure_impact(self, bf: Session, network, snapshot, failure_type, target):
        """
        Use fork_snapshot to simulate failure and compare reachability.
        
        This is the proper way to simulate failures in Batfish.
        """
        logger.info("Using fork_snapshot approach for failure impact")
        
        try:
            from pybatfish.datamodel.primitives import Interface
            
            # Create a forked snapshot name
            forked_snapshot_name = f"{snapshot}_failure_{failure_type}_{target.replace('[', '_').replace(']', '')}"
            
            # Fork the snapshot with the failure applied
            if failure_type == FailureType.NODE:
                logger.info(f"Forking snapshot with node '{target}' deactivated")
                forked_name = bf.fork_snapshot(
                    base_name=snapshot,
                    name=forked_snapshot_name,
                    overwrite=True,
                    deactivate_nodes=[target]
                )
            elif failure_type == FailureType.INTERFACE:
                # Parse interface specification
                interface_spec = self._parse_interface_spec(target)
                node = interface_spec["node"]
                interface_name = interface_spec["interface"]
                
                logger.info(f"Forking snapshot with interface '{node}[{interface_name}]' deactivated")
                interface_obj = Interface(hostname=node, interface=interface_name)
                forked_name = bf.fork_snapshot(
                    base_name=snapshot,
                    name=forked_snapshot_name,
                    overwrite=True,
                    deactivate_interfaces=[interface_obj]
                )
            else:
                return {
                    "overall": "ERROR",
                    "results": [],
                    "error": f"Unsupported failure type: {failure_type}"
                }
            
            if not forked_name:
                return {
                    "overall": "ERROR",
                    "results": [],
                    "error": "Failed to create forked snapshot"
                }
            
            logger.info(f"Successfully created forked snapshot: {forked_name}")
            
            # Get baseline reachability (original snapshot)
            logger.info("Getting baseline reachability...")
            bf.set_snapshot(snapshot)
            baseline_df = self._get_reachability(bf, network, snapshot)
            
            # Get failure reachability (forked snapshot)
            logger.info("Getting failure scenario reachability...")
            bf.set_snapshot(forked_name)
            failure_df = self._get_reachability(bf, network, forked_name)
            
            # Compare reachability to determine impact
            logger.info("Comparing baseline and failure scenarios...")
            impact_results = self._compare_reachability(baseline_df, failure_df)
            
            # Clean up forked snapshot
            try:
                logger.info(f"Cleaning up forked snapshot: {forked_name}")
                bf.delete_snapshot(forked_name)
            except Exception as e:
                logger.warning(f"Failed to clean up forked snapshot: {e}")
            
            # Determine overall impact
            if impact_results and len(impact_results) > 0:
                overall = "IMPACT"
            else:
                overall = "NO_IMPACT"
            
            return {
                "overall": overall,
                "results": impact_results,
                "summary": f"Found {len(impact_results)} impacted flows" if impact_results else "No traffic impact detected"
            }
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in fork_snapshot failure impact: {error_msg}")
            logger.error(traceback.format_exc())
            
            # Return error response
            return {
                "overall": "ERROR",
                "results": [],
                "error": error_msg
            }
    
    def _simple_failure_impact(self, bf: Session, network, snapshot, failure_type, target):
        """Very simple approach for failure impact when other methods fail"""
        logger.info("Using simple approach for failure impact")
        
        try:
            # Network and snapshot should already be set in the bf session
            
            # Get all nodes
            nodes_df = bf.q.nodeProperties().answer().frame()
            node_list = list(nodes_df["Node"])
            
            # Create a simple impact assessment
            if failure_type == FailureType.NODE:
                if target not in node_list:
                    return {
                        "overall": "ERROR",
                        "results": [],
                        "error": f"Node '{target}' not found in snapshot"
                    }
                
                # For node failure, assume impact if there are other nodes
                if len(node_list) > 1:
                    # Create a simple impact result for each other node
                    impact_results = []
                    for node in node_list:
                        if node != target:
                            impact_result = {
                                "flow": {
                                    "src": node,
                                    "dst": target,
                                    "ipProtocol": "ANY"
                                },
                                "baseline": "CONNECTED",
                                "withFailure": "DISCONNECTED",
                                "evidence": {
                                    "reason": f"Node {target} would be unavailable"
                                }
                            }
                            impact_results.append(impact_result)
                    
                    return {
                        "overall": "IMPACT",
                        "results": impact_results
                    }
                else:
                    return {
                        "overall": "NO_IMPACT",
                        "results": []
                    }
            
            elif failure_type == FailureType.INTERFACE:
                # Parse interface specification
                interface_spec = self._parse_interface_spec(target)
                node = interface_spec["node"]
                interface = interface_spec["interface"]
                
                if node not in node_list:
                    return {
                        "overall": "ERROR",
                        "results": [],
                        "error": f"Node '{node}' not found in snapshot"
                    }
                
                # Get interfaces for the node
                interfaces_df = bf.q.interfaceProperties().answer().frame()
                interfaces_df = interfaces_df[interfaces_df["Interface"].str.startswith(f"{node}[")]
                
                if len(interfaces_df) > 1:
                    # Create a simple impact result
                    impact_result = {
                        "flow": {
                            "src": "ANY",
                            "dst": "ANY",
                            "ipProtocol": "ANY"
                        },
                        "baseline": "CONNECTED",
                        "withFailure": "POTENTIALLY_DISCONNECTED",
                        "evidence": {
                            "reason": f"Interface {node}[{interface}] would be unavailable"
                        }
                    }
                    
                    return {
                        "overall": "IMPACT",
                        "results": [impact_result]
                    }
                else:
                    return {
                        "overall": "NO_IMPACT",
                        "results": []
                    }
            
            # This should not happen due to Pydantic validation
            return {
                "overall": "ERROR",
                "results": [],
                "error": f"Unsupported failure type: {failure_type}"
            }
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in simple failure impact: {error_msg}")
            logger.error(traceback.format_exc())
            
            # Return error response
            return {
                "overall": "ERROR",
                "results": [],
                "error": error_msg
            }


# Create singleton instance for FastMCP
failure_impact_tool = FailureImpactTool()
