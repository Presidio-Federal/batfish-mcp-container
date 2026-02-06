"""
Batfish AWS Reachability Tool

Tests traffic reachability between source and destination in AWS infrastructure.
Returns CONCISE results with exact SG rules, NACL rules, route tables, and path taken.
"""

import logging
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field
from pybatfish.client.session import Session
from pybatfish.datamodel import HeaderConstraints
from .aws_safety_utils import safe_batfish_query, check_network_active

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ReachabilityInput(BaseModel):
    """Input model for AWS reachability testing."""
    network: str = Field(..., description="Batfish network name")
    snapshot: str = Field(..., description="Batfish snapshot name")
    source_location: str = Field(..., description="Source location (subnet ID or 'internet')")
    dest_ip: str = Field(..., description="Destination IP address")
    dest_port: Optional[int] = Field(None, description="Destination port")
    protocol: Optional[str] = Field("tcp", description="Protocol: tcp, udp, icmp")
    host: str = Field("localhost", description="Batfish host to connect to")


def execute(input_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Test traffic reachability with CONCISE results.
    
    Returns exact SG rule, NACL rule, route table, and path - optimized for agent consumption.
    
    Args:
        input_data: Dictionary containing network, snapshot, source, destination, protocol, port
        
    Returns:
        Concise dictionary with allowed/denied, rule details, and path
    """
    try:
        # Validate input
        validated_input = ReachabilityInput(**input_data)
        
        network = validated_input.network
        snapshot = validated_input.snapshot
        source_location = validated_input.source_location
        dest_ip = validated_input.dest_ip
        dest_port = validated_input.dest_port
        protocol = validated_input.protocol
        host = validated_input.host
        
        logger.info(f"Testing reachability: {source_location} → {dest_ip}:{dest_port}/{protocol}")
        
        # Initialize Batfish session
        bf = Session(host=host)
        
        try:
            bf.set_network(network)
            bf.set_snapshot(snapshot)
            
            # Check if network is active
            network_status = check_network_active(bf)
            warnings = []
            if not network_status.get("has_nodes"):
                warning = network_status.get("warning")
                if warning:
                    warnings.append(warning)
                    logger.warning(warning)
            
            # Build header constraints
            header_kwargs = {
                "dstIps": dest_ip,
                "ipProtocols": [protocol] if protocol else None
            }
            
            if dest_port is not None:
                header_kwargs["dstPorts"] = str(dest_port)
            
            headers = HeaderConstraints(**header_kwargs)
            
            # Run reachability test using traceroute
            logger.info("Running reachability test...")
            reachability_result, error = safe_batfish_query(
                bf,
                "traceroute_reachability",
                lambda: bf.q.traceroute(
                    startLocation=source_location,
                    headers=headers
                ),
                timeout=30
            )
            
            if error:
                warnings.append(error)
                return {
                    "ok": False,
                    "error": error,
                    "allowed": False,
                    "result": "ERROR",
                    "source": source_location,
                    "destination": dest_ip,
                    "port": dest_port,
                    "protocol": protocol,
                    "warnings": warnings
                }
            
            if reachability_result is None or reachability_result.empty:
                # No path found - traffic is DENIED
                return {
                    "ok": True,
                    "allowed": False,
                    "result": "DENIED",
                    "reason": "No valid path found",
                    "source": source_location,
                    "destination": dest_ip,
                    "port": dest_port,
                    "protocol": protocol,
                    "path": [],
                    "blocking_rule": None
                }
            
            # Parse first flow result
            first_flow = reachability_result.iloc[0]
            flow_info = str(first_flow.get("Flow", ""))
            traces = first_flow.get("Traces", [])
            
            # Determine if traffic is allowed
            is_accepted = False
            disposition = "UNKNOWN"
            path_taken = []
            blocking_rule = None
            route_table = None
            
            if traces:
                first_trace = traces[0]
                disposition = str(first_trace.disposition) if hasattr(first_trace, 'disposition') else "UNKNOWN"
                is_accepted = "ACCEPT" in disposition.upper()
                
                # Extract concise path information
                if hasattr(first_trace, 'hops'):
                    for hop in first_trace.hops:
                        hop_node = str(hop.node.name) if hasattr(hop, 'node') and hasattr(hop.node, 'name') else "unknown"
                        
                        # Extract routing info
                        if hasattr(hop, 'routes') and hop.routes:
                            route = str(hop.routes[0])
                            if 'rtb-' in route:
                                # Extract route table ID
                                route_table = route.split('rtb-')[1].split()[0] if 'rtb-' in route else None
                                route_table = f"rtb-{route_table}" if route_table else None
                        
                        # Extract filter decisions (SG/NACL)
                        if hasattr(hop, 'steps'):
                            for step in hop.steps:
                                step_detail = step.detail if hasattr(step, 'detail') else {}
                                if hasattr(step_detail, 'filter'):
                                    filter_name = str(step_detail.filter)
                                    action = str(step.action) if hasattr(step, 'action') else "UNKNOWN"
                                    
                                    # Store blocking rule if denied
                                    if "DENY" in action.upper() or "DROP" in action.upper():
                                        blocking_rule = {
                                            "type": "sg" if filter_name.startswith("sg-") else "nacl" if filter_name.startswith("acl-") else "unknown",
                                            "id": filter_name,
                                            "action": "DENY"
                                        }
                        
                        path_taken.append(hop_node)
            
            # Build concise response
            return {
                "ok": True,
                "allowed": is_accepted,
                "result": "ALLOWED" if is_accepted else "DENIED",
                "source": source_location,
                "destination": dest_ip,
                "port": dest_port,
                "protocol": protocol,
                "disposition": disposition,
                "path": path_taken,
                "route_table": route_table,
                "blocking_rule": blocking_rule,
                "warnings": warnings,
                "reason": f"Traffic {disposition.lower()}" if disposition != "UNKNOWN" else "Unknown"
            }
        
        finally:
            # CRITICAL: Always close session to prevent hanging/freezing
            try:
                bf.delete_session()
                logger.info("Closed Batfish session")
            except Exception as close_error:
                logger.warning(f"Error closing Batfish session: {close_error}")
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error testing reachability: {error_msg}", exc_info=True)
        
        # Clean up session on error
        if 'bf' in locals():
            try:
                bf.delete_session()
                logger.info("Closed Batfish session after error")
            except Exception:
                pass
        
        return {
            "ok": False,
            "error": error_msg,
            "allowed": False,
            "result": "ERROR"
        }


