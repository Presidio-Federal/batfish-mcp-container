"""
Batfish AWS Trace Route Tool

Traces the path a packet takes from source to destination through AWS infrastructure.
Shows hop-by-hop routing decisions, security group rules, and network ACL evaluations.
"""

import logging
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from pybatfish.client.session import Session
from pybatfish.datamodel import HeaderConstraints, PathConstraints
from .aws_safety_utils import safe_batfish_query, check_network_active

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class TraceRouteInput(BaseModel):
    """Input model for AWS trace route."""
    network: str = Field(..., description="Batfish network name")
    snapshot: str = Field(..., description="Batfish snapshot name")
    source_location: str = Field(..., description="Source location (subnet ID like 'subnet-0c2b80533f81e2ead' or node name)")
    dest_ip: str = Field(..., description="Destination IP address (e.g., '10.0.0.168')")
    dest_port: Optional[int] = Field(None, description="Destination port (e.g., 443, 22, 80)")
    ip_protocol: Optional[str] = Field("tcp", description="IP protocol: tcp, udp, icmp (default: tcp)")
    host: str = Field("localhost", description="Batfish host to connect to")


def execute(input_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Trace the path from source IP to destination IP in AWS infrastructure.
    
    Shows:
    - Routing decisions at each hop
    - Security group permit/deny decisions
    - Network ACL evaluations
    - Final disposition (accepted/denied/dropped)
    
    Args:
        input_data: Dictionary containing network, snapshot, source_ip, dest_ip, and optional dest_port
        
    Returns:
        Dictionary with trace route results including hops, security decisions, and final disposition
    """
    try:
        # Validate input
        validated_input = TraceRouteInput(**input_data)
        
        network = validated_input.network
        snapshot = validated_input.snapshot
        source_location = validated_input.source_location
        dest_ip = validated_input.dest_ip
        dest_port = validated_input.dest_port
        ip_protocol = validated_input.ip_protocol
        host = validated_input.host
        
        logger.info(f"Tracing route in network '{network}', snapshot '{snapshot}' from {source_location} to {dest_ip}:{dest_port}")
        
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
            
            # Build header constraints for the flow
            header_kwargs = {
                "dstIps": dest_ip,
                "ipProtocols": [ip_protocol] if ip_protocol else None
            }
            
            if dest_port is not None:
                header_kwargs["dstPorts"] = str(dest_port)
            
            headers = HeaderConstraints(**header_kwargs)
            
            # Run traceroute query
            logger.info(f"Running traceroute query with protocol={ip_protocol}, port={dest_port}")
            trace_result, error = safe_batfish_query(
                bf,
                "traceroute",
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
                    "source_location": source_location,
                    "dest_ip": dest_ip,
                    "dest_port": dest_port,
                    "protocol": ip_protocol,
                    "traces": [],
                    "warnings": warnings
                }
            
            if trace_result is None or trace_result.empty:
                logger.warning("No trace route found")
                return {
                    "ok": True,
                    "source_location": source_location,
                    "dest_ip": dest_ip,
                    "dest_port": dest_port,
                    "protocol": ip_protocol,
                    "traces": [],
                    "warnings": warnings,
                    "message": "No route found from source to destination"
                }
            
            # Parse trace results
            traces = []
            for _, row in trace_result.iterrows():
                flow = row.get("Flow", "")
                traces_raw = row.get("Traces", [])
                
                # Extract trace information
                for trace in traces_raw:
                    trace_info = {
                        "disposition": str(trace.disposition) if hasattr(trace, 'disposition') else "UNKNOWN",
                        "hops": []
                    }
                    
                    # Parse hops
                    if hasattr(trace, 'hops'):
                        for hop in trace.hops:
                            hop_info = {
                                "node": str(hop.node.name) if hasattr(hop, 'node') and hasattr(hop.node, 'name') else "UNKNOWN",
                                "action": str(hop.action) if hasattr(hop, 'action') else "UNKNOWN"
                            }
                            
                            # Extract routing decision
                            if hasattr(hop, 'routes'):
                                hop_info["routes"] = [str(r) for r in hop.routes[:3]]  # Limit to first 3 routes
                            
                            # Extract filter decisions (security groups, NACLs)
                            if hasattr(hop, 'steps'):
                                filter_steps = []
                                for step in hop.steps:
                                    step_detail = step.detail if hasattr(step, 'detail') else {}
                                    if hasattr(step_detail, 'filter'):
                                        filter_steps.append({
                                            "filter": str(step_detail.filter),
                                            "action": str(step.action) if hasattr(step, 'action') else "UNKNOWN"
                                        })
                                if filter_steps:
                                    hop_info["filter_decisions"] = filter_steps
                            
                            trace_info["hops"].append(hop_info)
                    
                    traces.append(trace_info)
            
            logger.info(f"Found {len(traces)} trace(s)")
            
            # Determine overall result
            dispositions = [t.get("disposition", "UNKNOWN") for t in traces]
            accepted_count = sum(1 for d in dispositions if "ACCEPT" in d.upper())
            denied_count = sum(1 for d in dispositions if "DENIED" in d.upper() or "DROP" in d.upper())
            
            return {
                "ok": True,
                "source_location": source_location,
                "dest_ip": dest_ip,
                "dest_port": dest_port,
                "protocol": ip_protocol,
                "trace_count": len(traces),
                "accepted": accepted_count,
                "denied": denied_count,
                "traces": traces,
                "warnings": warnings,
                "summary": f"{accepted_count} accepted, {denied_count} denied/dropped" if traces else "No traces found"
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
        logger.error(f"Error tracing route: {error_msg}", exc_info=True)
        
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
            "source_location": input_data.get("source_location"),
            "dest_ip": input_data.get("dest_ip"),
            "traces": []
        }


