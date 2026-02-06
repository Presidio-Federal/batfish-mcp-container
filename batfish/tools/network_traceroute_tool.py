"""
Network Traceroute Tool

Traces the path a packet takes from source to destination through traditional network infrastructure
(routers, switches, firewalls). Shows hop-by-hop routing decisions and ACL evaluations.
"""

import logging
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from pybatfish.client.session import Session
from pybatfish.datamodel import HeaderConstraints

# Import safety utilities
try:
    from .aws_safety_utils import safe_batfish_query
except ImportError:
    try:
        from tools.aws_safety_utils import safe_batfish_query
    except ImportError:
        from aws_safety_utils import safe_batfish_query

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class NetworkTracerouteInput(BaseModel):
    """Input model for network traceroute."""
    network: str = Field(..., description="Batfish network name")
    snapshot: str = Field(..., description="Batfish snapshot name")
    source_location: str = Field(..., description="Source location (node name, interface, or IP)")
    dest_ip: str = Field(..., description="Destination IP address (e.g., '10.0.0.168')")
    dest_port: Optional[int] = Field(None, description="Destination port (e.g., 443, 22, 80)")
    ip_protocol: Optional[str] = Field("tcp", description="IP protocol: tcp, udp, icmp (default: tcp)")
    src_ip: Optional[str] = Field(None, description="Source IP address (optional, useful for multi-homed devices)")
    host: str = Field("localhost", description="Batfish host to connect to")


class NetworkTracerouteTool:
    """
    Tool for tracing packet paths through traditional network infrastructure.
    
    Supports analyzing:
    - Routing decisions at each hop
    - ACL permit/deny decisions
    - NAT transformations
    - Final disposition (accepted/denied/dropped)
    """

    def execute(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Trace the path from source to destination through network devices.
        
        Args:
            input_data: Dictionary containing network, snapshot, source_location, dest_ip, and optional parameters
            
        Returns:
            Dictionary with trace route results including hops, ACL decisions, and final disposition
        """
        try:
            # Validate input
            validated_input = NetworkTracerouteInput(**input_data)
            
            network = validated_input.network
            snapshot = validated_input.snapshot
            source_location = validated_input.source_location
            dest_ip = validated_input.dest_ip
            dest_port = validated_input.dest_port
            ip_protocol = validated_input.ip_protocol
            src_ip = validated_input.src_ip
            host = validated_input.host
            
            logger.info(f"Tracing route in network '{network}', snapshot '{snapshot}' from {source_location} to {dest_ip}:{dest_port}")
            
            # Initialize Batfish session
            bf = Session(host=host)
            bf.set_network(network)
            bf.set_snapshot(snapshot)
            
            logger.info(f"Connected to Batfish host: {host}")
            
            # Build header constraints for the flow
            header_kwargs = {
                "dstIps": dest_ip,
                "ipProtocols": [ip_protocol] if ip_protocol else None
            }
            
            if src_ip:
                header_kwargs["srcIps"] = src_ip
            
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
                timeout=45  # Network traceroutes can be more complex
            )
            
            if error:
                return {
                    "ok": False,
                    "error": error,
                    "source_location": source_location,
                    "dest_ip": dest_ip,
                    "dest_port": dest_port,
                    "protocol": ip_protocol,
                    "traces": []
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
                            # Try multiple ways to extract node name
                            node_name = "UNKNOWN"
                            if hasattr(hop, 'node'):
                                if hasattr(hop.node, 'name'):
                                    node_name = str(hop.node.name)
                                elif hasattr(hop.node, 'hostname'):
                                    node_name = str(hop.node.hostname)
                                else:
                                    node_name = str(hop.node)
                            
                            hop_info = {
                                "node": node_name,
                                "action": str(hop.action) if hasattr(hop, 'action') else "UNKNOWN"
                            }
                            
                            # Extract interface information
                            if hasattr(hop, 'node'):
                                if hasattr(hop.node, 'interface'):
                                    hop_info["interface"] = str(hop.node.interface)
                                elif hasattr(hop.node, 'interfaceName'):
                                    hop_info["interface"] = str(hop.node.interfaceName)
                            
                            # Extract routing decision
                            if hasattr(hop, 'routes'):
                                routes_info = []
                                for r in hop.routes[:3]:  # Limit to first 3 routes
                                    route_str = str(r)
                                    routes_info.append(route_str)
                                hop_info["routes"] = routes_info
                            
                            # Extract filter decisions (ACLs, firewalls)
                            if hasattr(hop, 'steps'):
                                filter_steps = []
                                for step in hop.steps:
                                    step_detail = step.detail if hasattr(step, 'detail') else {}
                                    
                                    # Filter decisions
                                    if hasattr(step_detail, 'filter'):
                                        filter_steps.append({
                                            "filter": str(step_detail.filter),
                                            "action": str(step.action) if hasattr(step, 'action') else "UNKNOWN",
                                            "type": "ACL"
                                        })
                                    
                                    # NAT transformations
                                    if hasattr(step_detail, 'transformedFlow'):
                                        filter_steps.append({
                                            "type": "NAT",
                                            "transformation": str(step_detail.transformedFlow),
                                            "action": str(step.action) if hasattr(step, 'action') else "UNKNOWN"
                                        })
                                
                                if filter_steps:
                                    hop_info["filter_decisions"] = filter_steps
                            
                            # Extract transformations (NAT, PAT)
                            if hasattr(hop, 'transformedFlow'):
                                hop_info["transformed_flow"] = str(hop.transformedFlow)
                            
                            trace_info["hops"].append(hop_info)
                    
                    traces.append(trace_info)
            
            logger.info(f"Found {len(traces)} trace(s)")
            
            # Determine overall result
            dispositions = [t.get("disposition", "UNKNOWN") for t in traces]
            accepted_count = sum(1 for d in dispositions if "ACCEPT" in d.upper())
            denied_count = sum(1 for d in dispositions if "DENIED" in d.upper() or "DROP" in d.upper())
            
            # Extract path summary
            path_summary = []
            if traces and traces[0].get("hops"):
                path_summary = [hop.get("node", "UNKNOWN") for hop in traces[0]["hops"]]
            
            return {
                "ok": True,
                "source_location": source_location,
                "dest_ip": dest_ip,
                "dest_port": dest_port,
                "protocol": ip_protocol,
                "trace_count": len(traces),
                "accepted": accepted_count,
                "denied": denied_count,
                "path_summary": path_summary,
                "traces": traces,
                "summary": f"{accepted_count} accepted, {denied_count} denied/dropped" if traces else "No traces found"
            }
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error tracing route: {error_msg}", exc_info=True)
            return {
                "ok": False,
                "error": error_msg,
                "source_location": input_data.get("source_location"),
                "dest_ip": input_data.get("dest_ip"),
                "traces": []
            }


# Create singleton instance
network_traceroute_tool = NetworkTracerouteTool()

