"""
Network Bidirectional Reachability Tool

Tests traffic reachability in both directions between source and destination through traditional
network infrastructure. This is critical for protocols that require bidirectional communication
(e.g., TCP handshakes, stateless firewalls, symmetric routing validation).
"""

import logging
from typing import Dict, Any, Optional
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


class NetworkBidirectionalReachabilityInput(BaseModel):
    """Input model for bidirectional reachability testing."""
    network: str = Field(..., description="Batfish network name")
    snapshot: str = Field(..., description="Batfish snapshot name")
    location_a: str = Field(..., description="Location A (node name, interface, or IP)")
    location_b: str = Field(..., description="Location B (node name, interface, or IP)")
    ip_a: str = Field(..., description="IP address at location A")
    ip_b: str = Field(..., description="IP address at location B")
    port: Optional[int] = Field(None, description="Port to test (e.g., 443, 22, 80)")
    protocol: Optional[str] = Field("tcp", description="Protocol: tcp, udp, icmp (default: tcp)")
    host: str = Field("localhost", description="Batfish host to connect to")


class NetworkBidirectionalReachabilityTool:
    """
    Tool for testing bidirectional reachability through traditional network infrastructure.
    
    Tests both directions:
    - Forward: A → B
    - Reverse: B → A
    
    Critical for validating:
    - TCP communication (requires bidirectional flow)
    - Stateless firewalls
    - Asymmetric routing detection
    - Return path validation
    """

    def execute(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Test reachability in both directions between two locations.
        
        Args:
            input_data: Dictionary containing network, snapshot, both locations, IPs, port, protocol
            
        Returns:
            Dictionary with bidirectional reachability results
        """
        try:
            # Validate input
            validated_input = NetworkBidirectionalReachabilityInput(**input_data)
            
            network = validated_input.network
            snapshot = validated_input.snapshot
            location_a = validated_input.location_a
            location_b = validated_input.location_b
            ip_a = validated_input.ip_a
            ip_b = validated_input.ip_b
            port = validated_input.port
            protocol = validated_input.protocol
            host = validated_input.host
            
            logger.info(f"Testing bidirectional reachability in network '{network}', snapshot '{snapshot}'")
            logger.info(f"A: {location_a} ({ip_a}) ↔ B: {location_b} ({ip_b})")
            
            # Initialize Batfish session
            bf = Session(host=host)
            bf.set_network(network)
            bf.set_snapshot(snapshot)
            
            logger.info(f"Connected to Batfish host: {host}")
            
            # Test forward direction: A → B
            logger.info("Testing forward direction: A → B")
            forward_result = self._test_direction(
                bf=bf,
                source_location=location_a,
                source_ip=ip_a,
                dest_ip=ip_b,
                dest_port=port,
                protocol=protocol,
                direction="forward"
            )
            
            # Test reverse direction: B → A
            logger.info("Testing reverse direction: B → A")
            reverse_result = self._test_direction(
                bf=bf,
                source_location=location_b,
                source_ip=ip_b,
                dest_ip=ip_a,
                dest_port=port,
                protocol=protocol,
                direction="reverse"
            )
            
            # Determine overall bidirectional status
            forward_ok = forward_result.get("allowed", False)
            reverse_ok = reverse_result.get("allowed", False)
            
            bidirectional_status = "FULLY_REACHABLE" if (forward_ok and reverse_ok) else \
                                   "FORWARD_ONLY" if forward_ok else \
                                   "REVERSE_ONLY" if reverse_ok else \
                                   "BLOCKED"
            
            # Build comprehensive response
            return {
                "ok": True,
                "bidirectional_status": bidirectional_status,
                "forward_allowed": forward_ok,
                "reverse_allowed": reverse_ok,
                "location_a": {
                    "location": location_a,
                    "ip": ip_a
                },
                "location_b": {
                    "location": location_b,
                    "ip": ip_b
                },
                "port": port,
                "protocol": protocol,
                "forward": forward_result,
                "reverse": reverse_result,
                "summary": self._generate_summary(forward_ok, reverse_ok, bidirectional_status),
                "warnings": self._generate_warnings(forward_ok, reverse_ok, forward_result, reverse_result)
            }
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error testing bidirectional reachability: {error_msg}", exc_info=True)
            return {
                "ok": False,
                "error": error_msg,
                "bidirectional_status": "ERROR",
                "forward_allowed": False,
                "reverse_allowed": False
            }

    def _test_direction(
        self,
        bf: Session,
        source_location: str,
        source_ip: str,
        dest_ip: str,
        dest_port: Optional[int],
        protocol: str,
        direction: str
    ) -> Dict[str, Any]:
        """
        Test reachability in one direction.
        
        Args:
            bf: Batfish session
            source_location: Source location
            source_ip: Source IP
            dest_ip: Destination IP
            dest_port: Destination port
            protocol: IP protocol
            direction: "forward" or "reverse"
            
        Returns:
            Dictionary with reachability results for this direction
        """
        try:
            # Build header constraints
            header_kwargs = {
                "srcIps": source_ip,
                "dstIps": dest_ip,
                "ipProtocols": [protocol] if protocol else None
            }
            
            if dest_port is not None:
                header_kwargs["dstPorts"] = str(dest_port)
            
            headers = HeaderConstraints(**header_kwargs)
            
            # Run traceroute query
            trace_result, error = safe_batfish_query(
                bf,
                f"traceroute_{direction}",
                lambda: bf.q.traceroute(
                    startLocation=source_location,
                    headers=headers
                ),
                timeout=30
            )
            
            if error:
                return {
                    "allowed": False,
                    "result": "ERROR",
                    "error": error,
                    "path": [],
                    "disposition": "ERROR"
                }
            
            if trace_result is None or trace_result.empty:
                return {
                    "allowed": False,
                    "result": "NO_ROUTE",
                    "reason": "No valid path found",
                    "path": [],
                    "disposition": "NO_ROUTE"
                }
            
            # Parse trace results
            first_flow = trace_result.iloc[0]
            traces = first_flow.get("Traces", [])
            
            if not traces:
                return {
                    "allowed": False,
                    "result": "NO_ROUTE",
                    "path": [],
                    "disposition": "NO_ROUTE"
                }
            
            first_trace = traces[0]
            disposition = str(first_trace.disposition) if hasattr(first_trace, 'disposition') else "UNKNOWN"
            is_accepted = "ACCEPT" in disposition.upper()
            
            # Extract path and blocking information
            path = []
            blocking_acl = None
            
            if hasattr(first_trace, 'hops'):
                for hop in first_trace.hops:
                    # Try multiple ways to extract node name
                    hop_node = "unknown"
                    if hasattr(hop, 'node'):
                        if hasattr(hop.node, 'name'):
                            hop_node = str(hop.node.name)
                        elif hasattr(hop.node, 'hostname'):
                            hop_node = str(hop.node.hostname)
                        else:
                            hop_node = str(hop.node)
                    path.append(hop_node)
                    
                    # Check for blocking ACL
                    if hasattr(hop, 'steps') and not is_accepted:
                        for step in hop.steps:
                            step_detail = step.detail if hasattr(step, 'detail') else {}
                            if hasattr(step_detail, 'filter'):
                                action = str(step.action) if hasattr(step, 'action') else "UNKNOWN"
                                if "DENY" in action.upper() or "DROP" in action.upper():
                                    blocking_acl = {
                                        "node": hop_node,
                                        "filter": str(step_detail.filter),
                                        "action": "DENY"
                                    }
                                    break
            
            return {
                "allowed": is_accepted,
                "result": "ALLOWED" if is_accepted else "DENIED",
                "disposition": disposition,
                "path": path,
                "blocking_acl": blocking_acl,
                "hop_count": len(path)
            }
            
        except Exception as e:
            logger.error(f"Error testing {direction} direction: {str(e)}")
            return {
                "allowed": False,
                "result": "ERROR",
                "error": str(e),
                "path": [],
                "disposition": "ERROR"
            }

    def _generate_summary(self, forward_ok: bool, reverse_ok: bool, status: str) -> str:
        """Generate human-readable summary."""
        if status == "FULLY_REACHABLE":
            return "Bidirectional communication is allowed. Traffic can flow in both directions."
        elif status == "FORWARD_ONLY":
            return "Only forward direction is allowed (A → B). Return traffic (B → A) is blocked."
        elif status == "REVERSE_ONLY":
            return "Only reverse direction is allowed (B → A). Forward traffic (A → B) is blocked."
        else:
            return "Communication is blocked in both directions."

    def _generate_warnings(
        self,
        forward_ok: bool,
        reverse_ok: bool,
        forward_result: Dict[str, Any],
        reverse_result: Dict[str, Any]
    ) -> list:
        """Generate warnings based on reachability results."""
        warnings = []
        
        # Asymmetric routing warning
        if forward_ok and reverse_ok:
            forward_path = forward_result.get("path", [])
            reverse_path = reverse_result.get("path", [])
            
            if forward_path and reverse_path:
                # Check if paths are symmetric
                if list(reversed(forward_path)) != reverse_path:
                    warnings.append("ASYMMETRIC_ROUTING: Forward and reverse paths differ. This may cause issues with stateful firewalls.")
        
        # One-way communication warning
        if forward_ok and not reverse_ok:
            warnings.append("ONE_WAY_ONLY: TCP connections will fail as return traffic is blocked.")
            if reverse_result.get("blocking_acl"):
                warnings.append(f"Blocked by: {reverse_result['blocking_acl']['filter']} on {reverse_result['blocking_acl']['node']}")
        
        if reverse_ok and not forward_ok:
            warnings.append("REVERSE_ONLY: Forward traffic is blocked.")
            if forward_result.get("blocking_acl"):
                warnings.append(f"Blocked by: {forward_result['blocking_acl']['filter']} on {forward_result['blocking_acl']['node']}")
        
        # Both directions blocked
        if not forward_ok and not reverse_ok:
            warnings.append("FULLY_BLOCKED: No communication possible in either direction.")
        
        return warnings


# Create singleton instance
network_bidirectional_reachability_tool = NetworkBidirectionalReachabilityTool()

