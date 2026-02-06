"""
Batfish AWS Subnet Segmentation Tool

Checks AWS subnet-to-subnet segmentation inside a Batfish snapshot.
For every pair of subnets, determines whether traffic is allowed or blocked,
and reports unexpected allows/blocks based on user expectations.
"""

import logging
from typing import Dict, Any, List, Tuple, Optional
from pydantic import BaseModel, Field
from pybatfish.client.session import Session
from pybatfish.datamodel import HeaderConstraints
import ipaddress
from .aws_safety_utils import safe_batfish_query, check_network_active

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SubnetSegmentationInput(BaseModel):
    """Input model for AWS subnet segmentation analysis."""
    network: str = Field(..., description="Batfish network name")
    snapshot: str = Field(..., description="Batfish snapshot name")
    expected_isolation: Dict[str, List[str]] = Field(
        default_factory=dict,
        description="Expected isolation rules: {'prod': ['dev']} means prod should be isolated from dev"
    )
    allowed_pairs: List[Tuple[str, str]] = Field(
        default_factory=list,
        description="List of subnet pairs that should allow traffic [(subnet-a, subnet-b)]"
    )
    denied_pairs: List[Tuple[str, str]] = Field(
        default_factory=list,
        description="List of subnet pairs that should deny traffic [(subnet-a, subnet-b)]"
    )
    host: str = Field("localhost", description="Batfish host to connect to")


def get_subnet_first_ip(cidr: str) -> str:
    """
    Get the first usable IP address from a subnet CIDR.
    
    Args:
        cidr: Subnet CIDR (e.g., "10.0.0.0/24")
        
    Returns:
        First usable IP address as string
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        # Get first host IP (skip network address)
        hosts = list(network.hosts())
        if hosts:
            return str(hosts[0])
        # If no hosts (e.g., /32), return network address
        return str(network.network_address)
    except Exception as e:
        logger.warning(f"Could not parse CIDR {cidr}: {e}")
        return cidr.split('/')[0]  # Fallback to just the IP part


def execute(input_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Check AWS subnet-to-subnet segmentation.
    
    Tests reachability between all subnet pairs and compares against expectations.
    
    Args:
        input_data: Dictionary containing network, snapshot, expectations
        
    Returns:
        Dictionary with allowed/denied pairs and unexpected violations
    """
    try:
        # Validate input
        validated_input = SubnetSegmentationInput(**input_data)
        
        network = validated_input.network
        snapshot = validated_input.snapshot
        expected_isolation = validated_input.expected_isolation
        allowed_pairs = validated_input.allowed_pairs
        denied_pairs = validated_input.denied_pairs
        host = validated_input.host
        
        logger.info(f"Starting AWS subnet segmentation analysis for network '{network}', snapshot '{snapshot}'")
        
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
            
            # Discover AWS subnets
            logger.info("Discovering AWS subnets...")
            nodes_df, error = safe_batfish_query(
                bf,
                "nodeProperties",
                bf.q.nodeProperties,
                timeout=30
            )
            
            if error:
                warnings.append(error)
                logger.warning(error)
                nodes_df = None
            
            # Extract subnets (nodes starting with 'subnet-')
            subnets = {}
            if nodes_df is not None and not nodes_df.empty:
                for _, row in nodes_df.iterrows():
                    node_name = row.get("Node", "")
                    if node_name.startswith("subnet-") or node_name.startswith("aws_subnet-"):
                        # Get subnet CIDR from interface properties
                        try:
                            # Use safe_batfish_query to handle errors gracefully
                            interfaces_df, error = safe_batfish_query(
                                bf,
                                f"interfaceProperties for {node_name}",
                                lambda: bf.q.interfaceProperties(nodes=node_name),
                                timeout=15
                            )
                            
                            if error:
                                logger.debug(f"Could not get interfaces for {node_name}: {error}")
                                continue
                            
                            if interfaces_df is not None and not interfaces_df.empty:
                                # Get the primary IP/CIDR from the first interface
                                first_interface = interfaces_df.iloc[0]
                                primary_ip = first_interface.get("Primary_Address", "")
                                if primary_ip:
                                    # Extract CIDR from Primary_Address (format: "10.0.0.1/24")
                                    subnets[node_name] = primary_ip
                                    logger.debug(f"Found subnet {node_name}: {primary_ip}")
                        except Exception as e:
                            logger.debug(f"Could not get interfaces for {node_name}: {e}")
                            continue
            
            if not subnets:
                logger.warning("No AWS subnets found in snapshot")
                return {
                    "ok": True,
                    "subnet_count": 0,
                    "allowed": [],
                    "denied": [],
                    "unexpected_allows": [],
                    "unexpected_blocks": [],
                    "warnings": warnings,
                    "message": "No subnets found in snapshot"
                }
            
            logger.info(f"Found {len(subnets)} subnets: {list(subnets.keys())}")
            
            # Test reachability for each subnet pair
            allowed = []
            denied = []
            
            subnet_ids = list(subnets.keys())
            total_pairs = len(subnet_ids) * (len(subnet_ids) - 1)  # Exclude self-pairs
            
            logger.info(f"Testing {total_pairs} subnet pairs for reachability...")
            
            for src_subnet in subnet_ids:
                src_cidr = subnets[src_subnet]
                src_ip = get_subnet_first_ip(src_cidr)
                
                for dst_subnet in subnet_ids:
                    # Skip same subnet
                    if src_subnet == dst_subnet:
                        continue
                    
                    dst_cidr = subnets[dst_subnet]
                    dst_ip = get_subnet_first_ip(dst_cidr)
                    
                    logger.debug(f"Testing {src_subnet} ({src_ip}) → {dst_subnet} ({dst_ip})")
                    
                    try:
                        # Test reachability using traceroute
                        reach_result, error = safe_batfish_query(
                            bf,
                            f"traceroute_{src_subnet}_to_{dst_subnet}",
                            lambda: bf.q.traceroute(
                                startLocation=src_subnet,
                                headers=HeaderConstraints(srcIps=src_ip, dstIps=dst_ip)
                            ),
                            timeout=15
                        )
                        
                        # Determine if traffic is allowed
                        is_allowed = False
                        if error:
                            logger.debug(f"Error testing {src_subnet} → {dst_subnet}: {error}")
                        elif reach_result is not None and not reach_result.empty:
                            traces = reach_result.iloc[0].get("Traces", [])
                            if traces:
                                disposition = str(traces[0].disposition) if hasattr(traces[0], 'disposition') else ""
                                is_allowed = "ACCEPT" in disposition.upper()
                        
                        pair = {
                            "source_subnet": src_subnet,
                            "dest_subnet": dst_subnet,
                            "source_ip": src_ip,
                            "dest_ip": dst_ip
                        }
                        
                        if is_allowed:
                            allowed.append(pair)
                        else:
                            denied.append(pair)
                            
                    except Exception as e:
                        logger.warning(f"Error testing {src_subnet} → {dst_subnet}: {e}")
                        # Assume denied on error
                        denied.append({
                            "source_subnet": src_subnet,
                            "dest_subnet": dst_subnet,
                            "source_ip": src_ip,
                            "dest_ip": dst_ip,
                            "error": str(e)
                        })
            
            logger.info(f"Reachability test complete: {len(allowed)} allowed, {len(denied)} denied")
            
            # Compare against expectations
            unexpected_allows = []
            unexpected_blocks = []
            
            # Check expected_isolation violations
            # Format: {"prod": ["dev"]} means prod should be isolated from dev
            for isolator, isolated_list in expected_isolation.items():
                for isolated in isolated_list:
                    # Check if any subnets with these tags can reach each other
                    for pair in allowed:
                        src = pair["source_subnet"]
                        dst = pair["dest_subnet"]
                        
                        # Simple tag matching (substring check)
                        if (isolator in src and isolated in dst) or (isolated in src and isolator in dst):
                            unexpected_allows.append({
                                **pair,
                                "reason": f"Violates expected isolation: {isolator} ↔ {isolated}"
                            })
            
            # Check denied_pairs violations (should be denied but is allowed)
            for denied_src, denied_dst in denied_pairs:
                for pair in allowed:
                    if pair["source_subnet"] == denied_src and pair["dest_subnet"] == denied_dst:
                        unexpected_allows.append({
                            **pair,
                            "reason": f"Should be denied per policy: {denied_src} → {denied_dst}"
                        })
            
            # Check allowed_pairs violations (should be allowed but is denied)
            for allowed_src, allowed_dst in allowed_pairs:
                found = False
                for pair in allowed:
                    if pair["source_subnet"] == allowed_src and pair["dest_subnet"] == allowed_dst:
                        found = True
                        break
                
                if not found:
                    # Find the denied pair for details
                    for pair in denied:
                        if pair["source_subnet"] == allowed_src and pair["dest_subnet"] == allowed_dst:
                            unexpected_blocks.append({
                                **pair,
                                "reason": f"Should be allowed per policy: {allowed_src} → {allowed_dst}"
                            })
                            break
            
            # Generate summary
            summary = {
                "total_pairs_tested": len(allowed) + len(denied),
                "allowed_count": len(allowed),
                "denied_count": len(denied),
                "violations": len(unexpected_allows) + len(unexpected_blocks),
                "unexpected_allows_count": len(unexpected_allows),
                "unexpected_blocks_count": len(unexpected_blocks)
            }
            
            logger.info(f"Segmentation analysis complete: {summary['violations']} violations found")
            
            return {
                "ok": True,
                "subnet_count": len(subnets),
                "subnets": list(subnets.keys()),
                "summary": summary,
                "allowed": allowed,
                "denied": denied,
                "unexpected_allows": unexpected_allows,
                "unexpected_blocks": unexpected_blocks,
                "warnings": warnings
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
        logger.error(f"Error in subnet segmentation analysis: {error_msg}", exc_info=True)
        
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
            "allowed": [],
            "denied": [],
            "unexpected_allows": [],
            "unexpected_blocks": []
        }


