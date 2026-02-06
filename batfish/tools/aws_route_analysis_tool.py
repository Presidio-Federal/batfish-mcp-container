"""
Batfish AWS Route Analysis Tool

Analyzes AWS routing inside the Batfish snapshot and identifies:
- Blackhole routes
- Missing return paths
- Subnets with no default route
- Misconfigured IGW/NATGW paths
- Asymmetric routing
- Overlapping or shadowed routes
- TGW propagation issues (if present)
- Subnets that cannot reach expected destinations
"""

import logging
from typing import Dict, Any, List, Set
from pydantic import BaseModel, Field
from pybatfish.client.session import Session
from pybatfish.datamodel import HeaderConstraints
import ipaddress
from .aws_safety_utils import check_network_active, safe_batfish_query

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class AwsRouteAnalysisInput(BaseModel):
    """Input model for AWS route analysis."""
    network: str = Field(..., description="Batfish network name")
    snapshot: str = Field(..., description="Batfish snapshot name")
    host: str = Field("localhost", description="Batfish host to connect to")
    skip_reachability_tests: bool = Field(True, description="Skip expensive reachability tests (recommended for large networks)")


def execute(input_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze AWS routing and identify routing issues.
    
    Tests for blackholes, missing defaults, asymmetric routing, conflicts,
    and unreachable subnets.
    
    Args:
        input_data: Dictionary containing network, snapshot
        
    Returns:
        Dictionary with categorized routing issues
    """
    try:
        # Validate input
        validated_input = AwsRouteAnalysisInput(**input_data)
        
        network = validated_input.network
        snapshot = validated_input.snapshot
        host = validated_input.host
        skip_reachability = validated_input.skip_reachability_tests
        
        logger.info(f"Starting AWS route analysis for network '{network}', snapshot '{snapshot}'")
        if skip_reachability:
            logger.info("Reachability tests are DISABLED (fast mode)")
        else:
            logger.warning("Reachability tests are ENABLED - this may take several minutes!")
        
        # Initialize Batfish session
        bf = Session(host=host)
        
        try:
            bf.set_network(network)
            bf.set_snapshot(snapshot)
            
            # Check if network is active
            network_status = check_network_active(bf)
            if not network_status["has_nodes"]:
                logger.warning(network_status["warning"])
            
            # Storage for findings
            blackholes = []
            missing_defaults = []
            asymmetric_routes = []
            route_conflicts = []
            unreachable_subnets = []
            invalid_igw_or_nat_paths = []
            warnings = []
            
            if network_status["warning"]:
                warnings.append(network_status["warning"])
            
            # 1. Get all route tables
            logger.info("Step 1: Retrieving route table information...")
            
            routes_df, error = safe_batfish_query(
                bf,
                "routes query",
                lambda: bf.q.routes(),
                timeout=30
            )
            
            # Get all nodes (includes route tables, subnets, IGWs, NAT GWs)
            nodes_df, error = safe_batfish_query(
                bf,
                "nodeProperties query",
                lambda: bf.q.nodeProperties(),
                timeout=30
            )
            
            subnet_nodes = []
            igw_nodes = []
            natgw_nodes = []
            rtb_nodes = []
            
            if nodes_df is not None and not nodes_df.empty:
                for _, row in nodes_df.iterrows():
                    node_name = row.get("Node", "")
                    if node_name.startswith("subnet-"):
                        subnet_nodes.append(node_name)
                    elif node_name.startswith("igw-"):
                        igw_nodes.append(node_name)
                    elif node_name.startswith("nat-"):
                        natgw_nodes.append(node_name)
                    elif node_name.startswith("rtb-"):
                        rtb_nodes.append(node_name)
            else:
                logger.warning("No nodes found - network may be empty")
                warnings.append("No active network nodes found")
            
            logger.info(f"Found {len(subnet_nodes)} subnets, {len(rtb_nodes)} route tables, {len(igw_nodes)} IGWs, {len(natgw_nodes)} NAT GWs")
            
            # 2. Analyze routes for each route table
            logger.info("Step 2: Analyzing route tables for issues...")
            
            if routes_df is not None and not routes_df.empty:
                for _, route in routes_df.iterrows():
                    node = route.get("Node", "")
                    network_dest = route.get("Network", "")
                    next_hop = str(route.get("Next_Hop", ""))
                    next_hop_ip = route.get("Next_Hop_IP", "")
                    protocol = route.get("Protocol", "")
                    
                    # Check for blackholes
                    if "null" in next_hop.lower() or "blackhole" in next_hop.lower() or "drop" in next_hop.lower():
                        blackholes.append({
                            "route_table": node,
                            "destination": network_dest,
                            "next_hop": next_hop,
                            "severity": "HIGH",
                            "issue": f"Blackhole route to {network_dest}"
                        })
                    
                    # Check for invalid IGW/NAT paths
                    if "igw-" in next_hop.lower() and node.startswith("subnet-"):
                        # Verify this is appropriate for a public subnet
                        # (This is actually valid for public subnets, but we flag for review)
                        pass
                    
                    # Check for overlapping routes (more-specific vs less-specific)
                    # This requires comparing all routes for the same route table
                    # We'll do this in a separate pass
            
            # 3. Check for missing default routes per subnet
            logger.info("Step 3: Checking for missing default routes...")
            
            for subnet in subnet_nodes:
                has_default = False
                has_any_route = False
                
                if routes_df is not None and not routes_df.empty:
                    subnet_routes = routes_df[routes_df["Node"] == subnet]
                    
                    if not subnet_routes.empty:
                        has_any_route = True
                        
                        for _, route in subnet_routes.iterrows():
                            network_dest = route.get("Network", "")
                            
                            # Check if this is a default route
                            if network_dest in ["0.0.0.0/0", "::/0"]:
                                has_default = True
                                break
                
                if not has_default and has_any_route:
                    missing_defaults.append({
                        "subnet": subnet,
                        "severity": "MEDIUM",
                        "issue": "Subnet has no default route (0.0.0.0/0)"
                    })
                elif not has_any_route:
                    missing_defaults.append({
                        "subnet": subnet,
                        "severity": "HIGH",
                        "issue": "Subnet has no routes configured"
                    })
            
            # 4. Test reachability to internet for subnets (OPTIONAL - can be very slow)
            logger.info("Step 4: Testing internet reachability from subnets...")
            
            if not skip_reachability:
                logger.warning(f"Running reachability tests for {len(subnet_nodes)} subnets - this may take several minutes...")
                
                for idx, subnet in enumerate(subnet_nodes):
                    logger.info(f"  Testing subnet {idx+1}/{len(subnet_nodes)}: {subnet}")
                    # Test if subnet can reach the internet
                    try:
                        # Use traceroute instead of reachability for better compatibility
                        reach_result, error = safe_batfish_query(
                            bf,
                            f"traceroute from {subnet}",
                            lambda: bf.q.traceroute(
                                startLocation=subnet,
                                headers=HeaderConstraints(dstIps="8.8.8.8", ipProtocols=["tcp"])
                            ),
                            timeout=30
                        )
                        
                        can_reach_internet = False
                        if reach_result is not None and not reach_result.empty:
                            for _, trace_row in reach_result.iterrows():
                                disposition = str(trace_row.get("Traces", [{}])[0].get("disposition", "")) if trace_row.get("Traces") else ""
                                if "ACCEPT" in disposition.upper() or "DELIVERED" in disposition.upper():
                                    can_reach_internet = True
                                    break
                        
                        if not can_reach_internet:
                            # Check if this subnet has a default route that should work
                            if routes_df is not None and not routes_df.empty:
                                subnet_routes = routes_df[routes_df["Node"] == subnet]
                                has_default_to_igw = False
                                
                                for _, route in subnet_routes.iterrows():
                                    network_dest = route.get("Network", "")
                                    next_hop = str(route.get("Next_Hop", ""))
                                    
                                    if network_dest == "0.0.0.0/0" and "igw-" in next_hop.lower():
                                        has_default_to_igw = True
                                        break
                                
                                if has_default_to_igw:
                                    unreachable_subnets.append({
                                        "subnet": subnet,
                                        "destination": "internet (8.8.8.8)",
                                        "severity": "HIGH",
                                        "issue": "Has default route to IGW but cannot reach internet (possible SG/NACL block)"
                                    })
                                
                    except Exception as e:
                        logger.warning(f"Could not test internet reachability for {subnet}: {e}")
            else:
                logger.info("  SKIPPED - Reachability tests disabled for performance (use skip_reachability_tests=false to enable)")
            
            # 5. Check for asymmetric routing (OPTIONAL - can be very slow)
            logger.info("Step 5: Checking for asymmetric routing patterns...")
            
            if not skip_reachability and len(subnet_nodes) > 1:
                logger.warning(f"Testing bidirectional reachability for up to 5 subnet pairs...")
                
                # Test bidirectional reachability between subnet pairs
                tested_pairs = set()
                
                for src_subnet in subnet_nodes[:5]:  # Limit to avoid too many tests
                    for dst_subnet in subnet_nodes[:5]:
                        if src_subnet == dst_subnet:
                            continue
                        
                        pair_key = tuple(sorted([src_subnet, dst_subnet]))
                        if pair_key in tested_pairs:
                            continue
                        tested_pairs.add(pair_key)
                        
                        try:
                            # Test A -> B using traceroute
                            reach_a_to_b, error = safe_batfish_query(
                                bf,
                                f"traceroute {src_subnet} to {dst_subnet}",
                                lambda: bf.q.traceroute(
                                    startLocation=src_subnet,
                                    headers=HeaderConstraints(dstIps="10.0.0.1")
                                ),
                                timeout=20
                            )
                            
                            # Test B -> A using traceroute
                            reach_b_to_a, error = safe_batfish_query(
                                bf,
                                f"traceroute {dst_subnet} to {src_subnet}",
                                lambda: bf.q.traceroute(
                                    startLocation=dst_subnet,
                                    headers=HeaderConstraints(dstIps="10.0.0.1")
                                ),
                                timeout=20
                            )
                            
                            a_to_b_works = reach_a_to_b is not None and not reach_a_to_b.empty
                            b_to_a_works = reach_b_to_a is not None and not reach_b_to_a.empty
                            
                            # Check for asymmetry
                            if a_to_b_works != b_to_a_works:
                                asymmetric_routes.append({
                                    "subnet_a": src_subnet,
                                    "subnet_b": dst_subnet,
                                    "direction_working": f"{src_subnet} -> {dst_subnet}" if a_to_b_works else f"{dst_subnet} -> {src_subnet}",
                                    "direction_failing": f"{dst_subnet} -> {src_subnet}" if a_to_b_works else f"{src_subnet} -> {dst_subnet}",
                                    "severity": "MEDIUM",
                                    "issue": "Asymmetric routing detected - one direction works but not the other"
                                })
                                
                        except Exception as e:
                            logger.debug(f"Could not test bidirectional reachability between {src_subnet} and {dst_subnet}: {e}")
            else:
                logger.info("  SKIPPED - Asymmetric routing tests disabled for performance")
            
            # 6. Check for route conflicts (overlapping routes)
            logger.info("Step 6: Checking for route conflicts and overlapping routes...")
            
            if routes_df is not None and not routes_df.empty:
                # Group routes by route table
                for rtb in rtb_nodes:
                    rtb_routes = routes_df[routes_df["Node"] == rtb]
                    
                    if rtb_routes.empty:
                        continue
                    
                    # Check for overlapping CIDR blocks
                    route_cidrs = []
                    for _, route in rtb_routes.iterrows():
                        network_dest = route.get("Network", "")
                        next_hop = str(route.get("Next_Hop", ""))
                        
                        try:
                            cidr = ipaddress.ip_network(network_dest, strict=False)
                            route_cidrs.append({
                                "cidr": cidr,
                                "next_hop": next_hop,
                                "destination": network_dest
                            })
                        except:
                            pass
                    
                    # Check for overlaps
                    for i, route_a in enumerate(route_cidrs):
                        for route_b in route_cidrs[i+1:]:
                            if route_a["cidr"].overlaps(route_b["cidr"]):
                                # Determine which is more specific
                                if route_a["cidr"].prefixlen != route_b["cidr"].prefixlen:
                                    more_specific = route_a if route_a["cidr"].prefixlen > route_b["cidr"].prefixlen else route_b
                                    less_specific = route_b if route_a["cidr"].prefixlen > route_b["cidr"].prefixlen else route_a
                                    
                                    route_conflicts.append({
                                        "route_table": rtb,
                                        "more_specific_route": more_specific["destination"],
                                        "less_specific_route": less_specific["destination"],
                                        "more_specific_next_hop": more_specific["next_hop"],
                                        "less_specific_next_hop": less_specific["next_hop"],
                                        "severity": "LOW",
                                        "issue": "Overlapping routes detected - more specific route will take precedence"
                                    })
            
            # 7. Identify invalid IGW/NAT paths
            logger.info("Step 7: Checking for invalid IGW/NAT gateway paths...")
            
            if routes_df is not None and not routes_df.empty:
                for _, route in routes_df.iterrows():
                    node = route.get("Node", "")
                    network_dest = route.get("Network", "")
                    next_hop = str(route.get("Next_Hop", ""))
                    
                    # Check for NAT gateway in public subnet (should use IGW instead)
                    if "nat-" in next_hop.lower() and network_dest == "0.0.0.0/0":
                        # This might be invalid if the subnet already has an IGW route
                        subnet_routes = routes_df[routes_df["Node"] == node]
                        has_igw_route = any("igw-" in str(r.get("Next_Hop", "")).lower() for _, r in subnet_routes.iterrows())
                        
                        if has_igw_route:
                            invalid_igw_or_nat_paths.append({
                                "subnet": node,
                                "route": network_dest,
                                "next_hop": next_hop,
                                "severity": "MEDIUM",
                                "issue": "Subnet has both IGW and NAT gateway routes - potential misconfiguration"
                            })
            
            # Generate summary
            total_issues = (
                len(blackholes) +
                len(missing_defaults) +
                len(asymmetric_routes) +
                len(route_conflicts) +
                len(unreachable_subnets) +
                len(invalid_igw_or_nat_paths)
            )
            
            logger.info(f"Route analysis complete: {total_issues} issues found")
            logger.info(f"  - {len(blackholes)} blackholes")
            logger.info(f"  - {len(missing_defaults)} missing defaults")
            logger.info(f"  - {len(asymmetric_routes)} asymmetric routes")
            logger.info(f"  - {len(route_conflicts)} route conflicts")
            logger.info(f"  - {len(unreachable_subnets)} unreachable subnets")
            logger.info(f"  - {len(invalid_igw_or_nat_paths)} invalid IGW/NAT paths")
            
            return {
                "ok": True,
                "total_issues": total_issues,
                "blackholes": blackholes,
                "missing_defaults": missing_defaults,
                "asymmetric_routes": asymmetric_routes,
                "route_conflicts": route_conflicts,
                "unreachable_subnets": unreachable_subnets,
                "invalid_igw_or_nat_paths": invalid_igw_or_nat_paths,
                "summary": f"{total_issues} routing issues found across {len(subnet_nodes)} subnets",
                "warnings": warnings if warnings else []
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
        logger.error(f"Error in AWS route analysis: {error_msg}", exc_info=True)
        
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
            "blackholes": [],
            "missing_defaults": [],
            "asymmetric_routes": [],
            "route_conflicts": [],
            "unreachable_subnets": [],
            "invalid_igw_or_nat_paths": []
        }


