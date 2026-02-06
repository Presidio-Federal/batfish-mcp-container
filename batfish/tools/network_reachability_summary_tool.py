"""
Network Reachability Summary Tool

Summarize cross-subnet reachability between network-owned prefixes.
The output must be a very small, concise set of (src subnet → dst subnet) pairs 
that represent real L3 reachability paths.
This is used for OT/IT segmentation and compliance analysis.
"""

import logging
from typing import Dict, Any, List, Set
from pydantic import BaseModel, Field
from pybatfish.client.session import Session

# Import safety utilities from AWS tools directory
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


class NetworkReachabilitySummaryInput(BaseModel):
    """Input model for reachability summary."""
    network: str = Field(..., description="Batfish network name")
    snapshot: str = Field(..., description="Batfish snapshot name")
    host: str = Field("localhost", description="Batfish host to connect to")


# Valid network device vendors
VALID_VENDORS = ["cisco", "juniper", "arista", "palo alto", "f5", "vyos"]


def execute(input_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Summarize cross-subnet reachability between network-owned prefixes.
    
    NOTE: This tool provides a CONSERVATIVE estimate based on Layer 3 edges
    rather than running expensive reachability queries which can freeze Batfish.
    
    For specific reachability testing, use traceroute with specific src/dst pairs.
    
    Args:
        input_data: Dictionary containing network, snapshot, and host
        
    Returns:
        Dictionary with:
        - ok: Success status
        - reachable_pairs: List of potential reachability based on L3 adjacencies
        - summary: Human-readable summary of results
    """
    try:
        # Validate input
        validated_input = NetworkReachabilitySummaryInput(**input_data)
        
        network = validated_input.network
        snapshot = validated_input.snapshot
        host = validated_input.host
        
        logger.info(f"Generating reachability summary for network '{network}', snapshot '{snapshot}'")
        logger.warning("Using Layer 3 topology instead of full reachability analysis to prevent Batfish freeze")
        
        # Initialize Batfish session
        bf = Session(host=host)
        bf.set_network(network)
        bf.set_snapshot(snapshot)
        
        logger.info(f"Connected to Batfish host: {host}")
        
        # Get valid network nodes by vendor (with safety wrapper)
        logger.info("Retrieving network nodes...")
        vendors_df, error = safe_batfish_query(
            bf,
            "nodeProperties query",
            lambda: bf.q.nodeProperties(),
            timeout=30
        )
        
        if error or vendors_df is None or vendors_df.empty:
            logger.warning(f"No nodes found in snapshot: {error}")
            return {
                "ok": True,
                "reachable_pairs": [],
                "summary": "No network devices found in snapshot."
            }
        
        # Filter to valid network devices only
        # Use Configuration_Format to determine vendor
        valid_nodes: Set[str] = set()
        for _, row in vendors_df.iterrows():
            node_name = str(row.get('Node', ''))
            config_format = str(row.get('Configuration_Format', '')).lower()
            
            # Extract vendor from config format (e.g., "cisco_ios" -> "cisco")
            vendor = None
            for valid_vendor in VALID_VENDORS:
                if valid_vendor.replace(" ", "_") in config_format or valid_vendor in config_format:
                    vendor = valid_vendor
                    break
            
            if vendor:
                valid_nodes.add(node_name)
        
        if not valid_nodes:
            logger.warning(f"No valid network devices found (valid vendors: {', '.join(VALID_VENDORS)})")
            return {
                "ok": True,
                "reachable_pairs": [],
                "summary": "No valid network devices found. Snapshot may contain only hosts or unsupported devices."
            }
        
        logger.info(f"Found {len(valid_nodes)} valid network device(s)")
        
        # Get IP ownership to build valid subnet list (with safety wrapper)
        logger.info("Retrieving IP ownership data...")
        owners_df, error = safe_batfish_query(
            bf,
            "ipOwners query",
            lambda: bf.q.ipOwners(),
            timeout=30
        )
        
        if error or owners_df is None or owners_df.empty:
            logger.warning(f"No IP ownership data found: {error}")
            return {
                "ok": True,
                "reachable_pairs": [],
                "summary": f"Found {len(valid_nodes)} network devices but no IP addressing configured."
            }
        
        # Build node -> subnets map
        node_subnets: Dict[str, Set[str]] = {}
        for node in valid_nodes:
            node_subnets[node] = set()
        
        for _, row in owners_df.iterrows():
            # Extract node name from Interface column
            interface_str = str(row.get('Interface', ''))
            
            # Parse node name
            if '[' in interface_str:
                node_name = interface_str.split('[')[0]
            elif '@' in interface_str:
                node_name = interface_str.split('@')[0]
            else:
                continue
            
            # Only include subnets owned by valid network devices
            if node_name not in valid_nodes:
                continue
            
            # Extract subnet/IP
            ip_str = str(row.get('IP', ''))
            if not ip_str or ip_str == 'nan':
                continue
            
            node_subnets[node_name].add(ip_str)
        
        logger.info(f"Built subnet ownership map")
        
        # Get Layer 3 edges to infer potential reachability (with safety wrapper)
        logger.info("Retrieving Layer 3 edges...")
        edges_df, error = safe_batfish_query(
            bf,
            "layer3Edges query",
            lambda: bf.q.layer3Edges(),
            timeout=30
        )
        
        if error or edges_df is None or edges_df.empty:
            logger.warning(f"No Layer 3 edges found: {error}")
            return {
                "ok": True,
                "reachable_pairs": [],
                "summary": f"Found {len(valid_nodes)} network devices but no Layer 3 adjacencies."
            }
        
        logger.info(f"Retrieved {len(edges_df)} Layer 3 edges")
        
        # Infer potential reachability from L3 topology
        # This is a CONSERVATIVE estimate - actual reachability may be restricted by ACLs/firewalls
        reachability_map: Dict[tuple, Dict[str, Any]] = {}
        
        for _, row in edges_df.iterrows():
            # Extract interface columns
            if 'Interface' in edges_df.columns and 'Remote_Interface' in edges_df.columns:
                interface_col = 'Interface'
                remote_col = 'Remote_Interface'
            elif len(edges_df.columns) >= 2:
                interface_col = edges_df.columns[0]
                remote_col = edges_df.columns[1]
            else:
                continue
            
            source_interface = str(row[interface_col])
            target_interface = str(row[remote_col])
            
            # Parse node names
            if '[' in source_interface:
                node_a = source_interface.split('[')[0]
            elif '@' in source_interface:
                node_a = source_interface.split('@')[0]
            else:
                node_a = source_interface
            
            if '[' in target_interface:
                node_b = target_interface.split('[')[0]
            elif '@' in target_interface:
                node_b = target_interface.split('@')[0]
            else:
                node_b = target_interface
            
            # Only process edges between valid network devices
            if node_a not in valid_nodes or node_b not in valid_nodes:
                continue
            
            # Get subnets for both nodes
            subnets_a = node_subnets.get(node_a, set())
            subnets_b = node_subnets.get(node_b, set())
            
            # If they have different subnets, assume bidirectional potential reachability
            if subnets_a and subnets_b:
                for subnet_a in subnets_a:
                    for subnet_b in subnets_b:
                        if subnet_a != subnet_b:
                            # Add A -> B
                            key_ab = (subnet_a, subnet_b)
                            if key_ab not in reachability_map:
                                reachability_map[key_ab] = {
                                    "src": subnet_a,
                                    "dst": subnet_b,
                                    "via": node_a,
                                    "reason": "L3 adjacency (potential)"
                                }
                            
                            # Add B -> A
                            key_ba = (subnet_b, subnet_a)
                            if key_ba not in reachability_map:
                                reachability_map[key_ba] = {
                                    "src": subnet_b,
                                    "dst": subnet_a,
                                    "via": node_b,
                                    "reason": "L3 adjacency (potential)"
                                }
        
        # Build result list (sorted for stability)
        reachable_pairs = []
        for key in sorted(reachability_map.keys()):
            reachable_pairs.append(reachability_map[key])
        
        # Generate summary
        total_pairs = len(reachable_pairs)
        
        if total_pairs == 0:
            summary = "No cross-subnet Layer 3 adjacencies detected."
        else:
            summary = f"{total_pairs} potential cross-subnet reachability pair(s) detected (based on L3 topology)."
        
        logger.info(summary)
        logger.warning("Results show POTENTIAL reachability based on L3 topology only. Actual reachability may be blocked by ACLs/firewalls. Use traceroute tool for specific path testing.")
        
        return {
            "ok": True,
            "reachable_pairs": reachable_pairs,
            "summary": summary,
            "warning": "Results based on L3 topology only. Actual reachability may differ due to ACLs/firewalls."
        }
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error generating reachability summary: {error_msg}")
        import traceback
        logger.error(traceback.format_exc())
        return {
            "ok": False,
            "error": error_msg,
            "reachable_pairs": []
        }

