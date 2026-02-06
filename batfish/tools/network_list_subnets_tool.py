"""
Network List Subnets Tool

Returns a concise list of unique IP subnets detected in the network,
showing which network devices own interfaces in each subnet.

Only includes real network devices (cisco, juniper, arista, palo alto, f5, vyos).
Excludes CLI/management nodes and hosts.
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


class NetworkListSubnetsInput(BaseModel):
    """Input model for listing subnets."""
    network: str = Field(..., description="Batfish network name")
    snapshot: str = Field(..., description="Batfish snapshot name")
    host: str = Field("localhost", description="Batfish host to connect to")


# Valid network device vendors
VALID_VENDORS = {"cisco", "juniper", "arista", "palo alto", "f5", "vyos"}


class NetworkListSubnetsTool:
    """
    Tool for listing all unique IP subnets in the network.
    
    Returns a structured summary of IP subnets showing which network devices
    have interfaces in each subnet, along with interface details and VRF assignments.
    
    Only includes real network infrastructure devices - excludes hosts and CLI nodes.
    """

    def execute(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        List all unique IP subnets in the network with their owners.
        
        Args:
            input_data: Dictionary containing network, snapshot, and host
            
        Returns:
            Dictionary with:
            - ok: Success status
            - subnets: List of subnet objects with prefix, owners, interfaces, and vrf
            - summary: Human-readable summary of results
        """
        try:
            # Validate input
            validated_input = NetworkListSubnetsInput(**input_data)
            
            network = validated_input.network
            snapshot = validated_input.snapshot
            host = validated_input.host
            
            logger.info(f"Listing subnets for network '{network}', snapshot '{snapshot}'")
            
            # Initialize Batfish session
            bf = Session(host=host)
            bf.set_network(network)
            bf.set_snapshot(snapshot)
            
            logger.info(f"Connected to Batfish host: {host}")
            
            # Get valid network nodes first (with safety wrapper)
            logger.info("Retrieving valid network nodes...")
            nodes_df, error = safe_batfish_query(
                bf,
                "nodeProperties query",
                lambda: bf.q.nodeProperties(),
                timeout=30
            )
            
            if error or nodes_df is None or nodes_df.empty:
                logger.warning(f"No nodes found in snapshot: {error}")
                return {
                    "ok": True,
                    "subnets": [],
                    "summary": "No network devices found in snapshot."
                }
            
            # Filter to only valid network device vendors
            # Use Configuration_Format to determine vendor
            valid_nodes: Set[str] = set()
            for _, row in nodes_df.iterrows():
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
                logger.warning("No valid network devices found (cisco, juniper, arista, palo alto, f5, vyos)")
                return {
                    "ok": True,
                    "subnets": [],
                    "summary": "No valid network devices found. Snapshot may contain only hosts or unsupported devices."
                }
            
            logger.info(f"Found {len(valid_nodes)} valid network device(s): {', '.join(sorted(valid_nodes))}")
            
            # Get interface properties with All_Prefixes (with safety wrapper)
            logger.info("Retrieving interface properties...")
            df, error = safe_batfish_query(
                bf,
                "interfaceProperties query",
                lambda: bf.q.interfaceProperties(),
                timeout=30
            )
            
            if error or df is None or df.empty:
                logger.warning(f"No interface data found: {error}")
                return {
                    "ok": True,
                    "subnets": [],
                    "summary": f"Found {len(valid_nodes)} network devices but no interface data."
                }
            
            logger.info(f"Retrieved {len(df)} interface records")
            
            # Use pandas to process data exactly as verified by user
            try:
                import pandas as pd
                
                # Extract node name from Interface object
                df = df.assign(Node=lambda x: x['Interface'].apply(lambda i: i.hostname))
                
                # Filter to valid nodes only
                df = df.query('Node in @valid_nodes')
                
                # Explode All_Prefixes to get one row per prefix
                df = df.explode('All_Prefixes')
                
                # Drop rows without prefixes
                df = df.dropna(subset=['All_Prefixes'])
                
                if df.empty:
                    logger.warning("No prefixes found after filtering")
                    return {
                        "ok": True,
                        "subnets": [],
                        "summary": f"Found {len(valid_nodes)} network devices but no IP prefixes configured."
                    }
                
                # Convert prefix to string
                df = df.assign(Prefix=lambda x: x['All_Prefixes'].astype(str))
                
                # Group by prefix and aggregate
                result = df.groupby('Prefix').apply(lambda g: pd.Series({
                    'owners': sorted(g['Node'].unique()),
                    'interfaces': sorted(f"{r.Node}[{r.Interface.interface}]" for _, r in g.iterrows()),
                    'vrf': g['VRF'].fillna('default').iloc[0] if g['VRF'].nunique() <= 1 else ', '.join(sorted(g['VRF'].fillna('default').unique()))
                })).reset_index()
                
                # Convert to list of dictionaries
                subnets_list = []
                for _, row in result.iterrows():
                    subnets_list.append({
                        "prefix": row['Prefix'],
                        "owners": row['owners'],
                        "interfaces": row['interfaces'],
                        "vrf": row['vrf']
                    })
                
            except Exception as e:
                logger.error(f"Error processing interface data: {e}")
                import traceback
                logger.error(traceback.format_exc())
                return {
                    "ok": False,
                    "error": f"Error processing interface data: {str(e)}",
                    "subnets": []
                }
            
            # Generate summary
            total_subnets = len(subnets_list)
            total_devices = len(valid_nodes)
            
            if total_subnets == 0:
                summary = f"No subnets detected across {total_devices} network device(s)."
            else:
                summary = f"Detected {total_subnets} unique subnet(s) across {total_devices} network device(s)."
            
            logger.info(summary)
            
            return {
                "ok": True,
                "subnets": subnets_list,
                "summary": summary
            }
        
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error listing subnets: {error_msg}")
            import traceback
            logger.error(traceback.format_exc())
            return {
                "ok": False,
                "error": error_msg,
                "subnets": []
            }


# Create singleton instance
network_list_subnets_tool = NetworkListSubnetsTool()
