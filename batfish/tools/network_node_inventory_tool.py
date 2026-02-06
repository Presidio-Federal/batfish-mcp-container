"""
Network Node Inventory Tool

Returns a list of all network nodes/devices with their configuration format and properties.
Pure data output - no CML-specific mappings. Agent can use this to determine CML node types.

Output includes:
- Node names
- Configuration format (cisco_ios, cisco_nxos, juniper, etc.)
- Device type inference
- Vendor information
"""

import logging
from typing import Dict, Any, List
from pydantic import BaseModel, Field
from pybatfish.client.session import Session

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


class NetworkNodeInventoryInput(BaseModel):
    """Input model for node inventory."""
    network: str = Field(..., description="Batfish network name")
    snapshot: str = Field(..., description="Batfish snapshot name")
    host: str = Field(default="localhost", description="Batfish host")


def execute(input_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Return inventory of all network nodes with their configuration details.
    
    Provides raw device data that an agent can use to:
    - Map to CML node definitions
    - Understand device types and roles
    - Generate topology metadata
    
    Args:
        input_data: Dictionary containing network, snapshot, and optional host
        
    Returns:
        Dictionary with:
        - ok: Success status
        - nodes: List of node objects with properties
        - total_nodes: Count of nodes
    """
    try:
        # Validate input
        validated_input = NetworkNodeInventoryInput(**input_data)
        
        network = validated_input.network
        snapshot = validated_input.snapshot
        host = validated_input.host
        
        logger.info(f"Retrieving node inventory for network={network}, snapshot={snapshot}")
        
        # Initialize Batfish session
        bf = Session(host=host)
        bf.set_network(network)
        bf.set_snapshot(snapshot)
        
        # Get node properties
        logger.info("Querying node properties...")
        nodes_df, error = safe_batfish_query(
            bf,
            "nodeProperties query",
            lambda: bf.q.nodeProperties(),
            timeout=30
        )
        
        if error or nodes_df is None or nodes_df.empty:
            return {
                "ok": False,
                "error": f"Failed to retrieve nodes: {error}",
                "nodes": [],
                "total_nodes": 0
            }
        
        logger.info(f"Found {len(nodes_df)} nodes")
        
        # Build node inventory
        nodes = []
        for _, row in nodes_df.iterrows():
            node_name = str(row.get('Node', ''))
            config_format = str(row.get('Configuration_Format', 'unknown'))
            device_type = str(row.get('Device_Type', 'unknown'))
            
            # Infer vendor from configuration format
            vendor = _infer_vendor(config_format)
            
            # Infer device role from name and type
            role = _infer_device_role(node_name, config_format, device_type)
            
            node_obj = {
                "name": node_name,
                "configuration_format": config_format,
                "device_type": device_type if device_type != 'unknown' else None,
                "vendor": vendor,
                "inferred_role": role,
            }
            
            nodes.append(node_obj)
        
        # Sort by name for consistent output
        nodes_sorted = sorted(nodes, key=lambda x: x['name'])
        
        return {
            "ok": True,
            "nodes": nodes_sorted,
            "total_nodes": len(nodes_sorted)
        }
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error retrieving node inventory: {error_msg}")
        import traceback
        logger.error(traceback.format_exc())
        return {
            "ok": False,
            "error": error_msg,
            "nodes": [],
            "total_nodes": 0
        }


def _infer_vendor(config_format: str) -> str:
    """
    Infer vendor from configuration format.
    
    Args:
        config_format: Configuration format string
        
    Returns:
        Vendor name
    """
    config_lower = config_format.lower()
    
    if 'cisco_ios' in config_lower or 'cisco_asa' in config_lower or 'cisco_nxos' in config_lower:
        return 'cisco'
    elif 'juniper' in config_lower:
        return 'juniper'
    elif 'arista' in config_lower:
        return 'arista'
    elif 'palo_alto' in config_lower:
        return 'palo_alto'
    elif 'f5' in config_lower:
        return 'f5'
    elif 'vyos' in config_lower:
        return 'vyos'
    elif 'fortinet' in config_lower:
        return 'fortinet'
    elif 'checkpoint' in config_lower:
        return 'checkpoint'
    else:
        return 'unknown'


def _infer_device_role(node_name: str, config_format: str, device_type: str) -> str:
    """
    Infer device role from name, config format, and device type.
    
    Args:
        node_name: Device hostname
        config_format: Configuration format
        device_type: Device type from Batfish
        
    Returns:
        Inferred role (router, switch, firewall, load_balancer, etc.)
    """
    name_lower = node_name.lower()
    config_lower = config_format.lower()
    
    # Check device type first
    if device_type and device_type != 'unknown':
        return device_type
    
    # Infer from name patterns
    if any(keyword in name_lower for keyword in ['fw', 'firewall', 'asa', 'srx']):
        return 'firewall'
    elif any(keyword in name_lower for keyword in ['switch', 'sw', 'nexus', 'n9k', 'n7k']):
        return 'switch'
    elif any(keyword in name_lower for keyword in ['router', 'rtr', 'core', 'edge', 'branch']):
        return 'router'
    elif any(keyword in name_lower for keyword in ['lb', 'load', 'balancer', 'f5']):
        return 'load_balancer'
    
    # Infer from configuration format
    if 'asa' in config_lower or 'palo_alto' in config_lower or 'fortinet' in config_lower:
        return 'firewall'
    elif 'nxos' in config_lower:
        return 'switch'
    elif 'ios' in config_lower or 'juniper' in config_lower:
        # Could be router or switch - default to router
        return 'router'
    elif 'f5' in config_lower:
        return 'load_balancer'
    
    return 'unknown'
