"""
Network Summary Tool

Provides a high-level overview of the network including device counts, vendor breakdown,
device types, and key statistics. Useful for understanding network composition at a glance.
"""

import logging
from typing import Dict, Any
import numpy as np
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


class NetworkSummaryInput(BaseModel):
    """Input model for network summary."""
    network: str = Field(..., description="Batfish network name")
    snapshot: str = Field(..., description="Batfish snapshot name")
    host: str = Field("localhost", description="Batfish host to connect to")


# Valid network infrastructure vendors
NETWORK_VENDORS = {"cisco", "juniper", "arista", "palo alto", "f5", "vyos"}


def convert_to_native_types(obj):
    """
    Recursively convert numpy types to native Python types for JSON serialization.
    
    Args:
        obj: Object to convert (can be dict, list, numpy type, etc.)
        
    Returns:
        Object with all numpy types converted to native Python types
    """
    if isinstance(obj, dict):
        return {key: convert_to_native_types(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [convert_to_native_types(item) for item in obj]
    elif isinstance(obj, (np.integer, np.int64, np.int32, np.int16, np.int8)):
        return int(obj)
    elif isinstance(obj, (np.floating, np.float64, np.float32)):
        return float(obj)
    elif isinstance(obj, np.bool_):
        return bool(obj)
    elif isinstance(obj, np.ndarray):
        return [convert_to_native_types(item) for item in obj.tolist()]
    else:
        return obj


def execute(input_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate a comprehensive network summary.
    
    Provides overview of:
    - Total device count
    - Network devices vs sensors/hosts
    - Vendor breakdown
    - Device type distribution
    - Subnet count
    - Interface statistics
    
    Args:
        input_data: Dictionary containing network, snapshot, and host
        
    Returns:
        Dictionary with:
        - ok: Success status
        - summary: High-level statistics
        - devices: Device breakdown by vendor and type
        - subnets: Subnet statistics
    """
    try:
        # Validate input
        validated_input = NetworkSummaryInput(**input_data)
        
        network = validated_input.network
        snapshot = validated_input.snapshot
        host = validated_input.host
        
        logger.info(f"Generating network summary for '{network}', snapshot '{snapshot}'")
        
        # Initialize Batfish session
        bf = Session(host=host)
        bf.set_network(network)
        bf.set_snapshot(snapshot)
        
        logger.info(f"Connected to Batfish host: {host}")
        
        # Get node properties (with safety wrapper)
        logger.info("Retrieving node properties...")
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
                "summary": {
                    "total_devices": 0,
                    "network_devices": 0,
                    "sensors_hosts": 0
                },
                "message": "No devices found in snapshot."
            }
        
        total_devices = len(nodes_df)
        logger.info(f"Found {total_devices} total devices")
        
        # Categorize devices
        network_devices = []
        sensors_hosts = []
        vendor_counts = {}
        config_format_counts = {}
        
        for _, row in nodes_df.iterrows():
            node_name = str(row.get('Node', ''))
            config_format = str(row.get('Configuration_Format', 'unknown'))
            
            # Count by configuration format
            config_format_counts[config_format] = config_format_counts.get(config_format, 0) + 1
            
            # Determine if network device or sensor/host
            config_lower = config_format.lower()
            is_network_device = False
            vendor = "Unknown"
            
            for valid_vendor in NETWORK_VENDORS:
                if valid_vendor.replace(" ", "_") in config_lower or valid_vendor in config_lower:
                    is_network_device = True
                    vendor = valid_vendor.title()
                    break
            
            if is_network_device:
                network_devices.append(node_name)
                vendor_counts[vendor] = vendor_counts.get(vendor, 0) + 1
            else:
                sensors_hosts.append(node_name)
                # Extract vendor from config format for sensors/hosts
                if config_format != 'unknown':
                    host_vendor = config_format.replace('_', ' ').title()
                    vendor_counts[host_vendor] = vendor_counts.get(host_vendor, 0) + 1
        
        # Get interface statistics
        logger.info("Retrieving interface statistics...")
        interfaces_df, error = safe_batfish_query(
            bf,
            "interfaceProperties query",
            lambda: bf.q.interfaceProperties(),
            timeout=30
        )
        
        interface_count = 0
        l3_interface_count = 0
        if interfaces_df is not None and not interfaces_df.empty:
            interface_count = int(len(interfaces_df))
            # Count L3 interfaces (those with All_Prefixes)
            if 'All_Prefixes' in interfaces_df.columns:
                l3_interface_count = int(interfaces_df['All_Prefixes'].notna().sum())
        
        # Get subnet statistics
        logger.info("Retrieving subnet statistics...")
        unique_subnets = set()
        if interfaces_df is not None and not interfaces_df.empty and 'All_Prefixes' in interfaces_df.columns:
            # Extract node names from Interface objects
            interfaces_df['Node'] = interfaces_df['Interface'].apply(
                lambda i: i.hostname if hasattr(i, 'hostname') else str(i).split('[')[0]
            )
            
            # Filter to network devices only
            network_df = interfaces_df[interfaces_df['Node'].isin(network_devices)]
            
            # Explode All_Prefixes and count unique subnets
            if not network_df.empty:
                exploded = network_df.explode('All_Prefixes')
                exploded = exploded.dropna(subset=['All_Prefixes'])
                unique_subnets = set(exploded['All_Prefixes'].astype(str).unique())
        
        # Build result
        result = {
            "ok": True,
            "summary": {
                "total_devices": int(total_devices),
                "network_devices": int(len(network_devices)),
                "sensors_hosts": int(len(sensors_hosts)),
                "total_interfaces": int(interface_count),
                "l3_interfaces": int(l3_interface_count),
                "unique_subnets": int(len(unique_subnets))
            },
            "vendors": dict(sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True)),
            "device_breakdown": {
                "network_infrastructure": sorted(network_devices),
                "sensors_and_hosts": sorted(sensors_hosts)
            },
            "top_platforms": dict(sorted(
                config_format_counts.items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:10])  # Top 10 platforms
        }
        
        # Generate human-readable summary
        summary_text = (
            f"Network '{network}' contains {total_devices} devices: "
            f"{len(network_devices)} network infrastructure devices "
            f"({', '.join([f'{count} {vendor}' for vendor, count in sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True)[:3]])}) "
            f"and {len(sensors_hosts)} sensors/hosts. "
            f"Total: {interface_count} interfaces ({l3_interface_count} L3), {len(unique_subnets)} unique subnets."
        )
        
        result["summary_text"] = summary_text
        
        logger.info(summary_text)
        
        # Convert all numpy types to native Python types for JSON serialization
        result = convert_to_native_types(result)
        
        return result
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error generating network summary: {error_msg}")
        import traceback
        logger.error(traceback.format_exc())
        return {
            "ok": False,
            "error": error_msg
        }

