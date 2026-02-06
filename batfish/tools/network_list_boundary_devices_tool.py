"""
Network List Boundary Devices Tool

List the REAL segmentation enforcement points in the network - the devices/interfaces 
that actually own subnets and route traffic (e.g., L3 switch SVIs, router interfaces).

This tool finds where security controls should be applied, not theoretical L3 topology.
"""

import logging
from typing import Dict, Any
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


class NetworkListBoundaryDevicesInput(BaseModel):
    """Input model for listing boundary devices."""
    network: str = Field(..., description="Batfish network name")
    snapshot: str = Field(..., description="Batfish snapshot name")
    host: str = Field("localhost", description="Batfish host to connect to")


# Valid network device vendors - only these can be segmentation enforcement points
VALID_VENDORS = {"cisco", "juniper", "arista", "palo alto", "f5", "vyos"}


def execute(input_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    List the real segmentation enforcement points - devices that route between multiple subnets.
    
    Returns devices that have interfaces in MULTIPLE different subnets, indicating they
    are performing inter-subnet routing and enforcing segmentation policies.
    
    Excludes devices with only a single management IP (e.g., just Vlan1 for management).
    
    Args:
        input_data: Dictionary containing network, snapshot, and host
        
    Returns:
        Dictionary with:
        - ok: Success status
        - boundaries: List of devices that route between multiple subnets
        - summary: Human-readable summary of results
    """
    try:
        # Validate input
        validated_input = NetworkListBoundaryDevicesInput(**input_data)
        
        network = validated_input.network
        snapshot = validated_input.snapshot
        host = validated_input.host
        
        logger.info(f"Finding segmentation enforcement points for network '{network}', snapshot '{snapshot}'")
        
        # Initialize Batfish session
        bf = Session(host=host)
        bf.set_network(network)
        bf.set_snapshot(snapshot)
        
        logger.info(f"Connected to Batfish host: {host}")
        
        # First, get valid network nodes by vendor (with safety wrapper)
        logger.info("Retrieving network nodes to filter by vendor...")
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
                "boundaries": [],
                "summary": "No network devices found in snapshot."
            }
        
        # Filter to valid network devices only (exclude sensors, hosts, endpoints)
        valid_nodes = set()
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
            logger.warning(f"No valid network devices found (valid vendors: {', '.join(VALID_VENDORS)})")
            return {
                "ok": True,
                "boundaries": [],
                "summary": "No valid network devices found. Snapshot may contain only hosts or unsupported devices."
            }
        
        logger.info(f"Found {len(valid_nodes)} valid network device(s): {', '.join(sorted(valid_nodes))}")
        
        # Get IP ownership data (with safety wrapper)
        logger.info("Retrieving IP ownership data...")
        df, error = safe_batfish_query(
            bf,
            "ipOwners query",
            lambda: bf.q.ipOwners(),
            timeout=30
        )
        
        if error or df is None or df.empty:
            logger.warning(f"No IP ownership data found: {error}")
            return {
                "ok": True,
                "boundaries": [],
                "summary": "No IP ownership data found in snapshot."
            }
        
        logger.info(f"Retrieved {len(df)} IP ownership records")
        logger.info(f"ipOwners columns: {list(df.columns)}")
        
        # ipOwners returns: Node, VRF, Interface, IP, Mask
        # We need to combine IP and Mask to get CIDR notation
        
        if 'Node' not in df.columns:
            logger.error("ipOwners query did not return 'Node' column")
            return {
                "ok": False,
                "error": "ipOwners query missing Node column",
                "boundaries": []
            }
        
        # Extract device name from Node column (the correct way)
        df['Device'] = df['Node'].astype(str)
        
        # Filter to only valid network devices (exclude sensors, hosts, endpoints)
        df = df[df['Device'].isin(valid_nodes)]
        
        if df.empty:
            logger.warning("No IP ownership data for valid network devices")
            return {
                "ok": True,
                "boundaries": [],
                "summary": f"Found {len(valid_nodes)} network devices but none have IP addresses configured."
            }
        
        logger.info(f"Filtered to {len(df)} IP ownership records from valid network devices")
        
        # Extract interface name from Interface column
        df['Interface_Name'] = df['Interface'].astype(str)
        
        # Combine IP and Mask to create CIDR notation
        def create_cidr(row):
            ip = str(row.get('IP', ''))
            mask = str(row.get('Mask', ''))
            
            if ip and ip != 'nan':
                if mask and mask != 'nan' and '/' not in ip:
                    return f"{ip}/{mask}"
                elif '/' in ip:
                    return ip
                else:
                    return ip
            return None
        
        df['CIDR'] = df.apply(create_cidr, axis=1)
        
        # Drop rows without valid CIDR
        df = df[df['CIDR'].notna()]
        
        # Log sample
        if not df.empty:
            logger.info(f"Sample: Device={df.iloc[0]['Device']}, Interface={df.iloc[0]['Interface_Name']}, CIDR={df.iloc[0]['CIDR']}")
        
        # First, get ALL interfaces per device to identify boundary devices
        # A boundary device has MULTIPLE interfaces with IPs (not just management)
        device_interface_count = df.groupby('Device')['Interface_Name'].nunique().reset_index()
        device_interface_count.columns = ['Device', 'Interface_Count']
        
        # Filter to devices with 2+ interfaces (actual routing devices)
        boundary_devices = set(
            device_interface_count[device_interface_count['Interface_Count'] >= 2]['Device'].tolist()
        )
        
        if not boundary_devices:
            logger.warning("No devices found with multiple L3 interfaces")
            return {
                "ok": True,
                "boundaries": [],
                "summary": "No segmentation enforcement devices found. All devices have only single management IPs."
            }
        
        logger.info(f"Found {len(boundary_devices)} devices with multiple L3 interfaces: {', '.join(sorted(boundary_devices))}")
        
        # Filter to only boundary devices
        df = df[df['Device'].isin(boundary_devices)]
        
        # Group by device and interface, collecting all CIDRs they own
        boundaries = df.groupby(['Device', 'Interface_Name'])['CIDR']\
            .apply(lambda x: sorted([str(cidr) for cidr in x if cidr and str(cidr) != 'nan']))\
            .reset_index()
        
        # Filter out empty subnet lists
        boundaries = boundaries[boundaries['CIDR'].apply(lambda x: len(x) > 0)]
        
        # Build result list grouped by device
        device_results = {}
        for _, row in boundaries.iterrows():
            device = str(row.Device)
            if device not in device_results:
                device_results[device] = {
                    "node": device,
                    "interfaces": []
                }
            device_results[device]["interfaces"].append({
                "interface": str(row.Interface_Name),
                "owns_subnets": row.CIDR
            })
        
        # Convert to list
        result = list(device_results.values())
        
        # Generate summary
        unique_devices = len(boundary_devices)
        total_interfaces = sum(len(d["interfaces"]) for d in result)
        
        summary = (
            f"Found {unique_devices} segmentation enforcement device(s) with {total_interfaces} L3 interfaces. "
            f"These devices route between multiple subnets. Apply ALL security controls here."
        )
        
        logger.info(summary)
        
        return {
            "ok": True,
            "boundaries": result,
            "summary": summary
        }
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error finding segmentation enforcement points: {error_msg}")
        import traceback
        logger.error(traceback.format_exc())
        return {
            "ok": False,
            "error": error_msg,
            "boundaries": []
        }


