"""
Network Segment Analysis Tool

Analyzes network segmentation by VLAN/VRF, showing which subnets belong to each segment
and which devices are in those segments.

Structure: VLAN → Subnets → Devices
Example: Vlan400 → [10.42.88.0/24, 10.42.89.0/24] → 45 devices (25 honeywell, 10 siemens, ...)

Useful for understanding network topology, device distribution, and segment composition.
"""

import logging
import re
from typing import Dict, Any, List, Tuple
from collections import defaultdict
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


class NetworkSegmentInput(BaseModel):
    """Input model for network segment analysis."""
    network: str = Field(..., description="Batfish network name")
    snapshot: str = Field(..., description="Batfish snapshot name")
    sample_size: int = Field(10, description="Number of device examples to show per segment (default: 10)")
    host: str = Field("localhost", description="Batfish host to connect to")


def normalize_device_name(device_name: str) -> str:
    """
    Normalize device names by removing unique identifiers (MAC addresses, serial numbers, etc.).
    
    Examples:
        honeywell-device-0040842014ba -> honeywell-device
        hp-inc-device-7c4d8f986228 -> hp-inc-device
        cisco-switch-001 -> cisco-switch
        sensor_12345 -> sensor
    
    Args:
        device_name: Original device name
        
    Returns:
        Normalized device name without unique identifiers
    """
    # Remove common MAC address patterns (12 hex chars, possibly with separators)
    name = re.sub(r'[-_:]?[0-9a-fA-F]{12}$', '', device_name)
    name = re.sub(r'[-_:][0-9a-fA-F]{2}([-_:][0-9a-fA-F]{2}){5}$', '', name)
    
    # Remove trailing serial numbers (4+ digits)
    name = re.sub(r'[-_]\d{4,}$', '', name)
    
    # Remove trailing short numbers (1-3 digits)
    name = re.sub(r'[-_]\d{1,3}$', '', name)
    
    # Remove trailing UUIDs
    name = re.sub(r'[-_][0-9a-fA-F]{8}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{12}$', '', name)
    
    # Clean up any trailing separators
    name = name.rstrip('-_:.')
    
    return name if name else device_name


def categorize_devices(device_list: List[str]) -> List[Dict[str, Any]]:
    """
    Categorize devices by type, counting instances of each normalized name.
    
    Args:
        device_list: List of device names
        
    Returns:
        List of device type summaries sorted by count (descending)
        [{"type": "honeywell-device", "count": 45, "examples": ["...", "..."]}, ...]
    """
    type_map = defaultdict(list)
    
    for device in device_list:
        normalized = normalize_device_name(device)
        type_map[normalized].append(device)
    
    # Build result list
    result = []
    for device_type, instances in type_map.items():
        result.append({
            "type": device_type,
            "count": len(instances),
            "examples": sorted(instances)[:5]  # Keep first 5 examples
        })
    
    # Sort by count (descending)
    result.sort(key=lambda x: x["count"], reverse=True)
    
    return result


def execute(input_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze network segmentation by VLAN and show devices within each segment.
    
    For each VLAN/VRF segment, shows:
    - Which subnets belong to this VLAN
    - Total device count in the VLAN
    - Device type breakdown with counts
    - Sample devices for each type
    
    Args:
        input_data: Dictionary containing network, snapshot, sample_size, and host
        
    Returns:
        Dictionary with:
        - ok: Success status
        - segments: List of VLAN/VRF objects with subnets and device breakdowns
        - summary: Human-readable summary
    """
    try:
        # Validate input
        validated_input = NetworkSegmentInput(**input_data)
        
        network = validated_input.network
        snapshot = validated_input.snapshot
        sample_size = validated_input.sample_size
        host = validated_input.host
        
        logger.info(f"Analyzing network segments for '{network}', snapshot '{snapshot}' (sample size: {sample_size})")
        
        # Initialize Batfish session
        bf = Session(host=host)
        bf.set_network(network)
        bf.set_snapshot(snapshot)
        
        logger.info(f"Connected to Batfish host: {host}")
        
        # Get IP ownership data to map devices to subnets
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
                "segments": [],
                "summary": "No IP ownership data found in snapshot."
            }
        
        logger.info(f"Retrieved {len(owners_df)} IP ownership records")
        
        # Get interface properties to map interfaces to VLANs/segments
        logger.info("Retrieving interface properties...")
        interfaces_df, error = safe_batfish_query(
            bf,
            "interfaceProperties query",
            lambda: bf.q.interfaceProperties(),
            timeout=30
        )
        
        if error or interfaces_df is None or interfaces_df.empty:
            logger.warning(f"No interface data found: {error}")
            return {
                "ok": True,
                "segments": [],
                "summary": "No interface data found in snapshot."
            }
        
        logger.info(f"Retrieved {len(interfaces_df)} interface records")
        
        # Build VLAN mapping: VLAN -> {subnets: set(), devices: list()}
        vlan_data = defaultdict(lambda: {"subnets": set(), "devices": list()})
        
        # Extract node from Interface object in interfaces_df
        interfaces_df['Node'] = interfaces_df['Interface'].apply(
            lambda i: i.hostname if hasattr(i, 'hostname') else str(i).split('[')[0]
        )
        interfaces_df['Interface_Name'] = interfaces_df['Interface'].apply(
            lambda i: i.interface if hasattr(i, 'interface') else str(i).split('[')[-1].rstrip(']')
        )
        
        # Process IP ownership to map devices and subnets to VLANs
        for _, row in owners_df.iterrows():
            node = str(row.get('Node', ''))
            ip = str(row.get('IP', ''))
            mask = str(row.get('Mask', ''))
            interface = str(row.get('Interface', ''))
            vrf = str(row.get('VRF', 'default'))
            
            if not node or node == 'nan':
                continue
            
            # Create CIDR notation for subnet
            subnet = None
            if ip and ip != 'nan':
                if mask and mask != 'nan' and '/' not in ip:
                    # Calculate network address from IP and mask
                    ip_parts = ip.split('.')
                    if len(ip_parts) == 4:
                        subnet = f"{'.'.join(ip_parts[:3])}.0/{mask}"
                elif '/' in ip:
                    # Extract network from IP/mask
                    ip_base = ip.split('/')[0]
                    mask_bits = ip.split('/')[-1]
                    ip_parts = ip_base.split('.')
                    if len(ip_parts) == 4:
                        subnet = f"{'.'.join(ip_parts[:3])}.0/{mask_bits}"
                else:
                    ip_parts = ip.split('.')
                    if len(ip_parts) == 4:
                        subnet = f"{'.'.join(ip_parts[:3])}.0/24"
            
            # Try to extract VLAN from interface name
            vlan_match = re.search(r'[Vv]lan(\d+)', interface)
            if vlan_match:
                vlan_id = vlan_match.group(1)
                segment_name = f"Vlan{vlan_id}"
                
                vlan_data[segment_name]["devices"].append(node)
                if subnet:
                    vlan_data[segment_name]["subnets"].add(subnet)
            elif subnet:
                # If no VLAN found, create a segment based on subnet
                segment_name = f"Subnet-{subnet}"
                vlan_data[segment_name]["devices"].append(node)
                vlan_data[segment_name]["subnets"].add(subnet)
        
        # Also process interfaces to find VLANs
        for _, row in interfaces_df.iterrows():
            node = str(row.get('Node', ''))
            interface_name = str(row.get('Interface_Name', ''))
            access_vlan = row.get('Access_VLAN')
            
            if not node or node == 'nan':
                continue
            
            # Check for access VLAN
            if access_vlan and str(access_vlan) != 'nan':
                segment_name = f"Vlan{access_vlan}"
                vlan_data[segment_name]["devices"].append(node)
            
            # Check for VLAN in interface name
            vlan_match = re.search(r'[Vv]lan(\d+)', interface_name)
            if vlan_match:
                vlan_id = vlan_match.group(1)
                segment_name = f"Vlan{vlan_id}"
                vlan_data[segment_name]["devices"].append(node)
        
        # Process segments (VLANs)
        segments_result = []
        for segment_name, data in vlan_data.items():
            # Deduplicate devices
            unique_devices = sorted(set(data["devices"]))
            total_count = len(unique_devices)
            
            if total_count == 0:
                continue
            
            # Categorize devices by type
            device_types = categorize_devices(unique_devices)
            
            # Limit device types shown based on sample_size
            top_types = device_types[:sample_size]
            
            # For each type, limit examples shown
            for device_type in top_types:
                device_type['examples'] = device_type['examples'][:min(5, sample_size)]
            
            segments_result.append({
                "segment": segment_name,
                "subnets": sorted(list(data["subnets"])) if data["subnets"] else [],
                "total_devices": total_count,
                "device_types": top_types,
                "showing_top": min(len(device_types), sample_size),
                "total_types": len(device_types)
            })
        
        # Sort segments by device count (descending)
        segments_result.sort(key=lambda x: x["total_devices"], reverse=True)
        
        # Generate summary
        total_segments = len(segments_result)
        total_devices_overall = sum(s["total_devices"] for s in segments_result)
        vlan_count = sum(1 for s in segments_result if s["segment"].startswith("Vlan"))
        subnet_only_count = total_segments - vlan_count
        
        summary = (
            f"Found {total_segments} network segment(s): {vlan_count} VLAN(s) "
            f"and {subnet_only_count} subnet-only segment(s). "
            f"Total: {total_devices_overall} device entries across all segments. "
            f"Showing top {sample_size} device types per segment."
        )
        
        logger.info(summary)
        
        return {
            "ok": True,
            "segments": segments_result,
            "summary": summary
        }
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error analyzing network segments: {error_msg}")
        import traceback
        logger.error(traceback.format_exc())
        return {
            "ok": False,
            "error": error_msg,
            "segments": []
        }

