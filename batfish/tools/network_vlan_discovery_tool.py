"""
VLAN Discovery Tool

Discovers VLANs in the network and shows which devices/ports have them configured.

Two modes:
1. Discovery mode (no VLANs specified): Lists all active VLANs with basic stats
2. Detail mode (VLANs specified): Shows exactly which devices have those VLANs and on which ports
"""

import logging
from typing import Dict, Any, List, Optional
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


class VlanDiscoveryInput(BaseModel):
    """Input model for VLAN discovery."""
    network: str = Field(..., description="Batfish network name")
    snapshot: str = Field(..., description="Batfish snapshot name")
    vlans: Optional[List[int]] = Field(None, description="Optional list of VLAN IDs to query (e.g., [1, 400, 120])")
    host: str = Field("localhost", description="Batfish host to connect to")


def parse_vlan_from_interface(interface_name: str) -> Optional[int]:
    """
    Extract VLAN ID from interface name.
    
    Examples:
        Vlan400 -> 400
        vlan1 -> 1
        GigabitEthernet0/1 -> None
    
    Args:
        interface_name: Interface name string
        
    Returns:
        VLAN ID as integer, or None if not a VLAN interface
    """
    import re
    match = re.search(r'[Vv]lan(\d+)', interface_name)
    if match:
        return int(match.group(1))
    return None


def execute(input_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Discover VLANs in the network.
    
    Mode 1 (Discovery): If no VLANs specified, returns list of all active VLANs with:
    - VLAN ID
    - VLAN name (if available)
    - Number of devices with this VLAN
    - Number of ports in this VLAN
    - Subnets associated with this VLAN
    
    Mode 2 (Detail): If VLANs specified, returns detailed information:
    - For each VLAN, shows which devices have it
    - For each device, shows which ports have the VLAN
    - Port details: interface name, access/trunk mode, status
    
    Args:
        input_data: Dictionary containing network, snapshot, optional vlans list, and host
        
    Returns:
        Dictionary with:
        - ok: Success status
        - mode: "discovery" or "detail"
        - vlans: List of VLAN information objects
        - summary: Human-readable summary
    """
    try:
        # Validate input
        validated_input = VlanDiscoveryInput(**input_data)
        
        network = validated_input.network
        snapshot = validated_input.snapshot
        vlans_filter = validated_input.vlans
        host = validated_input.host
        
        mode = "detail" if vlans_filter else "discovery"
        
        logger.info(f"VLAN discovery for '{network}', snapshot '{snapshot}' (mode: {mode})")
        if vlans_filter:
            logger.info(f"Filtering to VLANs: {vlans_filter}")
        
        # Initialize Batfish session
        bf = Session(host=host)
        bf.set_network(network)
        bf.set_snapshot(snapshot)
        
        logger.info(f"Connected to Batfish host: {host}")
        
        # Get interface properties to find VLANs
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
                "mode": mode,
                "vlans": [],
                "summary": "No interface data found in snapshot."
            }
        
        logger.info(f"Retrieved {len(interfaces_df)} interface records")
        
        # Extract node and interface names
        interfaces_df['Node'] = interfaces_df['Interface'].apply(
            lambda i: i.hostname if hasattr(i, 'hostname') else str(i).split('[')[0]
        )
        interfaces_df['Interface_Name'] = interfaces_df['Interface'].apply(
            lambda i: i.interface if hasattr(i, 'interface') else str(i).split('[')[-1].rstrip(']')
        )
        
        # Get IP ownership to map VLANs to subnets
        logger.info("Retrieving IP ownership data...")
        owners_df, error = safe_batfish_query(
            bf,
            "ipOwners query",
            lambda: bf.q.ipOwners(),
            timeout=30
        )
        
        # Build VLAN mapping
        vlan_data = defaultdict(lambda: {
            "vlan_id": 0,
            "devices": set(),
            "ports": [],
            "subnets": set()
        })
        
        # Process interfaces to find VLANs
        for _, row in interfaces_df.iterrows():
            node = str(row.get('Node', ''))
            interface_name = str(row.get('Interface_Name', ''))
            access_vlan = row.get('Access_VLAN')
            allowed_vlans = row.get('Allowed_VLANs')
            switchport_mode = row.get('Switchport_Mode')
            active = row.get('Active', True)
            
            if not node or node == 'nan':
                continue
            
            # Check for SVI (Switched Virtual Interface) - these are VLAN interfaces
            vlan_id = parse_vlan_from_interface(interface_name)
            if vlan_id:
                vlan_data[vlan_id]["vlan_id"] = vlan_id
                vlan_data[vlan_id]["devices"].add(node)
                vlan_data[vlan_id]["ports"].append({
                    "device": node,
                    "interface": interface_name,
                    "type": "SVI",
                    "mode": "routed",
                    "active": bool(active) if active is not None else True
                })
            
            # Check for access VLAN
            if access_vlan and str(access_vlan) != 'nan':
                vlan_id = int(access_vlan)
                vlan_data[vlan_id]["vlan_id"] = vlan_id
                vlan_data[vlan_id]["devices"].add(node)
                vlan_data[vlan_id]["ports"].append({
                    "device": node,
                    "interface": interface_name,
                    "type": "access",
                    "mode": str(switchport_mode) if switchport_mode else "access",
                    "active": bool(active) if active is not None else True
                })
            
            # Check for trunk VLANs
            if allowed_vlans and str(allowed_vlans) != 'nan':
                # Parse allowed VLANs (can be ranges like "1-4094" or lists like "1,10,20")
                allowed_str = str(allowed_vlans)
                vlan_list = []
                
                for part in allowed_str.split(','):
                    part = part.strip()
                    if '-' in part:
                        # Range: 1-4094
                        try:
                            start, end = part.split('-')
                            # Don't expand huge ranges
                            if int(end) - int(start) < 100:
                                vlan_list.extend(range(int(start), int(end) + 1))
                        except:
                            pass
                    else:
                        # Single VLAN
                        try:
                            vlan_list.append(int(part))
                        except:
                            pass
                
                for vlan_id in vlan_list:
                    vlan_data[vlan_id]["vlan_id"] = vlan_id
                    vlan_data[vlan_id]["devices"].add(node)
                    # Only add trunk ports if not already added as access
                    if not any(p["device"] == node and p["interface"] == interface_name 
                              for p in vlan_data[vlan_id]["ports"]):
                        vlan_data[vlan_id]["ports"].append({
                            "device": node,
                            "interface": interface_name,
                            "type": "trunk",
                            "mode": str(switchport_mode) if switchport_mode else "trunk",
                            "active": bool(active) if active is not None else True
                        })
        
        # Map VLANs to subnets using IP ownership
        if owners_df is not None and not owners_df.empty:
            for _, row in owners_df.iterrows():
                interface = str(row.get('Interface', ''))
                ip = str(row.get('IP', ''))
                mask = str(row.get('Mask', ''))
                
                # Extract VLAN from interface
                vlan_id = parse_vlan_from_interface(interface)
                if vlan_id and ip and ip != 'nan':
                    # Create CIDR notation
                    if mask and mask != 'nan' and '/' not in ip:
                        ip_parts = ip.split('.')
                        if len(ip_parts) == 4:
                            subnet = f"{'.'.join(ip_parts[:3])}.0/{mask}"
                    elif '/' in ip:
                        ip_parts = ip.split('/')[0].split('.')
                        if len(ip_parts) == 4:
                            subnet = f"{'.'.join(ip_parts[:3])}.0/{ip.split('/')[-1]}"
                    else:
                        ip_parts = ip.split('.')
                        if len(ip_parts) == 4:
                            subnet = f"{'.'.join(ip_parts[:3])}.0/24"
                    
                    if 'subnet' in locals():
                        vlan_data[vlan_id]["subnets"].add(subnet)
        
        # Filter VLANs if specified
        if vlans_filter:
            vlan_data = {vlan_id: data for vlan_id, data in vlan_data.items() 
                        if vlan_id in vlans_filter}
        
        # Build result based on mode
        if mode == "discovery":
            # Discovery mode: summarized list
            vlans_result = []
            for vlan_id in sorted(vlan_data.keys()):
                data = vlan_data[vlan_id]
                vlans_result.append({
                    "vlan_id": int(vlan_id),
                    "name": f"Vlan{vlan_id}",  # Default name
                    "device_count": len(data["devices"]),
                    "port_count": len(data["ports"]),
                    "subnets": sorted(list(data["subnets"])),
                    "devices": sorted(list(data["devices"]))
                })
            
            summary = f"Discovered {len(vlans_result)} active VLAN(s) in the network."
            
        else:
            # Detail mode: full port-level details
            vlans_result = []
            for vlan_id in sorted(vlan_data.keys()):
                data = vlan_data[vlan_id]
                
                # Group ports by device
                devices_detail = defaultdict(list)
                for port in data["ports"]:
                    devices_detail[port["device"]].append({
                        "interface": port["interface"],
                        "type": port["type"],
                        "mode": port["mode"],
                        "active": port["active"]
                    })
                
                vlans_result.append({
                    "vlan_id": int(vlan_id),
                    "name": f"Vlan{vlan_id}",
                    "subnets": sorted(list(data["subnets"])),
                    "devices": [
                        {
                            "device": device,
                            "ports": sorted(ports, key=lambda x: x["interface"])
                        }
                        for device, ports in sorted(devices_detail.items())
                    ],
                    "total_ports": len(data["ports"])
                })
            
            summary = (
                f"Found detailed information for {len(vlans_result)} VLAN(s). "
                f"Total: {sum(v['total_ports'] for v in vlans_result)} port(s) across "
                f"{len(set(d['device'] for v in vlans_result for d in v['devices']))} device(s)."
            )
        
        logger.info(summary)
        
        return {
            "ok": True,
            "mode": mode,
            "vlans": vlans_result,
            "summary": summary
        }
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error discovering VLANs: {error_msg}")
        import traceback
        logger.error(traceback.format_exc())
        return {
            "ok": False,
            "error": error_msg,
            "vlans": []
        }

