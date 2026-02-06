"""
Network Device Connections Tool

Shows all interfaces, VLANs, and connected devices for a specific network device.
Displays detailed interface-level information including VLAN assignments and neighbor connections.

Output format:
- Interface name, VLAN, connected device (if any)
- Summary: Total interfaces, active connections, VLANs used
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


class NetworkDeviceConnectionsInput(BaseModel):
    """Input model for device connections analysis."""
    network: str = Field(..., description="Batfish network name")
    snapshot: str = Field(..., description="Batfish snapshot name")
    device: str = Field(..., description="Device name to analyze")
    host: str = Field(default="localhost", description="Batfish host")


def execute(input_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Show all interfaces, VLANs, and connected devices for a specific device.
    
    Args:
        input_data: Dictionary containing network, snapshot, device, and optional host
        
    Returns:
        Dictionary with:
        - ok: Success status
        - device: Device name
        - interfaces: List of interfaces with VLAN and connection info
        - summary: Statistics
    """
    try:
        # Validate input
        validated_input = NetworkDeviceConnectionsInput(**input_data)
        
        network = validated_input.network
        snapshot = validated_input.snapshot
        device = validated_input.device
        host = validated_input.host
        
        logger.info(f"Analyzing connections for device={device}, network={network}, snapshot={snapshot}")
        
        # Initialize Batfish session
        bf = Session(host=host)
        bf.set_network(network)
        bf.set_snapshot(snapshot)
        
        # Get interface properties for the specific device
        logger.info(f"Querying interface properties for {device}...")
        interfaces_df, error = safe_batfish_query(
            bf,
            "interfaceProperties query",
            lambda: bf.q.interfaceProperties(nodes=device),
            timeout=30
        )
        
        if error or interfaces_df is None:
            return {
                "ok": False,
                "error": f"Failed to get interface properties: {error}",
                "interfaces": []
            }
        
        if interfaces_df.empty:
            return {
                "ok": False,
                "error": f"Device '{device}' not found in snapshot",
                "interfaces": []
            }
        
        # Get layer 3 edges to find connections
        logger.info("Querying layer 3 edges...")
        l3_edges, error = safe_batfish_query(
            bf,
            "layer3Edges query",
            lambda: bf.q.layer3Edges(nodes=device),
            timeout=30
        )
        
        if error or l3_edges is None:
            return {
                "ok": False,
                "error": f"Failed to get layer 3 edges: {error}",
                "interfaces": []
            }
        
        # Build connection map
        connection_map = {}
        for _, edge in l3_edges.iterrows():
            iface1 = edge.get('Interface')
            iface2 = edge.get('Remote_Interface')
            
            if iface1 and iface2:
                iface1_name = str(iface1.interface) if hasattr(iface1, 'interface') else 'unknown'
                remote_device = str(iface2.hostname) if hasattr(iface2, 'hostname') else 'unknown'
                remote_iface = str(iface2.interface) if hasattr(iface2, 'interface') else 'unknown'
                
                connection_map[iface1_name] = {
                    "remote_device": remote_device,
                    "remote_interface": remote_iface
                }
        
        # Process interfaces
        interfaces_list = []
        vlans_used = set()
        active_connections = 0
        
        for _, iface in interfaces_df.iterrows():
            iface_obj = iface.get('Interface')
            if not iface_obj:
                continue
                
            iface_name = str(iface_obj.interface) if hasattr(iface_obj, 'interface') else 'unknown'
            
            # Extract VLAN info
            vlan = None
            
            # Check if interface name contains VLAN
            if 'Vlan' in iface_name:
                import re
                match = re.search(r'Vlan(\d+)', iface_name, re.IGNORECASE)
                if match:
                    vlan = f"Vlan{match.group(1)}"
            
            # Check access VLAN
            if vlan is None:
                access_vlan = iface.get('Access_VLAN')
                if access_vlan and str(access_vlan) not in ['nan', 'null', 'None', '']:
                    try:
                        vlan_num = int(float(access_vlan))
                        vlan = f"Vlan{vlan_num}"
                    except:
                        pass
            
            # Check switchport mode
            switchport_mode = str(iface.get('Switchport_Mode', 'NONE'))
            if vlan is None:
                if switchport_mode == 'ACCESS':
                    # Access mode but no explicit VLAN = VLAN 1
                    vlan = "Vlan1"
                elif switchport_mode == 'NONE':
                    # No switchport mode - check if routed or switched
                    primary_address = iface.get('Primary_Address')
                    has_ip = primary_address and str(primary_address) not in ['nan', 'null', 'None', '']
                    if not has_ip and not iface_name.startswith('Vlan'):
                        # No IP and not a VLAN interface = likely default VLAN 1
                        vlan = "Vlan1"
            
            # Check if trunk - show native VLAN
            if switchport_mode == 'TRUNK':
                native_vlan = iface.get('Native_VLAN')
                if native_vlan and str(native_vlan) not in ['nan', 'null', 'None']:
                    try:
                        vlan_num = int(float(native_vlan))
                        vlan = f"Trunk (Native: Vlan{vlan_num})"
                    except:
                        vlan = "Trunk"
                else:
                    vlan = "Trunk"
            
            if vlan is None:
                vlan = "No VLAN"
            
            if vlan and vlan != "No VLAN":
                vlans_used.add(vlan)
            
            # Get connection info
            connection = connection_map.get(iface_name, {})
            connected_device = connection.get("remote_device", "None")
            connected_interface = connection.get("remote_interface", "")
            
            if connected_device != "None":
                active_connections += 1
            
            # Get interface status
            active = iface.get('Active', False)
            
            # Get primary IP
            primary_address = iface.get('Primary_Address')
            ip_address = str(primary_address) if primary_address and str(primary_address) != 'nan' else "No IP"
            
            interfaces_list.append({
                "interface": iface_name,
                "vlan": vlan,
                "connected_device": connected_device,
                "connected_interface": connected_interface,
                "ip_address": ip_address,
                "active": active,
                "switchport_mode": switchport_mode
            })
        
        # Sort interfaces by name
        interfaces_list.sort(key=lambda x: x["interface"])
        
        # Generate summary
        summary = (
            f"{len(interfaces_list)} interfaces, "
            f"{active_connections} active connections, "
            f"{len(vlans_used)} VLANs used"
        )
        
        logger.info(f"Device {device}: {summary}")
        
        return {
            "ok": True,
            "device": device,
            "interfaces": interfaces_list,
            "summary": summary,
            "totals": {
                "total_interfaces": len(interfaces_list),
                "active_connections": active_connections,
                "vlans_count": len(vlans_used),
                "vlans": sorted(list(vlans_used))
            }
        }
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error analyzing device connections: {error_msg}")
        import traceback
        logger.error(traceback.format_exc())
        return {
            "ok": False,
            "error": error_msg,
            "interfaces": []
        }

