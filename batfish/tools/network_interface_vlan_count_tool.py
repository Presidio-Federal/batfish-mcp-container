"""
Network Interface VLAN Count Tool

Calculates and displays interface/port counts per VLAN for each network device.
Shows TOTAL port allocation per VLAN (all ports, connected or not).
Different from network_vlan_device_count which only counts connected ports.

Output format:
- Per device: VLAN breakdown with total port counts
- Summary: Total interfaces and VLANs
"""

import logging
from typing import Dict, Any
from collections import defaultdict
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


class NetworkInterfaceVlanCountInput(BaseModel):
    """Input model for interface VLAN count analysis."""
    network: str = Field(..., description="Batfish network name")
    snapshot: str = Field(..., description="Batfish snapshot name")
    host: str = Field(default="localhost", description="Batfish host")
    format: str = Field(default="detailed", description="Output format: 'detailed' or 'matrix'")


def execute(input_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze total interface/port counts per VLAN for each network device.
    Counts ALL ports with VLAN assignments, not just connected ones.
    
    Args:
        input_data: Dictionary containing network, snapshot, optional host and format
        
    Returns:
        Dictionary with:
        - ok: Success status
        - devices: List of devices with VLAN breakdown and port counts
        - summary: Overall statistics
    """
    try:
        # Validate input
        validated_input = NetworkInterfaceVlanCountInput(**input_data)
        
        network = validated_input.network
        snapshot = validated_input.snapshot
        host = validated_input.host
        output_format = validated_input.format.lower()
        
        logger.info(f"Analyzing interface VLAN counts for network={network}, snapshot={snapshot}")
        
        # Initialize Batfish session
        bf = Session(host=host)
        bf.set_network(network)
        bf.set_snapshot(snapshot)
        
        # Get interface properties
        logger.info("Querying interface properties...")
        interfaces, error = safe_batfish_query(
            bf,
            "interfaceProperties query",
            lambda: bf.q.interfaceProperties(),
            timeout=30
        )
        
        if error or interfaces is None:
            return {
                "ok": False,
                "error": f"Failed to get interface properties: {error}",
                "devices": []
            }
        
        # Process each interface and group by device and VLAN
        device_vlan_ports = defaultdict(lambda: defaultdict(list))
        
        for _, iface in interfaces.iterrows():
            iface_obj = iface.get('Interface')
            if not iface_obj:
                continue
                
            device = str(iface_obj.hostname) if hasattr(iface_obj, 'hostname') else 'unknown'
            iface_name = str(iface_obj.interface) if hasattr(iface_obj, 'interface') else 'unknown'
            
            # Skip VLAN interfaces (SVIs) - we only want physical/logical ports
            if iface_name.startswith('Vlan'):
                continue
            
            # Skip loopback and null interfaces
            if iface_name.lower().startswith(('loopback', 'null', 'tunnel')):
                continue
            
            # Get VLAN for this interface
            vlan = None
            
            # Check Access_VLAN first (most common for switchports)
            access_vlan = iface.get('Access_VLAN')
            if access_vlan and str(access_vlan) not in ['nan', 'null', 'None', '']:
                try:
                    vlan_num = int(float(access_vlan))
                    vlan = f"Vlan{vlan_num}"
                except:
                    pass
            
            # Check switchport mode and set defaults
            if vlan is None:
                switchport_mode = str(iface.get('Switchport_Mode', 'NONE'))
                primary_address = iface.get('Primary_Address')
                has_ip = primary_address and str(primary_address) not in ['nan', 'null', 'None', '']
                
                if switchport_mode == 'ACCESS':
                    # Access mode but no explicit VLAN = VLAN 1 (default access VLAN)
                    vlan = "Vlan1"
                elif switchport_mode == 'TRUNK':
                    # For trunk ports, use native VLAN if available, otherwise mark as Trunk
                    native_vlan = iface.get('Native_VLAN')
                    if native_vlan and str(native_vlan) not in ['nan', 'null', 'None']:
                        try:
                            vlan_num = int(float(native_vlan))
                            vlan = f"Vlan{vlan_num} (Trunk)"
                        except:
                            vlan = "Trunk"
                    else:
                        vlan = "Trunk"
                elif switchport_mode == 'NONE' and not has_ip:
                    # No switchport mode and no IP = likely unconfigured switchport = VLAN 1
                    vlan = "Vlan1"
            
            # Final fallback: If still no VLAN and no IP address, default to VLAN 1
            if vlan is None:
                primary_address = iface.get('Primary_Address')
                has_ip = primary_address and str(primary_address) not in ['nan', 'null', 'None', '']
                
                if not has_ip:
                    # No VLAN assignment and no IP = default VLAN 1
                    vlan = "Vlan1"
            
            # Add ALL ports with VLAN assignments (no connection check)
            if vlan:
                # Get interface status
                active = iface.get('Active', False)
                admin_up = iface.get('Admin_Up', False)
                
                device_vlan_ports[device][vlan].append({
                    "interface": iface_name,
                    "active": active,
                    "admin_up": admin_up
                })
        
        # Build result structure
        devices_result = []
        total_ports = 0
        all_vlans = set()
        
        for device in sorted(device_vlan_ports.keys()):
            vlan_data = device_vlan_ports[device]
            
            vlan_breakdown = []
            device_port_count = 0
            
            for vlan in sorted(vlan_data.keys()):
                ports = vlan_data[vlan]
                port_count = len(ports)
                
                # Count active ports
                active_count = len([p for p in ports if p["active"]])
                admin_up_count = len([p for p in ports if p["admin_up"]])
                
                vlan_breakdown.append({
                    "vlan": vlan,
                    "port_count": port_count,
                    "active_count": active_count,
                    "admin_up_count": admin_up_count,
                    "shutdown_count": port_count - admin_up_count,
                    "interfaces": [p["interface"] for p in ports]
                })
                
                device_port_count += port_count
                all_vlans.add(vlan)
            
            total_ports += device_port_count
            
            devices_result.append({
                "device": device,
                "vlan_breakdown": vlan_breakdown,
                "total_ports": device_port_count,
                "total_vlans": len(vlan_breakdown)
            })
        
        # Generate summary
        summary = (
            f"{total_ports} total ports across "
            f"{len(all_vlans)} VLANs on {len(devices_result)} devices"
        )
        
        logger.info(summary)
        
        # If matrix format requested, build compact matrix view
        if output_format == "matrix":
            # Get all unique VLANs across all devices
            all_vlans_list = sorted(all_vlans, key=lambda x: (x.replace("Vlan", "").replace(" (Trunk)", ""), x))
            
            # Build matrix data
            matrix_rows = []
            for device in sorted(device_vlan_ports.keys()):
                row = {"device": device}
                vlan_data = device_vlan_ports[device]
                
                # For each VLAN, get the port count
                for vlan in all_vlans_list:
                    if vlan in vlan_data:
                        ports = vlan_data[vlan]
                        total_count = len(ports)
                        active_count = len([p for p in ports if p["active"]])
                        # Show as "active/total"
                        row[vlan] = f"{active_count}/{total_count}"
                    else:
                        row[vlan] = "0/0"
                
                # Add totals
                row["total_ports"] = sum(len(vlan_data[v]) for v in vlan_data.keys())
                matrix_rows.append(row)
            
            return {
                "ok": True,
                "format": "matrix",
                "vlans": all_vlans_list,
                "matrix": matrix_rows,
                "summary": summary,
                "note": "Matrix format shows 'active_ports/total_ports' per VLAN",
                "totals": {
                    "total_ports": total_ports,
                    "total_vlans": len(all_vlans),
                    "devices_analyzed": len(devices_result)
                }
            }
        
        # Otherwise return detailed format
        return {
            "ok": True,
            "format": "detailed",
            "devices": devices_result,
            "summary": summary,
            "totals": {
                "total_ports": total_ports,
                "total_vlans": len(all_vlans),
                "devices_analyzed": len(devices_result)
            }
        }
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error analyzing interface VLAN counts: {error_msg}")
        import traceback
        logger.error(traceback.format_exc())
        return {
            "ok": False,
            "error": error_msg,
            "devices": []
        }

