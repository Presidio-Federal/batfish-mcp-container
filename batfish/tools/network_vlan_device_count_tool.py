"""
Network VLAN Device Count Tool

Calculates and displays device counts per VLAN for each network device.
Shows how many devices are connected to each VLAN on each switch/router.

Output format:
- Per device: VLAN breakdown with device counts
- Summary: Total interfaces, devices, and VLANs
"""

import logging
from typing import Dict, Any, List
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


class NetworkVlanDeviceCountInput(BaseModel):
    """Input model for VLAN device count analysis."""
    network: str = Field(..., description="Batfish network name")
    snapshot: str = Field(..., description="Batfish snapshot name")
    host: str = Field(default="localhost", description="Batfish host")
    format: str = Field(default="detailed", description="Output format: 'detailed' or 'matrix'")


def execute(input_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze device counts per VLAN for each network device.
    
    Args:
        input_data: Dictionary containing network, snapshot, and optional host
        
    Returns:
        Dictionary with:
        - ok: Success status
        - devices: List of devices with VLAN breakdown and device counts
        - summary: Overall statistics
    """
    try:
        # Validate input
        validated_input = NetworkVlanDeviceCountInput(**input_data)
        
        network = validated_input.network
        snapshot = validated_input.snapshot
        host = validated_input.host
        output_format = validated_input.format.lower()
        
        logger.info(f"Analyzing VLAN device counts for network={network}, snapshot={snapshot}")
        
        # Initialize Batfish session
        bf = Session(host=host)
        bf.set_network(network)
        bf.set_snapshot(snapshot)
        
        # Get layer 3 edges (routed connections)
        logger.info("Querying layer 3 edges...")
        l3_edges, error = safe_batfish_query(
            bf,
            "layer3Edges query",
            lambda: bf.q.layer3Edges(),
            timeout=30
        )
        
        if error:
            logger.warning(f"Could not get layer 3 edges: {error}")
            l3_edges = None
        
        # Get layer 2 edges (switched connections) - this is what we really need for VLANs
        logger.info("Querying layer 1 topology (physical connections)...")
        layer1_topology, error = safe_batfish_query(
            bf,
            "layer1Topology query",
            lambda: bf.q.layer1Edges(),
            timeout=30
        )
        
        if error:
            logger.warning(f"Could not get layer 1 topology: {error}")
            layer1_topology = None
        
        # Get interface properties to get VLAN info
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
        
        # Build a map of what's connected where from both L1 and L3
        connection_map = {}
        
        # Add L3 connections
        if l3_edges is not None and not l3_edges.empty:
            for _, edge in l3_edges.iterrows():
                iface1 = edge.get('Interface')
                iface2 = edge.get('Remote_Interface')
                
                if iface1 and iface2:
                    device1 = str(iface1.hostname) if hasattr(iface1, 'hostname') else 'unknown'
                    iface1_name = str(iface1.interface) if hasattr(iface1, 'interface') else 'unknown'
                    device2 = str(iface2.hostname) if hasattr(iface2, 'hostname') else 'unknown'
                    
                    key = f"{device1}:{iface1_name}"
                    connection_map[key] = device2
        
        # Add L1 connections (physical/switched)
        if layer1_topology is not None and not layer1_topology.empty:
            for _, edge in layer1_topology.iterrows():
                iface1 = edge.get('Interface')
                iface2 = edge.get('Remote_Interface')
                
                if iface1 and iface2:
                    device1 = str(iface1.hostname) if hasattr(iface1, 'hostname') else 'unknown'
                    iface1_name = str(iface1.interface) if hasattr(iface1, 'interface') else 'unknown'
                    device2 = str(iface2.hostname) if hasattr(iface2, 'hostname') else 'unknown'
                    
                    key = f"{device1}:{iface1_name}"
                    # Only add if not already in map (L3 takes precedence)
                    if key not in connection_map:
                        connection_map[key] = device2
        
        # Now process each interface and group by device and VLAN
        device_vlan_ports = defaultdict(lambda: defaultdict(list))
        
        for _, iface in interfaces.iterrows():
            iface_obj = iface.get('Interface')
            if not iface_obj:
                continue
                
            device = str(iface_obj.hostname) if hasattr(iface_obj, 'hostname') else 'unknown'
            iface_name = str(iface_obj.interface) if hasattr(iface_obj, 'interface') else 'unknown'
            
            # Skip VLAN interfaces (SVIs) - we only want physical ports
            if iface_name.startswith('Vlan'):
                continue
            
            # Get VLAN for this interface
            vlan = None
            
            # Check Access_VLAN first (most common for switchports)
            access_vlan = iface.get('Access_VLAN')
            if access_vlan and str(access_vlan) not in ['nan', 'null', 'None', '']:
                try:
                    vlan_num = int(float(access_vlan))
                    vlan = f"Vlan{vlan_num}"
                    logger.debug(f"{device}:{iface_name} - Explicit Access_VLAN: {vlan}")
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
                    logger.debug(f"{device}:{iface_name} - ACCESS mode, defaulting to Vlan1")
                elif switchport_mode == 'TRUNK':
                    # For trunk ports, use native VLAN if available, otherwise mark as Trunk
                    native_vlan = iface.get('Native_VLAN')
                    if native_vlan and str(native_vlan) not in ['nan', 'null', 'None']:
                        try:
                            vlan_num = int(float(native_vlan))
                            vlan = f"Vlan{vlan_num} (Trunk)"
                            logger.debug(f"{device}:{iface_name} - TRUNK with native VLAN: {vlan}")
                        except:
                            vlan = "Trunk"
                    else:
                        vlan = "Trunk"
                        logger.debug(f"{device}:{iface_name} - TRUNK without native VLAN")
                elif switchport_mode == 'NONE' and not has_ip:
                    # No switchport mode and no IP = likely unconfigured switchport = VLAN 1
                    vlan = "Vlan1"
                    logger.debug(f"{device}:{iface_name} - NONE mode without IP, defaulting to Vlan1")
                elif has_ip:
                    logger.debug(f"{device}:{iface_name} - Has IP ({primary_address}), skipping (routed interface)")
            
            # Final fallback: If still no VLAN and no IP address, default to VLAN 1
            if vlan is None:
                primary_address = iface.get('Primary_Address')
                has_ip = primary_address and str(primary_address) not in ['nan', 'null', 'None', '']
                
                if not has_ip:
                    # No VLAN assignment and no IP = default VLAN 1
                    vlan = "Vlan1"
                    logger.debug(f"{device}:{iface_name} - Final fallback to Vlan1 (no VLAN, no IP)")
                else:
                    logger.debug(f"{device}:{iface_name} - Has IP, skipping")
            
            # Only process if we determined a VLAN
            if vlan:
                # Check if something is connected to this port
                key = f"{device}:{iface_name}"
                connected_device = connection_map.get(key, None)
                
                # Only add if there's a connection (back to original logic)
                if connected_device:
                    device_vlan_ports[device][vlan].append({
                        "interface": iface_name,
                        "connected_device": connected_device
                    })
        
        # Build result structure
        devices_result = []
        total_ports = 0
        all_vlans = set()
        all_connected_devices = set()
        
        for device in sorted(device_vlan_ports.keys()):
            vlan_data = device_vlan_ports[device]
            
            vlan_breakdown = []
            device_port_count = 0
            
            for vlan in sorted(vlan_data.keys()):
                ports = vlan_data[vlan]
                port_count = len(ports)
                
                # Get unique connected devices
                unique_devices = list(set(port["connected_device"] for port in ports))
                
                vlan_breakdown.append({
                    "vlan": vlan,
                    "port_count": port_count,
                    "connected_device_count": len(unique_devices),
                    "connected_devices": sorted(unique_devices),
                    "connections": ports
                })
                
                device_port_count += port_count
                all_vlans.add(vlan)
                all_connected_devices.update(unique_devices)
            
            total_ports += device_port_count
            
            devices_result.append({
                "device": device,
                "vlan_breakdown": vlan_breakdown,
                "total_ports": device_port_count,
                "total_vlans": len(vlan_breakdown)
            })
        
        # Generate summary
        summary = (
            f"{total_ports} ports with connections across "
            f"{len(all_vlans)} VLANs on {len(devices_result)} devices, "
            f"{len(all_connected_devices)} unique devices connected"
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
                
                # For each VLAN, get the connected device count
                for vlan in all_vlans_list:
                    if vlan in vlan_data:
                        ports = vlan_data[vlan]
                        connected_count = len(ports)  # All are connected since we filter above
                        unique_count = len(set(p["connected_device"] for p in ports))
                        # Show as "ports/devices" (e.g., "6/4" = 6 ports with 4 unique devices)
                        row[vlan] = f"{connected_count}/{unique_count}"
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
                "note": "Matrix format shows 'connected_ports/unique_devices' per VLAN",
                "totals": {
                    "total_ports": total_ports,
                    "unique_connected_devices": len(all_connected_devices),
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
                "unique_connected_devices": len(all_connected_devices),
                "total_vlans": len(all_vlans),
                "devices_analyzed": len(devices_result)
            }
        }
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error analyzing VLAN device counts: {error_msg}")
        import traceback
        logger.error(traceback.format_exc())
        return {
            "ok": False,
            "error": error_msg,
            "devices": []
        }

