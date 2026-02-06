"""
Network Generate Topology Tool

Generate interactive HTML visualization of network topology from Batfish data.
Includes network devices (routers, switches, firewalls) and hosts (servers, endpoints).
"""

import os
import json
import tempfile
import logging
import traceback
from typing import Dict, Any, List, Optional
from datetime import datetime, date
from pydantic import BaseModel, Field
from pybatfish.client.session import Session

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class NetworkGenerateTopologyInput(BaseModel):
    """Input model for generating topology visualization."""
    network: str = Field(..., description="Batfish network name")
    snapshot: str = Field(..., description="Batfish snapshot name")
    host: str = Field("localhost", description="Batfish host to connect to")
    output_path: Optional[str] = Field(None, description="Optional output path for HTML file (auto-generated if None)")
    include_hosts: bool = Field(True, description="Include host nodes in topology")


# Custom JSON encoder for datetime objects
class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        if hasattr(obj, 'dict') and callable(obj.dict):
            return obj.dict()
        if hasattr(obj, '__dict__'):
            return obj.__dict__
        return super().default(obj)


def _infer_device_info(hostname: str) -> Dict[str, str]:
    """
    Infer device vendor and type from hostname.
    
    Args:
        hostname: Device hostname
        
    Returns:
        Dictionary with vendor, device_type, and platform
    """
    hostname_lower = hostname.lower()
    
    # Default values
    vendor = "Unknown"
    device_type = "device"
    platform = "unknown"
    
    # Vendor inference
    if "cisco" in hostname_lower:
        vendor = "Cisco"
        platform = "Cisco IOS"
        if "asa" in hostname_lower:
            device_type = "firewall"
            platform = "Cisco ASA"
        else:
            device_type = "switch"
    elif "palo-alto" in hostname_lower or "paloalto" in hostname_lower:
        vendor = "Palo Alto Networks"
        device_type = "firewall"
        platform = "PAN-OS"
    elif "vmware" in hostname_lower:
        vendor = "VMware"
        device_type = "host"
        platform = "VMware ESXi"
    elif "hp" in hostname_lower or "hewlett-packard" in hostname_lower:
        vendor = "HP"
        device_type = "switch"
        platform = "HP Networking"
    elif "arista" in hostname_lower:
        vendor = "Arista"
        device_type = "switch"
        platform = "Arista EOS"
    elif "juniper" in hostname_lower:
        vendor = "Juniper"
        device_type = "router"
        platform = "Junos"
    elif "fortinet" in hostname_lower:
        vendor = "Fortinet"
        device_type = "firewall"
        platform = "FortiOS"
    elif "dell" in hostname_lower:
        vendor = "Dell"
        device_type = "switch"
        platform = "Dell Networking"
    elif "extreme" in hostname_lower:
        vendor = "Extreme Networks"
        device_type = "switch"
        platform = "ExtremeXOS"
    elif "viptela" in hostname_lower:
        vendor = "Viptela"
        device_type = "router"
        platform = "Viptela SD-WAN"
    elif "intel" in hostname_lower or "advantech" in hostname_lower or "lcfc" in hostname_lower or "apc" in hostname_lower or "icann" in hostname_lower or "algo" in hostname_lower:
        # These are likely hosts/sensors
        vendor = hostname.split('-device-')[0].replace('-', ' ').title() if '-device-' in hostname else "Unknown"
        device_type = "host"
        platform = "Endpoint"
    
    # Device type inference from hostname patterns
    if device_type == "device":  # If not determined by vendor
        if "switch" in hostname_lower or "sw" in hostname_lower:
            device_type = "switch"
        elif "router" in hostname_lower or "rtr" in hostname_lower or "gate" in hostname_lower:
            device_type = "router"
        elif "firewall" in hostname_lower or "fw" in hostname_lower:
            device_type = "firewall"
        elif "core" in hostname_lower:
            device_type = "switch"
        elif "edge" in hostname_lower:
            device_type = "router"
    
    return {
        "vendor": vendor,
        "device_type": device_type,
        "platform": platform
    }


def execute(input_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate interactive HTML visualization of network topology.
    
    Creates a D3.js-based interactive topology map showing:
    - Network devices (routers, switches, firewalls)
    - Hosts (servers, endpoints, workstations)
    - Physical connections between devices
    - Interface details and IP addressing
    - Layer 3 connectivity
    
    Args:
        input_data: Dictionary containing network, snapshot, host, and optional output_path
        
    Returns:
        Dictionary with generation status and HTML file path
    """
    try:
        # Validate input
        validated_input = NetworkGenerateTopologyInput(**input_data)
        
        network = validated_input.network
        snapshot = validated_input.snapshot
        host = validated_input.host
        output_path = validated_input.output_path
        include_hosts = validated_input.include_hosts
        
        logger.info(f"Generating topology for network '{network}', snapshot '{snapshot}'")
        
        # Initialize Batfish session
        bf = Session(host=host)
        bf.set_network(network)
        bf.set_snapshot(snapshot)
        
        logger.info("Retrieving network topology data from Batfish")
        
        # Get Layer 1 edges (physical cabling)
        # Layer 1 shows actual physical connections (switch port to host)
        # Layer 3 edges show IP-based adjacency which can create false full-mesh
        logger.info("Querying layer1Edges for physical topology...")
        edges_df = bf.q.layer1Edges().answer().frame()
        logger.info(f"Retrieved {len(edges_df)} Layer-1 edges (physical connections)")
        
        # If no Layer-1 edges, fall back to layer3Edges
        if edges_df.empty:
            logger.warning("No Layer-1 edges found, falling back to layer3Edges...")
            edges_df = bf.q.layer3Edges().answer().frame()
            logger.info(f"Retrieved {len(edges_df)} Layer-3 edges")
        
        # Get interface properties
        interfaces_df = bf.q.interfaceProperties().answer().frame()
        logger.info(f"Retrieved {len(interfaces_df)} interfaces")
        
        # Get node properties
        nodes_df = bf.q.nodeProperties().answer().frame()
        logger.info(f"Retrieved {len(nodes_df)} nodes")
        
        # Build device map
        devices = {}
        interface_map = {}
        
        # Process nodes first
        for _, row in nodes_df.iterrows():
            node_name = str(row.get('Node', ''))
            config_format = str(row.get('Configuration_Format', 'unknown'))
            
            # Determine device type based on config format and name
            device_type = _determine_device_type(node_name, config_format)
            
            devices[node_name] = {
                "hostname": node_name,
                "ip_address": node_name,  # Will be updated with management IP if found
                "platform": config_format,
                "vendor": _extract_vendor(config_format, node_name),
                "device_type": device_type,
                "model": config_format,
                "interfaces": []
            }
        
        # Process interfaces
        for _, row in interfaces_df.iterrows():
            node = str(row.get('Node', ''))
            interface = str(row.get('Interface', ''))
            
            if node not in interface_map:
                interface_map[node] = {}
            
            # Extract IP address
            ip_address = None
            subnet_mask = None
            primary_addr = row.get('Primary_Address')
            
            if primary_addr and primary_addr != "AUTO/NONE(DYNAMIC)" and '/' in str(primary_addr):
                ip_parts = str(primary_addr).split('/')
                if len(ip_parts) == 2:
                    ip_address = ip_parts[0]
                    subnet_mask = ip_parts[1]
            
            interface_map[node][interface] = {
                "name": interface,
                "ip_address": ip_address,
                "subnet_mask": subnet_mask,
                "description": row.get('Description', None),
                "active": row.get('Active', False),
                "vlan": row.get('Access_VLAN', None),
                "vrf": row.get('VRF', 'default'),
                "switchport_mode": row.get('Switchport_Mode', None),
                "status": "up" if row.get('Active', False) else "down"
            }
        
        # Build connections list from edges (includes both device-to-device and device-to-host)
        connections = []
        seen_links = set()  # Track bidirectional links to avoid duplicates
        
        if not edges_df.empty:
            # Log the column names to debug
            logger.info(f"Edge DataFrame columns: {list(edges_df.columns)}")
            logger.info(f"First edge sample: {edges_df.iloc[0].to_dict() if len(edges_df) > 0 else 'No edges'}")
            
            # Determine column names (layer1Edges vs layer3Edges may have different names)
            interface_col = None
            remote_col = None
            
            if "Interface" in edges_df.columns and "Remote_Interface" in edges_df.columns:
                interface_col = "Interface"
                remote_col = "Remote_Interface"
            elif edges_df.shape[1] >= 2:
                # Use first two columns
                interface_col = edges_df.columns[0]
                remote_col = edges_df.columns[1]
                logger.info(f"Using columns: {interface_col}, {remote_col}")
            
            if interface_col and remote_col:
                for _, row in edges_df.iterrows():
                    # Extract source device and interface
                    source_interface = str(row[interface_col])
                    if "@" in source_interface:
                        source_device, source_intf = source_interface.split("@", 1)
                    else:
                        source_parts = source_interface.split("[")
                        source_device = source_parts[0]
                        source_intf = source_interface
                    
                    # Extract target device and interface
                    remote_interface = str(row[remote_col])
                    if "@" in remote_interface:
                        target_device, target_intf = remote_interface.split("@", 1)
                    else:
                        target_parts = remote_interface.split("[")
                        target_device = target_parts[0]
                        target_intf = remote_interface
                    
                    # Clean interface names
                    clean_source_intf = source_intf.split('[')[-1].replace(']', '') if '[' in source_intf else source_intf
                    clean_target_intf = target_intf.split('[')[-1].replace(']', '') if '[' in target_intf else target_intf
                    
                    # Create bidirectional link identifier to avoid duplicates
                    # Sort to ensure (A,B) and (B,A) create the same ID
                    link_id = tuple(sorted([
                        (source_device, clean_source_intf),
                        (target_device, clean_target_intf)
                    ]))
                    
                    # Skip if we've already processed this link
                    if link_id in seen_links:
                        continue
                    
                    seen_links.add(link_id)
                    
                    # If target_device is not in devices, it's a host - add it now
                    if target_device not in devices and include_hosts:
                        # Get interface info for the gateway interface
                        gateway_intf_info = interface_map.get(source_device, {}).get(clean_source_intf, {})
                        
                        devices[target_device] = {
                            "hostname": target_device,
                            "ip_address": gateway_intf_info.get("ip_address", "unknown"),
                            "platform": "HOST",
                            "vendor": "Unknown",
                            "device_type": "host",
                            "model": "endpoint",
                            "vlan": gateway_intf_info.get("vlan", "unknown"),
                            "interfaces": [{
                                "name": clean_target_intf,
                                "ip_address": None,
                                "status": "up",
                                "connected_to": f"{source_device}:{clean_source_intf}",
                                "vlan": gateway_intf_info.get("vlan")
                            }]
                        }
                        logger.debug(f"Added host {target_device} connected to {source_device}:{clean_source_intf}")
                    
                    # Add interface to source device (only if it's a network device)
                    if source_device in devices:
                        interface_obj = interface_map.get(source_device, {}).get(clean_source_intf, {
                            "name": clean_source_intf,
                            "ip_address": None,
                            "status": "up"
                        })
                        interface_obj["connected_to"] = f"{target_device}:{clean_target_intf}"
                        
                        # Check if interface already exists
                        if not any(i["name"] == clean_source_intf for i in devices[source_device]["interfaces"]):
                            devices[source_device]["interfaces"].append(interface_obj)
                    
                    # Add interface to target device (only if it's a network device, not a host we just added)
                    if target_device in devices and devices[target_device].get("device_type") != "host":
                        interface_obj = interface_map.get(target_device, {}).get(clean_target_intf, {
                            "name": clean_target_intf,
                            "ip_address": None,
                            "status": "up"
                        })
                        interface_obj["connected_to"] = f"{source_device}:{clean_source_intf}"
                        
                        # Check if interface already exists
                        if not any(i["name"] == clean_target_intf for i in devices[target_device]["interfaces"]):
                            devices[target_device]["interfaces"].append(interface_obj)
                    
                    # Add connection (only once per unique link)
                    connections.append({
                        "source": source_device,
                        "target": target_device,
                        "source_port": clean_source_intf,
                        "target_port": clean_target_intf
                    })
            else:
                logger.error(f"Could not identify interface columns in edges DataFrame")
        
        # Log summary
        host_count = sum(1 for d in devices.values() if d.get("device_type") == "host")
        logger.info(f"Processed {len(connections)} connections")
        logger.info(f"Found {len(devices)} total devices ({host_count} hosts, {len(devices) - host_count} network devices)")
        
        # Create topology data structure
        topology_data = {
            "devices": devices,
            "connections": connections,
            "metadata": {
                "network": network,
                "snapshot": snapshot,
                "generated_at": datetime.now().isoformat(),
                "device_count": len(devices),
                "connection_count": len(connections)
            }
        }
        
        # Generate HTML
        html_content = _generate_html_template(topology_data)
        
        # Write HTML file
        if output_path:
            html_file_path = output_path
        else:
            # Create temporary file
            temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False)
            html_file_path = temp_file.name
            temp_file.close()
        
        with open(html_file_path, 'w') as f:
            f.write(html_content)
        
        logger.info(f"Topology visualization written to: {html_file_path}")
        
        return {
            "ok": True,
            "network": network,
            "snapshot": snapshot,
            "html_path": html_file_path,
            "html_content": html_content,  # Return HTML content directly
            "html_size_bytes": len(html_content),
            "device_count": len(devices),
            "connection_count": len(connections),
            "message": f"Successfully generated topology visualization with {len(devices)} devices and {len(connections)} connections"
        }
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error generating topology: {error_msg}")
        import traceback
        logger.error(traceback.format_exc())
        return {
            "ok": False,
            "error": error_msg
        }


def _determine_device_type(node_name: str, config_format: str) -> str:
    """Determine device type from name and config format."""
    config_lower = config_format.lower()
    name_lower = node_name.lower()
    
    # Check config format first
    if "cisco_asa" in config_lower or "asa" in config_lower:
        return "firewall"
    elif "palo_alto" in config_lower or "panos" in config_lower:
        return "firewall"
    elif "juniper" in config_lower:
        if "srx" in name_lower:
            return "firewall"
        return "router"
    elif "arista" in config_lower:
        return "switch"
    elif "cisco_nxos" in config_lower:
        return "switch"
    elif "cisco_ios" in config_lower or "cisco_xe" in config_lower:
        if "switch" in name_lower:
            return "switch"
        return "router"
    
    # Fallback to name-based detection
    if "switch" in name_lower or "sw-" in name_lower:
        return "switch"
    elif "router" in name_lower or "rtr-" in name_lower or "core" in name_lower or "edge" in name_lower:
        return "router"
    elif "firewall" in name_lower or "fw-" in name_lower or "asa" in name_lower:
        return "firewall"
    
    return "device"


def _extract_vendor(config_format: str, hostname: str = "") -> str:
    """Extract vendor name from config format or hostname."""
    config_lower = config_format.lower()
    name_lower = hostname.lower()
    
    # Check config format first
    if "cisco" in config_lower:
        return "Cisco"
    elif "juniper" in config_lower:
        return "Juniper"
    elif "arista" in config_lower:
        return "Arista"
    elif "palo_alto" in config_lower or "panos" in config_lower:
        return "Palo Alto Networks"
    elif "fortinet" in config_lower:
        return "Fortinet"
    elif "hp" in config_lower or "hewlett" in config_lower:
        return "HP"
    elif "dell" in config_lower:
        return "Dell"
    
    # Check hostname if config format didn't match
    if "cisco" in name_lower:
        return "Cisco"
    elif "palo-alto" in name_lower or "paloalto" in name_lower:
        return "Palo Alto Networks"
    elif "vmware" in name_lower:
        return "VMware"
    elif "hp" in name_lower or "hewlett-packard" in name_lower:
        return "HP"
    elif "juniper" in name_lower:
        return "Juniper"
    elif "arista" in name_lower:
        return "Arista"
    elif "viptela" in name_lower:
        return "Viptela"
    elif "fortinet" in name_lower:
        return "Fortinet"
    elif "dell" in name_lower:
        return "Dell"
    elif "-device-" in name_lower:
        # Extract vendor from hostname pattern like "cisco-systems-inc-device-abc123"
        vendor_part = name_lower.split('-device-')[0]
        return vendor_part.replace('-', ' ').title()
    
    return "Unknown"


def _generate_html_template(topology_data: Dict) -> str:
    """Generate complete HTML template with D3.js visualization."""
    
    return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Network Topology - {topology_data['metadata']['network']}</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
        .header {{ background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        #topology {{ width: 100%; height: 800px; border: 1px solid #ddd; background-color: white; border-radius: 5px; }}
        .node {{ cursor: pointer; }}
        .link {{ stroke: #666; stroke-opacity: 0.6; stroke-width: 2px; }}
        .node text {{ 
            font-size: 12px; 
            font-weight: bold; 
            text-shadow: 0 0 3px white, 0 0 3px white, 0 0 3px white;
        }}
        .tooltip {{ 
            position: absolute; 
            background: white; 
            border: 1px solid #ddd; 
            border-radius: 8px; 
            padding: 15px; 
            pointer-events: none;
            box-shadow: 0 4px 8px rgba(0,0,0,0.2);
            max-width: 500px;
            font-size: 12px;
            z-index: 1000;
        }}
        .tooltip h3 {{
            margin-top: 0;
            color: #2c3e50;
            border-bottom: 1px solid #eee;
            padding-bottom: 8px;
        }}
        .legend {{
            position: absolute;
            top: 20px;
            right: 20px;
            background: white;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 15px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.2);
        }}
        .legend-item {{
            display: flex;
            align-items: center;
            margin-bottom: 8px;
        }}
        .legend-color {{
            width: 20px;
            height: 20px;
            border-radius: 50%;
            margin-right: 10px;
        }}
        .controls {{
            margin: 20px 0;
            padding: 15px;
            background: #f8f9fa;
            border: 1px solid #ddd;
            border-radius: 4px;
        }}
        button {{
            padding: 8px 16px;
            background: #007bff;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            margin-right: 10px;
        }}
        button:hover {{
            background: #0056b3;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Network Topology Visualization</h1>
        <p><strong>Network:</strong> {topology_data['metadata']['network']} | 
           <strong>Snapshot:</strong> {topology_data['metadata']['snapshot']} | 
           <strong>Devices:</strong> {topology_data['metadata']['device_count']} | 
           <strong>Connections:</strong> {topology_data['metadata']['connection_count']}</p>
    </div>
    
    <div class="controls">
        <label><input type="checkbox" id="fix-nodes" checked> Fix Node Positions</label>
        <button id="unfix-all">Unfix All Nodes</button>
        <button id="reset-layout">Reset Layout</button>
        <button id="export-data">Export Topology Data</button>
    </div>
    
    <div id="topology"></div>
    
    <div class="legend">
        <h3>Device Types</h3>
        <div class="legend-item">
            <div class="legend-color" style="background-color: #4CAF50;"></div>
            <div>Router</div>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background-color: #2196F3;"></div>
            <div>Switch</div>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background-color: #FF9800;"></div>
            <div>Firewall</div>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background-color: #9C27B0;"></div>
            <div>Host</div>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background-color: #757575;"></div>
            <div>Unknown</div>
        </div>
    </div>
    
    <script>
        const data = {json.dumps(topology_data, cls=DateTimeEncoder)};
        
        // Create nodes and links for D3
        const nodes = [];
        const links = [];
        
        // Device type colors
        const colors = {{
            'router': '#4CAF50',
            'switch': '#2196F3',
            'firewall': '#FF9800',
            'host': '#9C27B0',
            'device': '#757575'
        }};
        
        // Add nodes
        for (const [id, device] of Object.entries(data.devices)) {{
            nodes.push({{
                id: id,
                hostname: device.hostname || id,
                ip: device.ip_address || id,
                platform: device.platform || 'unknown',
                vendor: device.vendor || 'unknown',
                device_type: device.device_type || 'device',
                vlan: device.vlan || 'unknown',
                interfaces: device.interfaces || []
            }});
        }}
        
        // Add links
        for (const conn of (data.connections || [])) {{
            if (conn.source && conn.target) {{
                links.push({{
                    source: conn.source,
                    target: conn.target,
                    sourcePort: conn.source_port || '',
                    targetPort: conn.target_port || ''
                }});
            }}
        }}
        
        // Create D3 force simulation
        const width = window.innerWidth - 40;
        const height = 800;
        
        // Organize nodes by device type for better layout
        const devicesByType = {{
            'router': [],
            'switch': [],
            'firewall': [],
            'host': [],
            'device': []
        }};
        
        nodes.forEach(node => {{
            const type = node.device_type || 'device';
            if (devicesByType[type]) {{
                devicesByType[type].push(node);
            }} else {{
                devicesByType['device'].push(node);
            }}
        }});
        
        // Set initial positions based on device type (organized layout)
        const rowHeight = 200;
        const colWidth = 300;
        let yOffset = 100;
        
        // Position firewalls at top
        devicesByType['firewall'].forEach((node, i) => {{
            node.x = width / 2 + (i - devicesByType['firewall'].length / 2) * colWidth;
            node.y = yOffset;
            node.fx = node.x;  // Fix position initially
            node.fy = node.y;
        }});
        yOffset += rowHeight;
        
        // Position routers
        devicesByType['router'].forEach((node, i) => {{
            node.x = width / 2 + (i - devicesByType['router'].length / 2) * colWidth;
            node.y = yOffset;
            node.fx = node.x;
            node.fy = node.y;
        }});
        yOffset += rowHeight;
        
        // Position switches
        devicesByType['switch'].forEach((node, i) => {{
            node.x = width / 2 + (i - devicesByType['switch'].length / 2) * colWidth;
            node.y = yOffset;
            node.fx = node.x;
            node.fy = node.y;
        }});
        yOffset += rowHeight;
        
        // Position hosts at bottom (spread out more)
        const hostsPerRow = Math.ceil(Math.sqrt(devicesByType['host'].length));
        devicesByType['host'].forEach((node, i) => {{
            const row = Math.floor(i / hostsPerRow);
            const col = i % hostsPerRow;
            node.x = 100 + col * 150;
            node.y = yOffset + row * 100;
            node.fx = node.x;
            node.fy = node.y;
        }});
        
        const simulation = d3.forceSimulation(nodes)
            .force("link", d3.forceLink(links).id(d => d.id).distance(150))
            .force("charge", d3.forceManyBody().strength(-300))
            .force("collide", d3.forceCollide().radius(60))
            .alphaDecay(0.01)
            .alpha(0.3);  // Start with lower energy since we have fixed positions
        
        const svg = d3.select("#topology")
            .append("svg")
            .attr("width", "100%")
            .attr("height", height)
            .attr("viewBox", [0, 0, width, height]);
        
        const g = svg.append("g");
        
        // Add zoom
        svg.call(d3.zoom()
            .extent([[0, 0], [width, height]])
            .scaleExtent([0.1, 8])
            .on("zoom", (event) => {{
                g.attr("transform", event.transform);
            }}));
        
        // Create links
        const link = g.append("g")
            .selectAll("line")
            .data(links)
            .enter()
            .append("line")
            .attr("class", "link");
        
        // Create link labels
        const linkText = g.append("g")
            .selectAll("text")
            .data(links)
            .enter()
            .append("text")
            .attr("font-size", "10px")
            .attr("text-anchor", "middle")
            .attr("dy", -5)
            .text(d => `${{d.sourcePort}} - ${{d.targetPort}}`);
        
        // Create nodes
        const node = g.append("g")
            .selectAll("g")
            .data(nodes)
            .enter()
            .append("g")
            .attr("class", "node")
            .call(d3.drag()
                .on("start", dragstarted)
                .on("drag", dragged)
                .on("end", dragended));
        
        // Node circles
        node.append("circle")
            .attr("r", 30)
            .attr("fill", d => colors[d.device_type] || colors['device'])
            .attr("stroke", "#333")
            .attr("stroke-width", 2);
        
        // Node labels
        node.append("text")
            .attr("dy", 50)
            .attr("text-anchor", "middle")
            .text(d => d.hostname);
        
        // Tooltip
        const tooltip = d3.select("body")
            .append("div")
            .attr("class", "tooltip")
            .style("opacity", 0);
        
        node.on("mouseover", function(event, d) {{
            tooltip.transition().duration(200).style("opacity", .9);
            
            let interfaceList = '';
            if (d.interfaces && d.interfaces.length > 0) {{
                interfaceList = '<h4>Interfaces:</h4><ul>';
                d.interfaces.forEach(intf => {{
                    const vlanInfo = intf.vlan && intf.vlan !== 'unknown' ? ` (VLAN ${{intf.vlan}})` : '';
                    interfaceList += `<li><strong>${{intf.name}}</strong>${{intf.ip_address ? ' - ' + intf.ip_address : ''}}${{vlanInfo}}</li>`;
                }});
                interfaceList += '</ul>';
            }}
            
            // Add VLAN if device has it
            const vlanInfo = d.vlan && d.vlan !== 'unknown' ? `<p><strong>VLAN:</strong> ${{d.vlan}}</p>` : '';
            
            tooltip.html(`
                <h3>${{d.hostname}}</h3>
                <p><strong>IP:</strong> ${{d.ip}}</p>
                <p><strong>Platform:</strong> ${{d.platform}}</p>
                <p><strong>Vendor:</strong> ${{d.vendor}}</p>
                <p><strong>Type:</strong> ${{d.device_type}}</p>
                ${{vlanInfo}}
                ${{interfaceList}}
            `)
            .style("left", (event.pageX + 10) + "px")
            .style("top", (event.pageY - 28) + "px");
        }})
        .on("mouseout", function() {{
            tooltip.transition().duration(500).style("opacity", 0);
        }});
        
        // Update positions
        simulation.on("tick", () => {{
            link
                .attr("x1", d => d.source.x)
                .attr("y1", d => d.source.y)
                .attr("x2", d => d.target.x)
                .attr("y2", d => d.target.y);
            
            linkText
                .attr("x", d => (d.source.x + d.target.x) / 2)
                .attr("y", d => (d.source.y + d.target.y) / 2);
            
            node.attr("transform", d => `translate(${{d.x}},${{d.y}})`);
        }});
        
        // Node fixing state - start with nodes fixed
        let nodesFixed = true;
        
        d3.select("#fix-nodes").on("change", function() {{
            nodesFixed = this.checked;
            nodes.forEach(node => {{
                if (nodesFixed) {{
                    node.fx = node.x;
                    node.fy = node.y;
                }} else {{
                    node.fx = null;
                    node.fy = null;
                }}
            }});
            if (!nodesFixed) simulation.alpha(0.3).restart();
        }});
        
        d3.select("#unfix-all").on("click", function() {{
            nodes.forEach(node => {{
                node.fx = null;
                node.fy = null;
            }});
            d3.select("#fix-nodes").property("checked", false);
            nodesFixed = false;
            simulation.alpha(0.3).restart();
        }});
        
        d3.select("#reset-layout").on("click", function() {{
            // Reset to organized layout
            location.reload();
        }});
        
        d3.select("#export-data").on("click", function() {{
            const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(data, null, 2));
            const downloadNode = document.createElement('a');
            downloadNode.setAttribute("href", dataStr);
            downloadNode.setAttribute("download", "topology.json");
            document.body.appendChild(downloadNode);
            downloadNode.click();
            downloadNode.remove();
        }});
        
        function dragstarted(event, d) {{
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }}
        
        function dragged(event, d) {{
            d.fx = event.x;
            d.fy = event.y;
        }}
        
        function dragended(event, d) {{
            if (!event.active) simulation.alphaTarget(0);
            if (!nodesFixed) {{
                d.fx = null;
                d.fy = null;
            }}
        }}
    </script>
</body>
</html>
"""

