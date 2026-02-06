"""
Network Get Allowed Services Tool

Discovers what protocols/services are allowed between network segments based on ACL rules.
Critical for validating segmentation policies (e.g., "OT zones should only allow industrial protocols").

Analyzes ACL rules to determine which protocols can flow between zones/VLANs.
"""

import logging
from typing import Dict, Any, List, Set
from collections import defaultdict
from pydantic import BaseModel, Field
from pybatfish.client.session import Session
import numpy as np

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


class NetworkGetAllowedServicesInput(BaseModel):
    """Input model for allowed services discovery."""
    network: str = Field(..., description="Batfish network name")
    snapshot: str = Field(..., description="Batfish snapshot name")
    host: str = Field("localhost", description="Batfish host to connect to")


def convert_to_native_types(obj):
    """Convert numpy types to native Python types for JSON serialization."""
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


def parse_protocol_info(row) -> Dict[str, Any]:
    """
    Extract protocol information from a filter line row.
    
    Returns protocol type, ports, and other relevant info.
    """
    protocol_info = {
        "protocol": "ip",
        "src_ports": None,
        "dst_ports": None,
        "icmp_type": None,
        "src": "any",
        "dst": "any"
    }
    
    # Try to get protocol
    ip_protocol = row.get('IpProtocol')
    if ip_protocol and str(ip_protocol) != 'nan':
        protocol_info["protocol"] = str(ip_protocol).lower()
    
    # Get source ports
    src_ports = row.get('Src_Ports')
    if src_ports and str(src_ports) != 'nan':
        protocol_info["src_ports"] = str(src_ports)
    
    # Get destination ports
    dst_ports = row.get('Dst_Ports')
    if dst_ports and str(dst_ports) != 'nan':
        protocol_info["dst_ports"] = str(dst_ports)
    
    # Get ICMP type if applicable
    icmp_code = row.get('Icmp_Code')
    if icmp_code and str(icmp_code) != 'nan':
        protocol_info["icmp_type"] = str(icmp_code)
    
    return protocol_info


def parse_acl_line_text(line_text: str) -> Dict[str, Any]:
    """
    Parse ACL line text to extract protocol, src, dst, ports.
    
    Examples:
        "permit udp any eq 2222 any dscp 55"
        "permit ip 10.42.88.192 0.0.0.31 10.45.192.224 0.0.0.31"
        "deny   ip any any"
    """
    import re
    
    protocol_info = {
        "protocol": "ip",
        "src": "any",
        "dst": "any",
        "src_ports": None,
        "dst_ports": None
    }
    
    parts = line_text.split()
    if len(parts) < 3:
        return protocol_info
    
    # First part is action (permit/deny) - skip it
    # Second part is protocol
    if len(parts) >= 2:
        protocol_info["protocol"] = parts[1].lower()
    
    # For IP/TCP/UDP, try to parse src/dst
    # Format: protocol src [src_port] dst [dst_port]
    if len(parts) >= 4:
        # Find "any" or IP addresses
        idx = 2
        
        # Source
        if parts[idx] == "any":
            protocol_info["src"] = "any"
            idx += 1
        elif parts[idx] == "host":
            protocol_info["src"] = parts[idx + 1]
            idx += 2
        elif re.match(r'\d+\.\d+\.\d+\.\d+', parts[idx]):
            # IP address possibly with wildcard mask
            if idx + 1 < len(parts) and re.match(r'\d+\.\d+\.\d+\.\d+', parts[idx + 1]):
                protocol_info["src"] = f"{parts[idx]}/{parts[idx + 1]}"
                idx += 2
            else:
                protocol_info["src"] = parts[idx]
                idx += 1
        
        # Source port (eq, range, etc.)
        if idx < len(parts) and parts[idx] in ["eq", "gt", "lt", "range"]:
            if parts[idx] == "eq" and idx + 1 < len(parts):
                protocol_info["src_ports"] = parts[idx + 1]
                idx += 2
            elif parts[idx] == "range" and idx + 2 < len(parts):
                protocol_info["src_ports"] = f"{parts[idx + 1]}-{parts[idx + 2]}"
                idx += 3
            else:
                idx += 1
        
        # Destination
        if idx < len(parts):
            if parts[idx] == "any":
                protocol_info["dst"] = "any"
                idx += 1
            elif parts[idx] == "host" and idx + 1 < len(parts):
                protocol_info["dst"] = parts[idx + 1]
                idx += 2
            elif re.match(r'\d+\.\d+\.\d+\.\d+', parts[idx]):
                if idx + 1 < len(parts) and re.match(r'\d+\.\d+\.\d+\.\d+', parts[idx + 1]):
                    protocol_info["dst"] = f"{parts[idx]}/{parts[idx + 1]}"
                    idx += 2
                else:
                    protocol_info["dst"] = parts[idx]
                    idx += 1
        
        # Destination port
        if idx < len(parts) and parts[idx] in ["eq", "gt", "lt", "range"]:
            if parts[idx] == "eq" and idx + 1 < len(parts):
                protocol_info["dst_ports"] = parts[idx + 1]
            elif parts[idx] == "range" and idx + 2 < len(parts):
                protocol_info["dst_ports"] = f"{parts[idx + 1]}-{parts[idx + 2]}"
    
    return protocol_info


def format_service_name(protocol_info: Dict[str, Any]) -> str:
    """
    Format a human-readable service name from protocol info.
    
    Examples:
        tcp/502 -> "Modbus TCP"
        tcp/80 -> "HTTP"
        tcp/443 -> "HTTPS"
    """
    protocol = protocol_info.get("protocol", "ip")
    dst_ports = protocol_info.get("dst_ports")
    
    if not dst_ports or dst_ports == "any":
        return protocol.upper()
    
    # Common service mappings
    service_map = {
        "tcp/20": "FTP-Data",
        "tcp/21": "FTP",
        "tcp/22": "SSH",
        "tcp/23": "Telnet",
        "tcp/25": "SMTP",
        "tcp/53": "DNS",
        "tcp/80": "HTTP",
        "tcp/443": "HTTPS",
        "tcp/502": "Modbus-TCP",
        "tcp/2404": "IEC-104",
        "tcp/20000": "DNP3",
        "tcp/3389": "RDP",
        "udp/53": "DNS",
        "udp/67": "DHCP-Server",
        "udp/68": "DHCP-Client",
        "udp/123": "NTP",
        "udp/161": "SNMP",
        "udp/162": "SNMP-Trap",
    }
    
    # Try to format as protocol/port
    if "/" not in dst_ports:
        key = f"{protocol}/{dst_ports}"
    else:
        key = f"{protocol}/{dst_ports}"
    
    return service_map.get(key, key.upper())


def execute(input_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Discover allowed protocols/services between network segments.
    
    For each enforcement point (device with ACLs), analyzes ACL rules to determine:
    - Which source → destination flows are permitted
    - Which protocols/ports are allowed
    - Which protocols/ports are explicitly denied
    - Default policy (permit/deny)
    
    Output is organized by zone-to-zone communication paths for policy validation.
    
    Args:
        input_data: Dictionary containing network, snapshot, and host
        
    Returns:
        Dictionary with:
        - ok: Success status
        - zone_communications: List of inter-zone allowed services
        - acl_details: Detailed ACL rule breakdown
        - summary: Statistics about service filtering
    """
    try:
        # Validate input
        validated_input = NetworkGetAllowedServicesInput(**input_data)
        
        network = validated_input.network
        snapshot = validated_input.snapshot
        host = validated_input.host
        
        logger.info(f"Discovering allowed services for '{network}', snapshot '{snapshot}'")
        
        # Initialize Batfish session
        bf = Session(host=host)
        bf.set_network(network)
        bf.set_snapshot(snapshot)
        
        logger.info(f"Connected to Batfish host: {host}")
        
        # Step 1: Get interface properties to find ACLs
        logger.info("Step 1: Retrieving interface properties to find ACLs...")
        interfaces_df, error = safe_batfish_query(
            bf,
            "interfaceProperties query",
            lambda: bf.q.interfaceProperties(),
            timeout=30
        )
        
        if error or interfaces_df is None or interfaces_df.empty:
            logger.warning(f"No interface properties found: {error}")
            return {
                "ok": True,
                "zone_communications": [],
                "acl_details": {},
                "summary": {
                    "total_acls": 0,
                    "enforcement_points": 0,
                    "services_allowed": 0,
                    "services_denied": 0
                },
                "message": "No interface data found in snapshot."
            }
        
        logger.info(f"Retrieved {len(interfaces_df)} interface records")
        
        # Build mapping of interfaces to ACLs and their VLANs/subnets
        interface_acl_map = {}
        
        for _, row in interfaces_df.iterrows():
            interface_obj = row.get('Interface')
            if not interface_obj:
                continue
            
            node = interface_obj.hostname if hasattr(interface_obj, 'hostname') else str(interface_obj).split('[')[0]
            interface_name = interface_obj.interface if hasattr(interface_obj, 'interface') else str(interface_obj).split('[')[-1].rstrip(']')
            
            # Try both old and new Batfish column names for ACL filters
            inbound_filter = row.get('Incoming_Filter_Name') or row.get('Inbound_Filter')
            outbound_filter = row.get('Outgoing_Filter_Name') or row.get('Outbound_Filter')
            vrf = row.get('VRF', 'default')
            
            # Get VLAN from interface name if possible
            import re
            vlan_match = re.search(r'[Vv]lan(\d+)', interface_name)
            vlan = f"Vlan{vlan_match.group(1)}" if vlan_match else interface_name
            
            key = f"{node}[{interface_name}]"
            
            interface_acl_map[key] = {
                "node": node,
                "interface": interface_name,
                "vlan": vlan,
                "vrf": str(vrf) if vrf and str(vrf) != 'nan' else 'default',
                "inbound_filter": str(inbound_filter) if inbound_filter and str(inbound_filter) != 'nan' else None,
                "outbound_filter": str(outbound_filter) if outbound_filter and str(outbound_filter) != 'nan' else None
            }
        
        # Step 2: Get ALL ACLs using findMatchingFilterLines (gets all ACL rules)
        logger.info("Step 2: Retrieving ALL ACL rules using findMatchingFilterLines...")
        filter_lines_df, error = safe_batfish_query(
            bf,
            "findMatchingFilterLines query",
            lambda: bf.q.findMatchingFilterLines(filters="/.*/"),
            timeout=45
        )
        
        if error or filter_lines_df is None or filter_lines_df.empty:
            logger.warning(f"No ACL rules found: {error}")
            return {
                "ok": True,
                "zone_communications": [],
                "acl_details": {},
                "summary": {
                    "total_acls": 0,
                    "enforcement_points": 0,
                    "services_allowed": 0,
                    "services_denied": 0
                },
                "message": f"No ACL data found in snapshot."
            }
        
        logger.info(f"Retrieved {len(filter_lines_df)} ACL rule records")
        
        # Collect all unique ACLs from findMatchingFilterLines
        all_acls = set()
        for _, row in filter_lines_df.iterrows():
            filter_name = str(row.get('Filter', ''))
            if filter_name and filter_name != 'nan':
                all_acls.add(filter_name)
        
        if not all_acls:
            logger.warning("No ACLs found in filter line data")
            return {
                "ok": True,
                "zone_communications": [],
                "acl_details": {},
                "summary": {
                    "total_acls": 0,
                    "enforcement_points": 0,
                    "services_allowed": 0,
                    "services_denied": 0
                },
                "message": "No ACLs configured in the network. Network is flat."
            }
        
        logger.info(f"Found {len(all_acls)} unique ACL(s)")
        
        # Step 3: Parse ACL rules
        acl_details = defaultdict(lambda: {
            "name": "",
            "applied_on": [],
            "rules": [],
            "permit_count": 0,
            "deny_count": 0
        })
        
        services_allowed = set()
        services_denied = set()
        
        for _, row in filter_lines_df.iterrows():
            filter_name = str(row.get('Filter', ''))
            node = str(row.get('Node', ''))
            line_text = str(row.get('Line', ''))
            line_num = row.get('Line_Index', 0)
            action = str(row.get('Action', 'unknown'))
            
            if filter_name not in all_acls:
                continue
            
            # Parse the ACL line text to extract protocol info
            protocol_info = parse_acl_line_text(line_text)
            service_name = format_service_name(protocol_info)
            
            # Get source and destination from parsed text
            src = protocol_info.get("src", "any")
            dst = protocol_info.get("dst", "any")
            
            rule_entry = {
                "line": int(line_num) if isinstance(line_num, (int, np.integer)) else line_num,
                "action": action.lower(),
                "src": src,
                "dst": dst,
                "protocol": protocol_info["protocol"],
                "service": service_name
            }
            
            if protocol_info["dst_ports"]:
                rule_entry["dst_ports"] = protocol_info["dst_ports"]
            
            acl_details[filter_name]["name"] = filter_name
            acl_details[filter_name]["rules"].append(rule_entry)
            
            if 'permit' in action.lower():
                acl_details[filter_name]["permit_count"] += 1
                services_allowed.add(service_name)
            elif 'deny' in action.lower():
                acl_details[filter_name]["deny_count"] += 1
                services_denied.add(service_name)
        
        # Step 4: Map ACLs to interfaces (for those that are interface-applied)
        for key, info in interface_acl_map.items():
            if info["inbound_filter"] and info["inbound_filter"] in acl_details:
                acl_details[info["inbound_filter"]]["applied_on"].append({
                    "device": info["node"],
                    "interface": info["interface"],
                    "vlan": info["vlan"],
                    "direction": "inbound"
                })
            
            if info["outbound_filter"] and info["outbound_filter"] in acl_details:
                acl_details[info["outbound_filter"]]["applied_on"].append({
                    "device": info["node"],
                    "interface": info["interface"],
                    "vlan": info["vlan"],
                    "direction": "outbound"
                })
        
        # For ACLs not applied to interfaces, mark them as "defined but not interface-applied"
        for acl_name in acl_details.keys():
            if not acl_details[acl_name]["applied_on"]:
                acl_details[acl_name]["applied_on"].append({
                    "device": "N/A",
                    "interface": "N/A",
                    "vlan": "N/A",
                    "direction": "not_interface_applied",
                    "note": "ACL defined but may be used for VTY, QoS, or other non-interface purposes"
                })
        
        # Step 5: Build zone communications (interface-to-interface flow summary)
        zone_communications = []
        
        for acl_name, details in acl_details.items():
            for application in details["applied_on"]:
                # Group rules by service
                services_permitted = defaultdict(list)
                services_blocked = defaultdict(list)
                
                for rule in details["rules"]:
                    service = rule["service"]
                    if 'permit' in rule["action"]:
                        services_permitted[service].append({
                            "src": rule["src"],
                            "dst": rule["dst"]
                        })
                    elif 'deny' in rule["action"]:
                        services_blocked[service].append({
                            "src": rule["src"],
                            "dst": rule["dst"]
                        })
                
                # Build communication entry
                comm_entry = {
                    "acl_name": acl_name,
                    "services_permitted": [
                        {"service": svc, "flows": flows}
                        for svc, flows in sorted(services_permitted.items())
                    ],
                    "services_blocked": [
                        {"service": svc, "flows": flows}
                        for svc, flows in sorted(services_blocked.items())
                    ],
                    "total_permit_rules": details["permit_count"],
                    "total_deny_rules": details["deny_count"]
                }
                
                # Add location info if available
                if application.get("direction") != "not_interface_applied":
                    comm_entry["enforcement_point"] = f"{application['device']}[{application['interface']}]"
                    comm_entry["vlan"] = application["vlan"]
                    comm_entry["direction"] = application["direction"]
                else:
                    comm_entry["enforcement_point"] = "Not applied to interface"
                    comm_entry["note"] = application.get("note", "")
                
                zone_communications.append(comm_entry)
        
        # Build summary
        summary = {
            "total_acls": len(acl_details),
            "enforcement_points": len(zone_communications),
            "unique_services_allowed": len(services_allowed),
            "unique_services_denied": len(services_denied),
            "services_allowed_list": sorted(list(services_allowed)),
            "services_denied_list": sorted(list(services_denied))
        }
        
        summary_text = (
            f"Found {len(acl_details)} ACL(s) on {len(zone_communications)} enforcement point(s). "
            f"{len(services_allowed)} unique service(s) permitted, "
            f"{len(services_denied)} service(s) explicitly denied."
        )
        
        logger.info(summary_text)
        
        result = {
            "ok": True,
            "zone_communications": zone_communications,
            "acl_details": dict(acl_details),
            "summary": summary,
            "summary_text": summary_text
        }
        
        return convert_to_native_types(result)
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error discovering allowed services: {error_msg}")
        import traceback
        logger.error(traceback.format_exc())
        return {
            "ok": False,
            "error": error_msg,
            "zone_communications": []
        }

