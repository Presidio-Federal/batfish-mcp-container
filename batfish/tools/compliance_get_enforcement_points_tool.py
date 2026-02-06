"""
Network Enforcement Points Tool

Identifies all enforcement points in a network - devices/interfaces that perform (or should perform)
inter-segment security control.

An enforcement point is:
- Any L3 interface (SVI/routed port) on a device with multiple subnets
- Where ACLs can be (or are) applied to control inter-segment traffic

This tool reveals WHERE security controls should be applied, not WHAT the controls should be.
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


class NetworkEnforcementPointsInput(BaseModel):
    """Input model for enforcement points discovery."""
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


def execute(input_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Identify all enforcement points in the network.
    
    An enforcement point is any device with multiple L3 interfaces (routing between segments).
    For each enforcement point, shows:
    - Which interfaces are routing between subnets
    - Which subnets each interface owns
    - Whether ACLs are applied (inbound/outbound)
    - ACL rules summary
    - Whether the interface has enforcement (has_enforcement flag)
    
    Args:
        input_data: Dictionary containing network, snapshot, and host
        
    Returns:
        Dictionary with:
        - ok: Success status
        - enforcement_points: List of enforcement point details
        - summary: Statistics and gap analysis
        - network_is_flat: True if no ACLs exist anywhere
    """
    try:
        # Validate input
        validated_input = NetworkEnforcementPointsInput(**input_data)
        
        network = validated_input.network
        snapshot = validated_input.snapshot
        host = validated_input.host
        
        logger.info(f"Identifying enforcement points for '{network}', snapshot '{snapshot}'")
        
        # Initialize Batfish session
        bf = Session(host=host)
        bf.set_network(network)
        bf.set_snapshot(snapshot)
        
        logger.info(f"Connected to Batfish host: {host}")
        
        # Step 1: Get IP ownership to find L3 interfaces
        logger.info("Step 1: Retrieving IP ownership data...")
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
                "enforcement_points": [],
                "summary": {
                    "total_enforcement_points": 0,
                    "devices_with_zero_acls": 0,
                    "interfaces_with_filtering": 0,
                    "interfaces_without_filtering": 0
                },
                "network_is_flat": True,
                "message": "No IP ownership data found in snapshot."
            }
        
        logger.info(f"Found {len(owners_df)} IP ownership records")
        
        # Build device -> interfaces mapping
        # Use lowercase for device names to handle case inconsistencies
        device_interfaces = defaultdict(lambda: defaultdict(set))
        device_name_map = {}  # lowercase -> original casing
        
        for _, row in owners_df.iterrows():
            node = str(row.get('Node', ''))
            interface = str(row.get('Interface', ''))
            ip = str(row.get('IP', ''))
            mask = str(row.get('Mask', ''))
            
            if not node or node == 'nan' or not ip or ip == 'nan':
                continue
            
            # Store original casing
            node_lower = node.lower()
            if node_lower not in device_name_map:
                device_name_map[node_lower] = node
            
            # Create CIDR notation
            if mask and mask != 'nan' and '/' not in ip:
                subnet = f"{ip}/{mask}"
            elif '/' in ip:
                subnet = ip
            else:
                subnet = ip
            
            device_interfaces[node_lower][interface].add(subnet)
        
        # Filter to devices with multiple L3 interfaces (enforcement points)
        enforcement_devices = {
            device: interfaces 
            for device, interfaces in device_interfaces.items() 
            if len(interfaces) >= 2
        }
        
        if not enforcement_devices:
            logger.warning("No enforcement points found (no devices with multiple L3 interfaces)")
            return {
                "ok": True,
                "enforcement_points": [],
                "summary": {
                    "total_enforcement_points": 0,
                    "devices_with_zero_acls": 0,
                    "interfaces_with_filtering": 0,
                    "interfaces_without_filtering": 0
                },
                "network_is_flat": True,
                "message": "No enforcement points found. All devices have only single L3 interfaces."
            }
        
        logger.info(f"Found {len(enforcement_devices)} potential enforcement point(s)")
        
        # Step 2: Get interface properties to check for ACLs
        logger.info("Step 2: Retrieving interface properties to check for ACLs...")
        interfaces_df, error = safe_batfish_query(
            bf,
            "interfaceProperties query",
            lambda: bf.q.interfaceProperties(),
            timeout=30
        )
        
        if error or interfaces_df is None or interfaces_df.empty:
            logger.warning(f"No interface properties found: {error}")
            # Return enforcement points without ACL info
            result = build_result_without_acls(enforcement_devices)
            return convert_to_native_types(result)
        
        logger.info(f"Retrieved {len(interfaces_df)} interface property records")
        
        # Get ALL ACLs in the network first
        logger.info("Step 2a: Discovering ALL ACLs in network...")
        all_network_acls_df, error = safe_batfish_query(
            bf,
            "findMatchingFilterLines query for all ACLs",
            lambda: bf.q.findMatchingFilterLines(filters="/.*/"),
            timeout=45
        )
        
        all_network_acls = set()
        acl_to_node_map = {}  # ACL name -> list of nodes
        
        if all_network_acls_df is not None and not all_network_acls_df.empty:
            all_network_acls = set(all_network_acls_df['Filter'].unique())
            logger.info(f"Found {len(all_network_acls)} total ACL(s) in network")
            
            # Build map of which node each ACL belongs to
            for _, row in all_network_acls_df.iterrows():
                acl_name = str(row.get('Filter', ''))
                node = str(row.get('Node', ''))
                if acl_name and node:
                    if acl_name not in acl_to_node_map:
                        acl_to_node_map[acl_name] = []
                    if node not in acl_to_node_map[acl_name]:
                        acl_to_node_map[acl_name].append(node)
        
        # Now use searchFilters to find WHERE each ACL is applied
        logger.info("Step 2b: Using searchFilters to find ACL application locations...")
        interface_acls = {}  # Key: "node[interface]" -> {inbound: ACL, outbound: ACL}
        acls_found_on_interfaces = set()
        
        for acl_name in all_network_acls:
            try:
                logger.debug(f"  Searching for ACL '{acl_name}' application...")
                search_df, error = safe_batfish_query(
                    bf,
                    f"searchFilters for {acl_name}",
                    lambda acl=acl_name: bf.q.searchFilters(filters=acl),
                    timeout=10
                )
                
                if error or search_df is None or search_df.empty:
                    continue
                
                # searchFilters returns where the ACL is used
                for _, row in search_df.iterrows():
                    node = str(row.get('Node', ''))
                    if node:
                        logger.info(f"  → ACL '{acl_name}' is referenced on device '{node}'")
                        acls_found_on_interfaces.add(acl_name)
                        
            except Exception as e:
                logger.debug(f"Error searching for ACL '{acl_name}': {e}")
                continue
        
        # ALSO check interfaceProperties as a fallback
        logger.info("Step 2c: Also checking interfaceProperties for ACL applications...")
        logger.info(f"interfaceProperties columns available: {list(interfaces_df.columns)}")
        
        # Count how many interfaces have ACL info
        acl_found_count = 0
        for _, row in interfaces_df.iterrows():
            interface_obj = row.get('Interface')
            if not interface_obj:
                continue
            
            node = interface_obj.hostname if hasattr(interface_obj, 'hostname') else str(interface_obj).split('[')[0]
            node_lower = node.lower()
            interface_name = interface_obj.interface if hasattr(interface_obj, 'interface') else str(interface_obj).split('[')[-1].rstrip(']')
            
            # Try both old and new Batfish column names
            inbound_filter = row.get('Incoming_Filter_Name') or row.get('Inbound_Filter')
            outbound_filter = row.get('Outgoing_Filter_Name') or row.get('Outbound_Filter')
            
            # Debug: log if we find any ACL info
            if (inbound_filter and str(inbound_filter) != 'nan') or (outbound_filter and str(outbound_filter) != 'nan'):
                acl_found_count += 1
                logger.debug(f"Found ACL on {node}[{interface_name}]: inbound={inbound_filter}, outbound={outbound_filter}")
            
            key = f"{node_lower}[{interface_name}]"
            
            # Store ACL info if present
            if (inbound_filter and str(inbound_filter) != 'nan') or (outbound_filter and str(outbound_filter) != 'nan'):
                interface_acls[key] = {
                    "inbound": str(inbound_filter).strip() if inbound_filter and str(inbound_filter) != 'nan' else None,
                    "outbound": str(outbound_filter).strip() if outbound_filter and str(outbound_filter) != 'nan' else None
                }
                
                if inbound_filter and str(inbound_filter) != 'nan':
                    acls_found_on_interfaces.add(str(inbound_filter))
                    logger.info(f"  → ACL '{inbound_filter}' applied inbound on {node}[{interface_name}]")
                if outbound_filter and str(outbound_filter) != 'nan':
                    acls_found_on_interfaces.add(str(outbound_filter))
                    logger.info(f"  → ACL '{outbound_filter}' applied outbound on {node}[{interface_name}]")
        
        logger.info(f"Found {acl_found_count} interface(s) with ACL info from interfaceProperties")
        logger.info(f"Total unique ACLs found applied to interfaces: {len(acls_found_on_interfaces)}")
        
        # ACLs that exist but aren't on interfaces (VTY/QoS/Control-plane)
        other_acls = all_network_acls - acls_found_on_interfaces
        if other_acls:
            logger.info(f"ACLs NOT on interfaces (VTY/QoS/Control-plane): {len(other_acls)} examples: {sorted(list(other_acls))[:10]}")
        
        # Step 3: Get filter details for ACLs found on interfaces
        logger.info("Step 3: Retrieving ACL filter details...")
        acl_details = {}
        
        # Use the already-loaded all_network_acls_df to build ACL details
        if all_network_acls_df is not None and not all_network_acls_df.empty:
            logger.info(f"Building ACL details from {len(all_network_acls)} ACL(s)...")
            
            # Build ACL details from filter lines
            for _, row in all_network_acls_df.iterrows():
                filter_name = str(row.get('Filter', ''))
                line_num = row.get('Line_Index', 0)
                action = str(row.get('Action', ''))
                
                if filter_name not in acl_details:
                    acl_details[filter_name] = {
                        "name": filter_name,
                        "total_lines": 0,
                        "permit_lines": 0,
                        "deny_lines": 0
                    }
                
                acl_details[filter_name]["total_lines"] += 1
                if 'permit' in action.lower():
                    acl_details[filter_name]["permit_lines"] += 1
                elif 'deny' in action.lower():
                    acl_details[filter_name]["deny_lines"] += 1
        
        # Step 4: Build enforcement points result
        logger.info("Step 4: Building enforcement points result...")
        
        # Build case-insensitive ACL lookup
        acl_details_lookup = {name.lower(): name for name in acl_details.keys()}
        
        # Build a map of device -> ACLs for zone-based firewalls
        # Maps device to list of ACLs configured on that device
        device_acls_map = defaultdict(list)
        if all_network_acls_df is not None and not all_network_acls_df.empty:
            for _, row in all_network_acls_df.iterrows():
                node = str(row.get('Node', ''))
                filter_name = str(row.get('Filter', ''))
                if node and node != 'nan' and filter_name and filter_name != 'nan':
                    node_lower = node.lower()
                    # Only add each ACL once per device
                    if filter_name not in device_acls_map[node_lower]:
                        device_acls_map[node_lower].append(filter_name)
        
        logger.info(f"Device ACL mapping built: {dict(device_acls_map)}")
        
        enforcement_points = []
        
        interfaces_with_filtering = 0
        interfaces_without_filtering = 0
        devices_with_zero_acls = 0
        
        for device_lower, interfaces in sorted(enforcement_devices.items()):
            # Get original device name casing
            device = device_name_map.get(device_lower, device_lower)
            device_has_any_acl = False
            device_interfaces_list = []
            
            # Get device-level ACLs (for zone-based firewalls)
            device_level_acls = device_acls_map.get(device_lower, [])
            
            for interface_name, subnets in sorted(interfaces.items()):
                key = f"{device_lower}[{interface_name}]"
                acls = interface_acls.get(key, {"inbound": None, "outbound": None})
                
                # Debug: Show lookup
                logger.debug(f"Looking up key='{key}' in interface_acls")
                if key in interface_acls:
                    logger.debug(f"  → Found: {interface_acls[key]}")
                else:
                    logger.debug(f"  → NOT FOUND. Available keys: {list(interface_acls.keys())[:5]}")
                
                has_enforcement = bool(acls["inbound"] or acls["outbound"])
                
                if has_enforcement:
                    interfaces_with_filtering += 1
                    device_has_any_acl = True
                else:
                    interfaces_without_filtering += 1
                
                # Build ACL info
                acl_info = []
                if acls["inbound"]:
                    # Try exact match first, then case-insensitive
                    matched_name = acls["inbound"] if acls["inbound"] in acl_details else acl_details_lookup.get(acls["inbound"].lower())
                    acl_detail = acl_details.get(matched_name, {}) if matched_name else {}
                    
                    acl_info.append({
                        "name": acls["inbound"],
                        "direction": "inbound",
                        "total_rules": acl_detail.get("total_lines", 0),
                        "permit_rules": acl_detail.get("permit_lines", 0),
                        "deny_rules": acl_detail.get("deny_lines", 0)
                    })
                
                if acls["outbound"]:
                    # Try exact match first, then case-insensitive
                    matched_name = acls["outbound"] if acls["outbound"] in acl_details else acl_details_lookup.get(acls["outbound"].lower())
                    acl_detail = acl_details.get(matched_name, {}) if matched_name else {}
                    
                    acl_info.append({
                        "name": acls["outbound"],
                        "direction": "outbound",
                        "total_rules": acl_detail.get("total_lines", 0),
                        "permit_rules": acl_detail.get("permit_rules", 0),
                        "deny_rules": acl_detail.get("deny_rules", 0)
                    })
                
                device_interfaces_list.append({
                    "interface": interface_name,
                    "subnets": sorted(list(subnets)),
                    "acls": acl_info if acl_info else [],
                    "has_enforcement": has_enforcement
                })
            
            # If we didn't find interface-level ACLs BUT the device has device-level ACLs,
            # mark it as having enforcement and report the device-level ACLs
            device_acl_summary = []
            if device_level_acls:
                device_has_any_acl = True
                for acl_name in device_level_acls:
                    matched_name = acl_name if acl_name in acl_details else acl_details_lookup.get(acl_name.lower())
                    acl_detail = acl_details.get(matched_name, {}) if matched_name else {}
                    
                    device_acl_summary.append({
                        "name": acl_name,
                        "total_rules": acl_detail.get("total_lines", 0),
                        "permit_rules": acl_detail.get("permit_lines", 0),
                        "deny_rules": acl_detail.get("deny_lines", 0)
                    })
            
            if not device_has_any_acl:
                devices_with_zero_acls += 1
            
            enforcement_point = {
                "device": device,
                "interfaces": device_interfaces_list,
                "has_any_enforcement": device_has_any_acl
            }
            
            # Add device-level ACL info for zone-based firewalls
            if device_acl_summary:
                enforcement_point["device_level_acls"] = device_acl_summary
                enforcement_point["enforcement_type"] = "zone-based" if not any(i["has_enforcement"] for i in device_interfaces_list) else "mixed"
            else:
                enforcement_point["enforcement_type"] = "interface-based" if any(i["has_enforcement"] for i in device_interfaces_list) else "none"
            
            enforcement_points.append(enforcement_point)
        
        # Determine if network is flat
        # Network is flat only if NO ACLs exist anywhere (not even zone-based ones)
        network_is_flat = (len(enforcement_points) == devices_with_zero_acls)
        
        # Count zone-based vs interface-based enforcement
        zone_based_count = len([ep for ep in enforcement_points if ep.get("enforcement_type") == "zone-based"])
        interface_based_count = len([ep for ep in enforcement_points if ep.get("enforcement_type") == "interface-based"])
        mixed_count = len([ep for ep in enforcement_points if ep.get("enforcement_type") == "mixed"])
        
        # Build summary
        summary = {
            "total_enforcement_points": len(enforcement_points),
            "devices_with_zero_acls": devices_with_zero_acls,
            "devices_with_enforcement": len(enforcement_points) - devices_with_zero_acls,
            "zone_based_enforcement": zone_based_count,
            "interface_based_enforcement": interface_based_count,
            "mixed_enforcement": mixed_count,
            "interfaces_with_filtering": interfaces_with_filtering,
            "interfaces_without_filtering": interfaces_without_filtering,
            "acls_on_interfaces": len(acls_found_on_interfaces),
            "total_acls_in_network": len(all_network_acls)
        }
        
        # Add note about non-interface ACLs
        if all_network_acls and len(all_network_acls) > len(acls_found_on_interfaces):
            other_acls = all_network_acls - acls_found_on_interfaces
            summary["note"] = (
                f"{len(other_acls)} ACL(s) exist but are NOT applied to interfaces. "
                f"These may be used for VTY access control, QoS policies, or control plane filtering. "
                f"Examples: {', '.join(sorted(list(other_acls))[:5])}"
            )
        
        if devices_with_zero_acls > 0:
            summary["warning"] = (
                f"{devices_with_zero_acls} enforcement point(s) have NO ACLs detected. "
                f"These devices route between segments without security controls!"
            )
        
        devices_with_enforcement = len(enforcement_points) - devices_with_zero_acls
        summary_text = (
            f"Found {len(enforcement_points)} enforcement point(s). "
            f"{devices_with_enforcement} device(s) with ACLs "
            f"({zone_based_count} zone-based, {interface_based_count} interface-based, {mixed_count} mixed), "
            f"{devices_with_zero_acls} device(s) without ACLs."
        )
        
        if network_is_flat:
            summary_text += " ⚠️  Network is FLAT - no ACLs detected anywhere!"
        
        logger.info(summary_text)
        
        result = {
            "ok": True,
            "enforcement_points": enforcement_points,
            "summary": summary,
            "summary_text": summary_text,
            "network_is_flat": network_is_flat
        }
        
        return convert_to_native_types(result)
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error identifying enforcement points: {error_msg}")
        import traceback
        logger.error(traceback.format_exc())
        return {
            "ok": False,
            "error": error_msg,
            "enforcement_points": []
        }


def build_result_without_acls(enforcement_devices: Dict) -> Dict:
    """
    Build result when interface properties are not available.
    Marks all interfaces as having no enforcement.
    """
    enforcement_points = []
    total_interfaces = 0
    
    for device, interfaces in sorted(enforcement_devices.items()):
        device_interfaces_list = []
        
        for interface_name, subnets in sorted(interfaces.items()):
            total_interfaces += 1
            device_interfaces_list.append({
                "interface": interface_name,
                "subnets": sorted(list(subnets)),
                "acls": [],
                "has_enforcement": False
            })
        
        enforcement_points.append({
            "device": device,
            "interfaces": device_interfaces_list,
            "has_any_enforcement": False
        })
    
    return {
        "ok": True,
        "enforcement_points": enforcement_points,
        "summary": {
            "total_enforcement_points": len(enforcement_points),
            "devices_with_zero_acls": len(enforcement_points),
            "interfaces_with_filtering": 0,
            "interfaces_without_filtering": total_interfaces,
            "warning": "Unable to retrieve ACL information. All enforcement points marked as unprotected."
        },
        "network_is_flat": True
    }

