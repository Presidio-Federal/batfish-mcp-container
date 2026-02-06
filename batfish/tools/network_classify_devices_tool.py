"""
Network Classify Devices Tool

Classifies network devices by type (PLC, SCADA, workstation, switch, etc.) for policy validation.
Critical for verifying device placement (e.g., "PLCs must be in Level 0").

Uses multiple signals: vendor, naming patterns, VLANs, and network behavior to classify devices.
"""

import logging
import re
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


class NetworkClassifyDevicesInput(BaseModel):
    """Input model for device classification."""
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


# Classification rules based on vendor and naming patterns
CLASSIFICATION_RULES = {
    "plc": {
        "vendors": ["siemens", "allen-bradley", "ab", "rockwell", "schneider", "modicon", "ge", "omron", "mitsubishi", "honeywell", "yokogawa"],
        "name_patterns": [r"plc", r"controller", r"s7-", r"controllogix", r"compactlogix", r"device-[0-9a-f]{12}"],
        "confidence_boost": {"vlan_indicators": ["ot", "process", "control", "scada", "400", "100", "200"]},
        "oui_vendors": ["honeywell", "siemens", "schneider", "rockwell", "ab", "omron", "yokogawa", "ge"]
    },
    "scada": {
        "vendors": ["ge", "siemens", "schneider", "abb", "emerson", "wonderware", "iconics"],
        "name_patterns": [r"scada", r"hmi", r"historian", r"wonderware", r"ignition", r"iconics"],
        "confidence_boost": {"vlan_indicators": ["ot", "scada", "control", "120", "150"]}
    },
    "rtu": {
        "vendors": ["ge", "siemens", "schweitzer", "sel"],
        "name_patterns": [r"rtu", r"remote.*terminal", r"sel-"],
        "confidence_boost": {"vlan_indicators": ["ot", "field", "remote"]}
    },
    "ied": {
        "vendors": ["schweitzer", "sel", "ge", "siemens", "abb"],
        "name_patterns": [r"ied", r"relay", r"sel-\d+", r"protection"],
        "confidence_boost": {"vlan_indicators": ["ot", "substation", "protection"]}
    },
    "switch": {
        "vendors": ["cisco", "juniper", "arista", "hp", "dell", "brocade", "extreme"],
        "name_patterns": [r"switch", r"sw-", r"sw\d+", r"-sw", r"catalyst", r"nexus", r"-cs\d+"],
        "config_formats": ["cisco_ios", "cisco_nxos", "juniper", "arista"]
    },
    "router": {
        "vendors": ["cisco", "juniper", "palo alto"],
        "name_patterns": [r"router", r"rtr", r"edge", r"border", r"gateway"],
        "config_formats": ["cisco_ios", "juniper"]
    },
    "firewall": {
        "vendors": ["palo alto", "fortinet", "checkpoint", "cisco"],
        "name_patterns": [r"firewall", r"fw-", r"fw\d+", r"palo", r"fortigate", r"asa"],
        "config_formats": ["palo_alto", "fortinet", "checkpoint"]
    },
    "workstation": {
        "vendors": ["hp", "dell", "lenovo", "microsoft", "vmware", "apple", "asus", "acer"],
        "name_patterns": [r"workstation", r"desktop", r"ws-", r"pc-", r"laptop", r"wks"],
        "confidence_boost": {"vlan_indicators": ["corp", "office", "user", "desktop", "1", "10"]},
        "oui_vendors": ["hp", "dell", "lenovo", "apple", "microsoft", "intel"]
    },
    "server": {
        "vendors": ["hp", "dell", "vmware", "microsoft", "linux", "supermicro"],
        "name_patterns": [r"server", r"srv-", r"srvr", r"host", r"esxi", r"vcenter"],
        "confidence_boost": {"vlan_indicators": ["server", "dmz", "data"]}
    },
    "phone": {
        "vendors": ["cisco", "polycom", "yealink", "avaya", "mitel", "grandstream"],
        "name_patterns": [r"phone", r"voip", r"sep[0-9a-f]{12}", r"polycom", r"yealink", r"avaya", r"sip-"],
        "confidence_boost": {"vlan_indicators": ["voice", "voip", "phone", "telephony"]},
        "oui_vendors": ["cisco", "polycom", "yealink", "avaya"]
    },
    "printer": {
        "vendors": ["hp", "canon", "xerox", "brother", "epson", "ricoh"],
        "name_patterns": [r"printer", r"print", r"mfp", r"copier"],
        "confidence_boost": {"vlan_indicators": ["print"]},
        "oui_vendors": ["hp", "canon", "xerox", "brother", "epson"]
    },
    "sensor": {
        "vendors": ["nozomi", "claroty", "dragos", "forescout", "armis", "cisco", "palo alto"],
        "name_patterns": [r"sensor", r"probe", r"monitor", r"nozomi", r"claroty", r"dragos"],
        "confidence_boost": {"vlan_indicators": ["mgmt", "monitor", "security"]}
    },
    "iot_device": {
        "vendors": ["iot", "nest", "ring", "amazon", "google"],
        "name_patterns": [r"iot", r"sensor", r"camera", r"thermostat"],
        "confidence_boost": {"vlan_indicators": ["iot", "guest"]}
    }
}


def extract_vendor_from_name(device_name: str) -> str:
    """
    Extract vendor from device name (typically MAC OUI vendor).
    
    Examples:
        cisco-systems-inc-device-0012435d3763 -> cisco-systems-inc
        honeywell-device-0040842014ba -> honeywell
        hp-inc-device-c018034a0314 -> hp-inc
        nakanmaincs1 -> (none)
    
    Returns vendor string or empty string if not found.
    """
    # Pattern: vendor-name-device-MACADDR or vendor-name-MACADDR
    # Look for pattern: <vendor>-device-<hex> or <vendor>-<hex>
    match = re.match(r'^([a-z0-9]+-[a-z0-9-]+?)(?:-device)?-[0-9a-f]{12}$', device_name.lower())
    if match:
        vendor = match.group(1)
        # Clean up vendor name
        vendor = vendor.replace('-inc', '').replace('-systems', '').replace('-corp', '')
        return vendor
    return ""


def classify_device(device_name: str, vendor: str, config_format: str, vlan: str = None) -> Dict[str, Any]:
    """
    Classify a single device based on multiple signals.
    
    Args:
        device_name: Device hostname
        vendor: Vendor name (from config format or explicit)
        config_format: Configuration format (cisco_ios, etc.)
        vlan: VLAN name/number if known
        
    Returns:
        Classification dict with type, confidence, and evidence
    """
    device_name_lower = device_name.lower()
    vendor_lower = vendor.lower()
    config_format_lower = config_format.lower()
    vlan_lower = vlan.lower() if vlan else ""
    
    # For HOST devices, try to extract vendor from device name (MAC OUI)
    if config_format_lower == "host":
        name_vendor = extract_vendor_from_name(device_name)
        if name_vendor:
            vendor_lower = name_vendor
            # Add evidence that we extracted vendor from name
    
    scores = defaultdict(lambda: {"score": 0, "evidence": []})
    
    for device_type, rules in CLASSIFICATION_RULES.items():
        # Check vendor match (including OUI vendors for endpoints)
        for vendor_pattern in rules.get("vendors", []):
            if vendor_pattern in vendor_lower:
                scores[device_type]["score"] += 3
                scores[device_type]["evidence"].append(f"vendor:{vendor_pattern}")
                break
        
        # Check OUI vendors (for HOST devices with MAC-based names)
        if config_format_lower == "host":
            for oui_vendor in rules.get("oui_vendors", []):
                if oui_vendor in vendor_lower or oui_vendor in device_name_lower:
                    scores[device_type]["score"] += 4
                    scores[device_type]["evidence"].append(f"oui:{oui_vendor}")
                    break
        
        # Check name patterns
        for pattern in rules.get("name_patterns", []):
            if re.search(pattern, device_name_lower):
                scores[device_type]["score"] += 5
                scores[device_type]["evidence"].append(f"naming:{pattern}")
        
        # Check config format
        for format_pattern in rules.get("config_formats", []):
            if format_pattern in config_format_lower:
                scores[device_type]["score"] += 2
                scores[device_type]["evidence"].append(f"config_format:{format_pattern}")
                break
        
        # Check VLAN indicators (boost confidence)
        if vlan_lower:
            boost_rules = rules.get("confidence_boost", {})
            for indicator in boost_rules.get("vlan_indicators", []):
                if indicator in vlan_lower:
                    scores[device_type]["score"] += 3
                    scores[device_type]["evidence"].append(f"vlan:{indicator}")
    
    # For HOST devices with no clear match, make educated guesses based on vendor + VLAN
    if config_format_lower == "host" and not scores:
        # If it's a known IT vendor (cisco, vmware, hp, dell), it's likely NOT a PLC
        it_vendors = ["cisco", "vmware", "hp", "dell", "intel", "microsoft", "lenovo"]
        is_it_vendor = any(v in vendor_lower for v in it_vendors)
        
        if is_it_vendor:
            # IT vendor - likely workstation, server, or phone
            if "vmware" in vendor_lower:
                scores["server"]["score"] = 4
                scores["server"]["evidence"].append("it_vendor:vmware")
            elif "cisco" in vendor_lower and ("voice" in vlan_lower or "voip" in vlan_lower or "phone" in vlan_lower):
                scores["phone"]["score"] = 4
                scores["phone"]["evidence"].append("it_vendor:cisco+voice_vlan")
            else:
                scores["workstation"]["score"] = 3
                scores["workstation"]["evidence"].append(f"it_vendor:{vendor_lower}")
        else:
            # Unknown vendor - use VLAN as hint
            if vlan_lower:
                vlan_num_match = re.search(r'(\d+)', vlan_lower)
                if vlan_num_match:
                    vlan_num = int(vlan_num_match.group(1))
                    if vlan_num >= 100 and vlan_num <= 500:
                        scores["plc"]["score"] = 2
                        scores["plc"]["evidence"].append(f"ot_vlan:{vlan_num}")
                    elif vlan_num == 1 or (vlan_num >= 10 and vlan_num <= 50):
                        scores["workstation"]["score"] = 2
                        scores["workstation"]["evidence"].append(f"corporate_vlan:{vlan_num}")
    
    # Determine best match
    if not scores:
        return {
            "classification": "unknown",
            "confidence": "low",
            "score": 0,
            "evidence": ["no_match"]
        }
    
    best_type = max(scores.items(), key=lambda x: x[1]["score"])
    device_type = best_type[0]
    score_info = best_type[1]
    
    # Determine confidence level
    if score_info["score"] >= 7:
        confidence = "high"
    elif score_info["score"] >= 3:
        confidence = "medium"
    else:
        confidence = "low"
    
    return {
        "classification": device_type,
        "confidence": confidence,
        "score": int(score_info["score"]),
        "evidence": score_info["evidence"]
    }


def execute(input_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Classify all devices in the network by type.
    
    Uses multiple signals to classify each device:
    - Vendor information (from nodeProperties)
    - Device naming patterns
    - Configuration format
    - VLAN membership (if available)
    
    Returns classification for each device with confidence level and evidence.
    
    Args:
        input_data: Dictionary containing network, snapshot, and host
        
    Returns:
        Dictionary with:
        - ok: Success status
        - device_classifications: List of classified devices
        - device_type_summary: Count by type
        - summary: Statistics
    """
    try:
        # Validate input
        validated_input = NetworkClassifyDevicesInput(**input_data)
        
        network = validated_input.network
        snapshot = validated_input.snapshot
        host = validated_input.host
        
        logger.info(f"Classifying devices for '{network}', snapshot '{snapshot}'")
        
        # Initialize Batfish session
        bf = Session(host=host)
        bf.set_network(network)
        bf.set_snapshot(snapshot)
        
        logger.info(f"Connected to Batfish host: {host}")
        
        # Step 1: Get node properties
        logger.info("Step 1: Retrieving node properties...")
        nodes_df, error = safe_batfish_query(
            bf,
            "nodeProperties query",
            lambda: bf.q.nodeProperties(),
            timeout=30
        )
        
        if error or nodes_df is None or nodes_df.empty:
            logger.warning(f"No node properties found: {error}")
            return {
                "ok": True,
                "device_classifications": [],
                "device_type_summary": {},
                "summary": {
                    "total_devices": 0,
                    "classified": 0,
                    "unclassified": 0
                },
                "message": "No device data found in snapshot."
            }
        
        logger.info(f"Found {len(nodes_df)} device(s)")
        
        # Step 2: Get interface properties to map devices to VLANs/subnets
        logger.info("Step 2: Retrieving interface properties for VLAN/subnet mapping...")
        interfaces_df, error = safe_batfish_query(
            bf,
            "interfaceProperties query",
            lambda: bf.q.interfaceProperties(),
            timeout=30
        )
        
        # Build device -> VLAN/subnet mapping
        device_vlan_map = {}
        device_subnet_map = {}
        subnet_to_vlan_map = {}  # Map subnet networks to their VLANs
        
        if interfaces_df is not None and not interfaces_df.empty:
            import ipaddress
            
            for _, row in interfaces_df.iterrows():
                interface_obj = row.get('Interface')
                if not interface_obj:
                    continue
                
                node = interface_obj.hostname if hasattr(interface_obj, 'hostname') else str(interface_obj).split('[')[0]
                interface_name = interface_obj.interface if hasattr(interface_obj, 'interface') else str(interface_obj).split('[')[-1].rstrip(']')
                
                # Get all prefixes (subnets) from this interface
                all_prefixes = row.get('All_Prefixes')
                if all_prefixes and len(all_prefixes) > 0:
                    if node not in device_subnet_map:
                        device_subnet_map[node] = []
                    
                    for prefix in all_prefixes:
                        subnet_str = str(prefix)
                        if subnet_str not in device_subnet_map[node]:
                            device_subnet_map[node].append(subnet_str)
                        
                        # If this is a VLAN interface (SVI), map the subnet to the VLAN
                        if 'vlan' in interface_name.lower():
                            vlan_match = re.search(r'[Vv]lan(\d+)', interface_name)
                            if vlan_match:
                                vlan_num = vlan_match.group(1)
                                vlan_name = f"Vlan{vlan_num}"
                                
                                # Convert subnet to network format (strip host bits)
                                try:
                                    # Handle both "10.42.90.254/24" and just "10.42.90.0/24" formats
                                    network = ipaddress.ip_network(subnet_str, strict=False)
                                    network_str = str(network)
                                    
                                    # Map this network to this VLAN
                                    if network_str not in subnet_to_vlan_map:
                                        subnet_to_vlan_map[network_str] = vlan_name
                                        logger.debug(f"Mapped subnet {network_str} → {vlan_name}")
                                except Exception as e:
                                    logger.debug(f"Failed to parse subnet {subnet_str}: {e}")
                
                # Extract VLAN from interface name for devices (switches that have VLANs configured)
                if 'vlan' in interface_name.lower():
                    vlan_match = re.search(r'[Vv]lan(\d+)', interface_name)
                    if vlan_match:
                        vlan = f"Vlan{vlan_match.group(1)}"
                        if node not in device_vlan_map:
                            device_vlan_map[node] = []
                        if vlan not in device_vlan_map[node]:
                            device_vlan_map[node].append(vlan)
        
        logger.info(f"Mapped {len(device_vlan_map)} device(s) to VLANs, {len(device_subnet_map)} to subnets")
        logger.info(f"Built subnet-to-VLAN map with {len(subnet_to_vlan_map)} entries")
        
        # Log sample of subnet-to-VLAN map for debugging
        if subnet_to_vlan_map:
            sample = list(subnet_to_vlan_map.items())[:5]
            logger.info(f"Sample subnet→VLAN mappings: {sample}")
        
        # Step 3: Classify each device
        logger.info("Step 3: Classifying devices...")
        device_classifications = []
        device_type_counts = defaultdict(int)
        high_confidence_count = 0
        medium_confidence_count = 0
        low_confidence_count = 0
        
        for _, row in nodes_df.iterrows():
            node = str(row.get('Node', ''))
            config_format = str(row.get('Configuration_Format', 'unknown'))
            
            if not node or node == 'nan':
                continue
            
            # Extract vendor from config format
            vendor = config_format.split('_')[0] if '_' in config_format else config_format
            
            # Get VLANs and subnets this device is in
            vlans = device_vlan_map.get(node, [])
            subnets = device_subnet_map.get(node, [])
            primary_subnet = subnets[0] if subnets else None
            
            # If device has subnet but no VLAN, look up VLAN from subnet
            if not vlans and primary_subnet:
                import ipaddress
                try:
                    # Get network portion of subnet (e.g., 10.42.90.251/24 → 10.42.90.0/24)
                    network = ipaddress.ip_network(primary_subnet, strict=False)
                    network_str = str(network)
                    
                    # Look up VLAN for this subnet
                    if network_str in subnet_to_vlan_map:
                        inferred_vlan = subnet_to_vlan_map[network_str]
                        vlans = [inferred_vlan]
                        logger.info(f"✓ Inferred {inferred_vlan} for {node} from subnet {network_str}")
                    else:
                        logger.debug(f"✗ No VLAN mapping found for {node} subnet {network_str}")
                        logger.debug(f"  Available mappings: {list(subnet_to_vlan_map.keys())[:10]}")
                except Exception as e:
                    logger.debug(f"Error inferring VLAN for {node}: {e}")
            
            primary_vlan = vlans[0] if vlans else None
            
            # Classify
            classification = classify_device(node, vendor, config_format, primary_vlan)
            
            device_classifications.append({
                "device": node,
                "classification": classification["classification"],
                "confidence": classification["confidence"],
                "score": classification["score"],
                "evidence": classification["evidence"],
                "vendor": vendor,
                "config_format": config_format,
                "vlans": vlans,
                "subnets": subnets,
                "primary_subnet": primary_subnet
            })
            
            device_type_counts[classification["classification"]] += 1
            
            if classification["confidence"] == "high":
                high_confidence_count += 1
            elif classification["confidence"] == "medium":
                medium_confidence_count += 1
            else:
                low_confidence_count += 1
        
        # Build summary
        total_devices = len(device_classifications)
        classified = total_devices - device_type_counts.get("unknown", 0)
        unclassified = device_type_counts.get("unknown", 0)
        
        summary = {
            "total_devices": total_devices,
            "classified": classified,
            "unclassified": unclassified,
            "high_confidence": high_confidence_count,
            "medium_confidence": medium_confidence_count,
            "low_confidence": low_confidence_count
        }
        
        summary_text = (
            f"Classified {total_devices} device(s): "
            f"{classified} classified, {unclassified} unknown. "
            f"Confidence: {high_confidence_count} high, {medium_confidence_count} medium, {low_confidence_count} low."
        )
        
        logger.info(summary_text)
        
        result = {
            "ok": True,
            "device_classifications": device_classifications,
            "device_type_summary": dict(device_type_counts),
            "subnet_vlan_map": dict(subnet_to_vlan_map),  # FIXED: correct variable name
            "summary": summary,
            "summary_text": summary_text
        }
        
        return convert_to_native_types(result)
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error classifying devices: {error_msg}")
        import traceback
        logger.error(traceback.format_exc())
        return {
            "ok": False,
            "error": error_msg,
            "device_classifications": []
        }

