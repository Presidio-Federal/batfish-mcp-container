"""
Network Auto-Classify Zones Tool

Automatically classifies network devices and segments into security model zones (e.g., Purdue levels).
This tool does the heavy lifting that would otherwise require the AI agent to manually parse and map
thousands of device classifications.

Reduces AI workload by ~95% for compliance workflows.
"""

import logging
import re
import ipaddress
from typing import Dict, Any, List, Set
from collections import defaultdict
from pydantic import BaseModel, Field
from pybatfish.client.session import Session

# Import other tools to run internally
from .network_classify_devices_tool import execute as classify_devices_execute
from .network_segment_tool import execute as segment_execute
from .network_vlan_discovery_tool import execute as vlan_discovery_execute

# Import path utilities to load models
from pathlib import Path
import json


def get_models_directory() -> Path:
    """Get the path to the models directory."""
    tool_file = Path(__file__)
    # Go up from tools/ to batfish/, then to models/
    # Path: .../tools/this_file.py -> .../batfish/ -> .../batfish/models/
    models_dir = tool_file.parent.parent / 'models'
    return models_dir


def load_model(model_name: str) -> Dict[str, Any] | None:
    """
    Load a security model from JSON file.
    
    Args:
        model_name: Name of model (e.g., 'purdue', 'isa95')
        
    Returns:
        Model dictionary or None if not found
    """
    models_dir = get_models_directory()
    model_file = models_dir / f"{model_name}.json"
    
    if not model_file.exists():
        return None
    
    try:
        with open(model_file, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading model {model_name}: {e}")
        return None

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class NetworkAutoClassifyZonesInput(BaseModel):
    """Input model for auto zone classification."""
    network: str = Field(..., description="Batfish network name")
    snapshot: str = Field(..., description="Batfish snapshot name")
    model_name: str = Field(..., description="Security model name (e.g., 'purdue', 'isa95', 'nist_csf')")
    rule_set: str = Field("default", description="Classification rule set to use (default: 'default')")
    host: str = Field("localhost", description="Batfish host to connect to")


def convert_to_native_types(obj):
    """Convert numpy types to native Python types for JSON serialization."""
    import numpy as np
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


def get_purdue_level_for_device_type(device_type: str, confidence: str) -> str | None:
    """
    Map device classification to Purdue level.
    
    Args:
        device_type: Device classification (plc, scada, workstation, etc.)
        confidence: Confidence level (high, medium, low)
        
    Returns:
        Purdue level or None if not mappable
    """
    # Only use high-confidence classifications for zone assignment
    if confidence != "high":
        return None
    
    mapping = {
        "plc": "Level_0",
        "rtu": "Level_0",
        "ied": "Level_0",
        "scada": "Level_1",
        "hmi": "Level_1",
        "historian": "Level_1",
        "workstation": "Level_2",  # Engineering workstations
        "server": "Level_3",        # Operations/MES
        "printer": "Level_4",
        "phone": "Level_4"
    }
    
    return mapping.get(device_type)


def calculate_zone_confidence(zone_data: Dict[str, Any], device_count: int, high_conf_count: int) -> Dict[str, Any]:
    """
    Calculate confidence score for a zone classification.
    
    Args:
        zone_data: Zone mapping data
        device_count: Total devices in zone
        high_conf_count: High-confidence devices in zone
        
    Returns:
        Confidence assessment
    """
    if device_count == 0:
        return {
            "overall": "none",
            "score": 0,
            "reasons": ["No devices mapped to this zone"]
        }
    
    conf_ratio = high_conf_count / device_count
    reasons = []
    
    if conf_ratio >= 0.8:
        overall = "high"
        score = 9
        reasons.append(f"✅ {high_conf_count}/{device_count} devices are high-confidence")
    elif conf_ratio >= 0.5:
        overall = "medium"
        score = 6
        reasons.append(f"⚠️ {high_conf_count}/{device_count} devices are high-confidence")
        reasons.append(f"⚠️ {device_count - high_conf_count} devices have lower confidence")
    else:
        overall = "low"
        score = 3
        reasons.append(f"⚠️ Only {high_conf_count}/{device_count} devices are high-confidence")
        reasons.append("⚠️ Zone assignment may be inaccurate - review manually")
    
    # Check for VLAN indicators
    if len(zone_data.get("vlans", [])) > 0:
        reasons.append(f"✅ Explicit VLAN separation detected")
        score += 1
    else:
        reasons.append(f"⚠️ No explicit VLAN separation")
    
    return {
        "overall": overall,
        "score": min(score, 10),
        "reasons": reasons
    }


def execute(input_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Automatically classify network devices into security model zones.
    
    This tool orchestrates multiple internal operations to automatically map your network
    to a security model (like Purdue, ISA-95, NIST CSF) without requiring the AI agent
    to manually parse thousands of lines of device data.
    
    Workflow:
    1. Loads the security model to understand required zones
    2. Classifies all network devices (runs network_classify_devices internally)
    3. Segments the network (runs network_segment internally)
    4. Auto-maps devices to zones based on classification + model rules
    5. Calculates confidence scores for each zone
    6. Returns ready-to-use zone_mapping for compliance checking
    
    Args:
        input_data: Dictionary containing network, snapshot, model_name, rule_set, and host
        
    Returns:
        Dictionary with:
        - ok: Success status
        - auto_classified_zones: Zone mapping ready for compliance checking
        - confidence_summary: Overall confidence assessment
        - device_distribution: Device counts per zone
        - ready_for_compliance_check: Boolean indicating if mapping is usable
        - warnings: Any issues detected during auto-classification
    """
    try:
        # Validate input
        validated_input = NetworkAutoClassifyZonesInput(**input_data)
        
        network = validated_input.network
        snapshot = validated_input.snapshot
        model_name = validated_input.model_name
        rule_set = validated_input.rule_set
        host = validated_input.host
        
        logger.info(f"Auto-classifying zones for network '{network}', snapshot '{snapshot}', model '{model_name}'")
        
        # Step 1: Load the security model to understand what zones we need
        logger.info(f"Step 1: Loading security model '{model_name}'")
        model = load_model(model_name)
        
        if model is None:
            return {
                "ok": False,
                "error": f"Security model '{model_name}' not found",
                "note": "Use network_list_models to see available models"
            }
        
        zones_needed = list(model.get("zones", {}).keys())
        logger.info(f"Model defines {len(zones_needed)} zones: {', '.join(zones_needed)}")
        
        # Step 2: Run device classification internally
        logger.info("Step 2: Classifying all network devices...")
        device_input = {
            "network": network,
            "snapshot": snapshot,
            "host": host,
            "rule_set": rule_set
        }
        device_results = classify_devices_execute(device_input)
        
        if not device_results.get("ok"):
            return {
                "ok": False,
                "error": "Failed to classify devices",
                "details": device_results.get("error")
            }
        
        device_classifications = device_results.get("device_classifications", [])
        logger.info(f"Classified {len(device_classifications)} devices")
        
        # CRITICAL: Get the subnet-to-VLAN map from device classification results
        # The classify_devices tool already built this for us!
        classify_subnet_vlan_map = device_results.get("subnet_vlan_map", {})
        logger.info(f"Got subnet-to-VLAN map from classify_devices: {len(classify_subnet_vlan_map)} entries")
        
        # Step 3: Run segmentation internally
        logger.info("Step 3: Analyzing network segments...")
        segment_input = {
            "network": network,
            "snapshot": snapshot,
            "host": host,
            "sample_size": 50  # Get more devices per segment
        }
        segment_results = segment_execute(segment_input)
        
        if not segment_results.get("ok"):
            return {
                "ok": False,
                "error": "Failed to segment network",
                "details": segment_results.get("error")
            }
        
        segments = segment_results.get("segments", [])
        logger.info(f"Found {len(segments)} network segments")
        
        # Step 3.5: Extract device-to-VLAN mappings from network segments
        # The segment tool already grouped devices by VLAN - use that!
        logger.info("Step 3.5: Extracting device-to-VLAN mappings from segments...")
        
        device_to_vlans_from_segments = defaultdict(set)
        for segment in segments:
            segment_name = segment.get("segment", "")
            # Extract VLAN ID from segment name (e.g., "Vlan3" -> 3)
            vlan_match = re.search(r'[Vv]lan(\d+)', segment_name)
            if vlan_match:
                vlan_id = int(vlan_match.group(1))
                # Get all devices in this segment from device_types
                device_types = segment.get("device_types", [])
                for device_type_entry in device_types:
                    # Each device_type_entry has "examples" which is a list of actual device names
                    examples = device_type_entry.get("examples", [])
                    for device_name in examples:
                        if device_name:
                            device_to_vlans_from_segments[device_name.lower()].add(vlan_id)
        
        logger.info(f"Extracted VLAN mappings for {len(device_to_vlans_from_segments)} devices from segments")
        
        # Step 3.6: Also build subnet-to-VLAN mapping from interfaceProperties (for supernet matching)
        
        # Initialize Batfish session
        from pybatfish.client.session import Session
        try:
            from .aws_safety_utils import safe_batfish_query
        except ImportError:
            from tools.aws_safety_utils import safe_batfish_query
        
        bf = Session(host=host)
        bf.set_network(network)
        bf.set_snapshot(snapshot)
        
        # CRITICAL: Get ALL devices from ipOwners (not just samples from segments)
        logger.info("Step 3.6: Getting ALL device-to-VLAN mappings from ipOwners...")
        ipowners_df, error = safe_batfish_query(
            bf,
            "ipOwners query for all devices",
            lambda: bf.q.ipOwners(),
            timeout=30
        )
        
        device_to_vlans_from_ipowners = defaultdict(set)
        if ipowners_df is not None and not ipowners_df.empty:
            logger.info(f"Processing {len(ipowners_df)} IP ownerships...")
            for _, row in ipowners_df.iterrows():
                node = row.get('Node')
                interface = row.get('Interface')
                
                if not node or not interface:
                    continue
                
                # Extract VLAN from interface name
                vlan_match = re.search(r'[Vv]lan(\d+)', str(interface))
                if vlan_match:
                    vlan_id = int(vlan_match.group(1))
                    device_to_vlans_from_ipowners[node.lower()].add(vlan_id)
        
        logger.info(f"Mapped {len(device_to_vlans_from_ipowners)} devices to VLANs from ipOwners")
        
        # Get interface properties - this shows which VLAN each device/interface is on
        interfaces_df, error = safe_batfish_query(
            bf,
            "interfaceProperties query",
            lambda: bf.q.interfaceProperties(),
            timeout=30
        )
        
        # Build device-to-VLAN mapping and subnet-to-VLAN mapping
        device_to_vlans = defaultdict(set)
        subnet_to_vlan = {}
        vlan_to_subnets_map = defaultdict(set)
        
        if interfaces_df is not None and not interfaces_df.empty:
            logger.info(f"Processing {len(interfaces_df)} interfaces for VLAN mappings...")
            
            for _, row in interfaces_df.iterrows():
                interface_obj = row.get('Interface')
                if not interface_obj:
                    continue
                
                device = interface_obj.hostname if hasattr(interface_obj, 'hostname') else str(interface_obj).split('[')[0]
                interface_name = interface_obj.interface if hasattr(interface_obj, 'interface') else str(interface_obj).split('[')[-1].rstrip(']')
                
                # Check for SVI (VLAN interface with subnet)
                vlan_match = re.search(r'[Vv]lan(\d+)', interface_name)
                if vlan_match:
                    vlan_id = int(vlan_match.group(1))
                    device_to_vlans[device.lower()].add(vlan_id)
                    
                    # Get subnet from this SVI
                    all_prefixes = row.get('All_Prefixes', [])
                    if all_prefixes:
                        logger.debug(f"  SVI {device}[{interface_name}] (VLAN {vlan_id}) has prefixes: {all_prefixes}")
                    for prefix in all_prefixes:
                        try:
                            network_obj = ipaddress.ip_network(str(prefix), strict=False)
                            normalized_subnet = str(network_obj)
                            subnet_to_vlan[normalized_subnet] = vlan_id
                            vlan_to_subnets_map[vlan_id].add(normalized_subnet)
                            logger.debug(f"    Mapped {normalized_subnet} -> VLAN {vlan_id}")
                        except Exception as e:
                            logger.warning(f"    Failed to parse prefix {prefix}: {e}")
                
                # Check for access VLAN on switchports
                access_vlan = row.get('Access_VLAN')
                if access_vlan and str(access_vlan) != 'nan':
                    vlan_id = int(access_vlan)
                    device_to_vlans[device.lower()].add(vlan_id)
        
        logger.info(f"Built mappings: {len(device_to_vlans)} devices mapped to VLANs, {len(subnet_to_vlan)} subnets mapped to VLANs")
        logger.info(f"  Plus {len(classify_subnet_vlan_map)} subnet→VLAN from classify_devices")
        
        # Merge the subnet-to-VLAN map from classify_devices (which has the critical data!)
        for subnet_str, vlan_name in classify_subnet_vlan_map.items():
            # Extract VLAN ID from name like "Vlan3" -> 3
            vlan_match = re.search(r'[Vv]lan(\d+)', str(vlan_name))
            if vlan_match:
                vlan_id = int(vlan_match.group(1))
                subnet_to_vlan[subnet_str] = vlan_id
                vlan_to_subnets_map[vlan_id].add(subnet_str)
        
        logger.info(f"  After merge: {len(subnet_to_vlan)} total subnet mappings")
        
        # Count total unique VLANs
        all_vlans = set()
        for vlans_set in device_to_vlans.values():
            all_vlans.update(vlans_set)
        for vlan_id in vlan_to_subnets_map.keys():
            all_vlans.add(vlan_id)
        
        logger.info(f"  Total unique VLANs found: {len(all_vlans)} - {sorted(all_vlans)[:20]}")
        
        logger.info(f"Built VLAN map with {len(all_vlans)} VLANs total")
        
        # Step 4: Auto-map devices to zones
        logger.info("Step 4: Auto-mapping devices to zones...")
        
        # Initialize zone mapping
        zone_mapping = {}
        for zone_name in zones_needed:
            zone_mapping[zone_name] = {
                "subnets": [],
                "vlans": [],
                "devices": []
            }
        
        # Track statistics
        high_conf_per_zone = defaultdict(int)
        total_per_zone = defaultdict(int)
        unmapped_devices = []
        
        # Map each device to a zone based on its classification
        logger.info(f"Mapping {len(device_classifications)} devices to zones...")
        logger.info(f"Sample devices in device_to_vlans map: {list(device_to_vlans.keys())[:5]}")
        logger.info(f"Sample devices in classifications: {[d.get('device') for d in device_classifications[:5]]}")
        
        vlan_assignment_count = 0
        for device in device_classifications:
            device_name = device.get("device")
            device_type = device.get("classification")
            confidence = device.get("confidence")
            subnets = device.get("subnets", [])
            vlans = device.get("vlans", [])
            
            # Determine Purdue level for this device
            purdue_level = get_purdue_level_for_device_type(device_type, confidence)
            
            if purdue_level and purdue_level in zone_mapping:
                # Add device to zone
                zone_mapping[purdue_level]["devices"].append(device_name)
                total_per_zone[purdue_level] += 1
                
                if confidence == "high":
                    high_conf_per_zone[purdue_level] += 1
                
                # Add subnets
                for subnet in subnets:
                    if subnet and subnet not in zone_mapping[purdue_level]["subnets"]:
                        zone_mapping[purdue_level]["subnets"].append(subnet)
                
                # Add VLANs (from device's vlans list if available)
                for vlan in vlans:
                    if vlan and vlan not in zone_mapping[purdue_level]["vlans"]:
                        zone_mapping[purdue_level]["vlans"].append(vlan)
                
                # CRITICAL: Infer VLANs using THREE methods:
                # Method 1: ipOwners-based lookup (most comprehensive - ALL devices)
                device_name_lower = device_name.lower()
                if device_name_lower in device_to_vlans_from_ipowners:
                    for vlan_id in device_to_vlans_from_ipowners[device_name_lower]:
                        if vlan_id not in zone_mapping[purdue_level]["vlans"]:
                            logger.info(f"  ✓ Device {device_name} -> VLAN {vlan_id} (from ipOwners)")
                            zone_mapping[purdue_level]["vlans"].append(vlan_id)
                            vlan_assignment_count += 1
                
                # Method 2: Segment-based lookup (backup)
                if device_name_lower in device_to_vlans_from_segments:
                    for vlan_id in device_to_vlans_from_segments[device_name_lower]:
                        if vlan_id not in zone_mapping[purdue_level]["vlans"]:
                            logger.info(f"  ✓ Device {device_name} -> VLAN {vlan_id} (from segment)")
                            zone_mapping[purdue_level]["vlans"].append(vlan_id)
                            vlan_assignment_count += 1
                
                # Method 3: Direct device-to-VLAN lookup (for switches/infrastructure from interfaceProperties)
                if device_name_lower in device_to_vlans:
                    for vlan_id in device_to_vlans[device_name_lower]:
                        if vlan_id not in zone_mapping[purdue_level]["vlans"]:
                            logger.info(f"  ✓ Device {device_name} -> VLAN {vlan_id} (direct mapping)")
                            zone_mapping[purdue_level]["vlans"].append(vlan_id)
                            vlan_assignment_count += 1
                
                # Method 4: Subnet-to-VLAN lookup (for endpoints via supernet matching)
                # Need to handle both exact matches and supernet matches
                for subnet in subnets:
                    try:
                        device_network = ipaddress.ip_network(subnet, strict=False)
                        normalized_subnet = str(device_network)
                        
                        # Try exact match first
                        if normalized_subnet in subnet_to_vlan:
                            inferred_vlan = subnet_to_vlan[normalized_subnet]
                            if inferred_vlan not in zone_mapping[purdue_level]["vlans"]:
                                logger.info(f"  ✓ Device {device_name} subnet {subnet} -> VLAN {inferred_vlan} (exact match)")
                                zone_mapping[purdue_level]["vlans"].append(inferred_vlan)
                                vlan_assignment_count += 1
                        else:
                            # Try supernet match - check if device subnet is within any mapped subnet
                            for mapped_subnet_str, vlan_id in subnet_to_vlan.items():
                                try:
                                    mapped_network = ipaddress.ip_network(mapped_subnet_str, strict=False)
                                    if device_network.subnet_of(mapped_network):
                                        if vlan_id not in zone_mapping[purdue_level]["vlans"]:
                                            logger.info(f"  ✓ Device {device_name} subnet {subnet} in supernet {mapped_subnet_str} -> VLAN {vlan_id}")
                                            zone_mapping[purdue_level]["vlans"].append(vlan_id)
                                            vlan_assignment_count += 1
                                        break  # Found a match, stop searching
                                except:
                                    pass
                    except Exception as e:
                        pass
            else:
                # Device couldn't be mapped (low confidence or unknown type)
                unmapped_devices.append({
                    "device": device_name,
                    "type": device_type,
                    "confidence": confidence,
                    "reason": "low_confidence" if confidence != "high" else "unknown_device_type"
                })
        
        logger.info(f"Total VLAN assignments made: {vlan_assignment_count}")
        
        # Step 5: Calculate confidence scores for each zone
        logger.info("Step 5: Calculating confidence scores...")
        zone_confidence = {}
        for zone_name in zones_needed:
            device_count = total_per_zone.get(zone_name, 0)
            high_conf_count = high_conf_per_zone.get(zone_name, 0)
            zone_confidence[zone_name] = calculate_zone_confidence(
                zone_mapping[zone_name],
                device_count,
                high_conf_count
            )
        
        # Step 6: Build confidence summary
        high_conf_zones = sum(1 for z in zone_confidence.values() if z["overall"] == "high")
        medium_conf_zones = sum(1 for z in zone_confidence.values() if z["overall"] == "medium")
        low_conf_zones = sum(1 for z in zone_confidence.values() if z["overall"] == "low")
        empty_zones = sum(1 for z in zone_confidence.values() if z["overall"] == "none")
        
        confidence_summary = {
            "high_confidence_zones": high_conf_zones,
            "medium_confidence_zones": medium_conf_zones,
            "low_confidence_zones": low_conf_zones,
            "empty_zones": empty_zones,
            "unmapped_devices": len(unmapped_devices),
            "total_devices_mapped": sum(total_per_zone.values())
        }
        
        # Step 7: Generate warnings
        warnings = []
        if len(unmapped_devices) > 10:
            warnings.append(f"⚠️ {len(unmapped_devices)} devices could not be auto-mapped (low confidence or unknown types)")
        if low_conf_zones > 0:
            warnings.append(f"⚠️ {low_conf_zones} zone(s) have low confidence - review manually")
        if empty_zones > len(zones_needed) / 2:
            warnings.append(f"⚠️ {empty_zones} zone(s) are empty - network may not match {model_name} model")
        
        # Determine if ready for compliance check
        ready_for_compliance = (
            len(unmapped_devices) < len(device_classifications) * 0.3 and  # Less than 30% unmapped
            low_conf_zones <= len(zones_needed) * 0.3 and  # Less than 30% low confidence
            empty_zones < len(zones_needed) * 0.5  # Less than 50% empty
        )
        
        logger.info(f"Auto-classification complete: {confidence_summary['total_devices_mapped']} devices mapped")
        
        # Add confidence to each zone in the output
        for zone_name in zone_mapping:
            zone_mapping[zone_name]["confidence"] = zone_confidence[zone_name]
            zone_mapping[zone_name]["device_count"] = total_per_zone.get(zone_name, 0)
        
        result = {
            "ok": True,
            "model_name": model_name,
            "auto_classified_zones": zone_mapping,
            "confidence_summary": confidence_summary,
            "device_distribution": dict(total_per_zone),
            "ready_for_compliance_check": ready_for_compliance,
            "warnings": warnings,
            "unmapped_devices": unmapped_devices[:20] if len(unmapped_devices) > 20 else unmapped_devices,  # Limit output
            "summary": (
                f"Auto-classified {confidence_summary['total_devices_mapped']} devices into {len(zones_needed)} zones. "
                f"{high_conf_zones} high-confidence, {medium_conf_zones} medium-confidence, {low_conf_zones} low-confidence zones. "
                f"Ready for compliance check: {ready_for_compliance}"
            )
        }
        
        return convert_to_native_types(result)
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error auto-classifying zones: {error_msg}")
        import traceback
        logger.error(traceback.format_exc())
        return {
            "ok": False,
            "error": error_msg
        }

