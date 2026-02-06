"""
Network List Classification Rules Tool

Lists and displays device classification rule sets.
Allows users to view what rules are being used to classify devices.
"""

import logging
import json
from pathlib import Path
from typing import Dict, Any, List
from pydantic import BaseModel, Field

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class NetworkListClassificationRulesInput(BaseModel):
    """Input model for listing classification rules."""
    rule_set: str | None = Field(
        None, 
        description="Optional: specific rule set name to view in detail. If None, lists all available rule sets"
    )
    show_details: bool = Field(
        False,
        description="If True, shows full rule details. If False, shows summaries only"
    )


def get_classification_rules_directory() -> Path:
    """Get the path to the classification_rules directory."""
    # This tool is in: src/servers/batfish/tools/
    # Rules are in: src/servers/batfish/classification_rules/
    tool_file = Path(__file__)
    # Go up from tools/ to batfish/, then to classification_rules/
    # Path: .../tools/this_file.py -> .../batfish/ -> .../batfish/classification_rules/
    rules_dir = tool_file.parent.parent / 'classification_rules'
    return rules_dir


def load_rule_set(rule_set_name: str) -> Dict[str, Any] | None:
    """
    Load a specific rule set from JSON file.
    
    Args:
        rule_set_name: Name of rule set (e.g., "default", "custom_my_site")
        
    Returns:
        Rule set dictionary or None if not found
    """
    rules_dir = get_classification_rules_directory()
    
    # Try exact match first
    rule_file = rules_dir / f"{rule_set_name}.json"
    
    if not rule_file.exists():
        # Try with .json extension already included
        if not rule_set_name.endswith('.json'):
            return None
        rule_file = rules_dir / rule_set_name
    
    if not rule_file.exists():
        return None
    
    try:
        with open(rule_file, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading rule set {rule_set_name}: {e}")
        return None


def list_available_rule_sets() -> List[Dict[str, Any]]:
    """
    List all available classification rule sets.
    
    Returns:
        List of rule set summaries
    """
    rules_dir = get_classification_rules_directory()
    
    if not rules_dir.exists():
        logger.warning(f"Classification rules directory not found: {rules_dir}")
        return []
    
    rule_sets = []
    
    for rule_file in rules_dir.glob("*.json"):
        try:
            with open(rule_file, 'r') as f:
                rules = json.load(f)
            
            rule_sets.append({
                "name": rule_file.stem,
                "display_name": rules.get("name", rule_file.stem),
                "version": rules.get("version", "unknown"),
                "description": rules.get("description", ""),
                "device_types_count": len(rules.get("device_types", {})),
                "last_updated": rules.get("last_updated", "unknown")
            })
        except Exception as e:
            logger.warning(f"Error reading rule set {rule_file.name}: {e}")
            continue
    
    return sorted(rule_sets, key=lambda x: x["name"])


def summarize_device_type(device_type: str, rules: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create a summary of a device type's rules.
    
    Args:
        device_type: Device type key (e.g., "plc")
        rules: Device type rules dictionary
        
    Returns:
        Summary dictionary
    """
    return {
        "type": device_type,
        "display_name": rules.get("display_name", device_type),
        "category": rules.get("category", "unknown"),
        "purdue_level": rules.get("purdue_level"),
        "vendors_count": len(rules.get("vendors", [])),
        "sample_vendors": rules.get("vendors", [])[:3],
        "patterns_count": len(rules.get("name_patterns", [])),
        "sample_patterns": rules.get("name_patterns", [])[:3],
        "has_vlan_indicators": len(rules.get("vlan_indicators", [])) > 0,
        "has_oui_vendors": len(rules.get("oui_vendors", [])) > 0
    }


def execute(input_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    List or view device classification rule sets.
    
    Modes:
    1. List all rule sets (rule_set=None, show_details=False)
    2. View specific rule set summary (rule_set="name", show_details=False)
    3. View full rule set details (rule_set="name", show_details=True)
    
    Args:
        input_data: Dictionary containing optional rule_set and show_details
        
    Returns:
        Dictionary with:
        - ok: Success status
        - rule_sets: List of rule sets (if listing all)
        - rule_set: Specific rule set data (if viewing one)
        - summary: Human-readable summary
    """
    try:
        # Validate input
        validated_input = NetworkListClassificationRulesInput(**input_data)
        
        rule_set_name = validated_input.rule_set
        show_details = validated_input.show_details
        
        # Check if classification rules directory exists
        rules_dir = get_classification_rules_directory()
        if not rules_dir.exists():
            return {
                "ok": False,
                "error": f"Classification rules directory not found",
                "rule_sets": [],
                "note": "Contact administrator - classification_rules directory missing"
            }
        
        # Mode 1: List all rule sets
        if rule_set_name is None:
            logger.info("Listing all available classification rule sets")
            
            rule_sets = list_available_rule_sets()
            
            if not rule_sets:
                return {
                "ok": True,
                "rule_sets": [],
                "summary": "No classification rule sets found.",
                "note": "Contact administrator to add rule set files"
            }
            
            # If show_details is True, load full details for all rule sets
            if show_details:
                detailed_rule_sets = []
                for rs in rule_sets:
                    rules = load_rule_set(rs["name"])
                    if rules:
                        device_types = rules.get("device_types", {})
                        enhanced_device_types = {}
                        for dt_name, dt_rules in device_types.items():
                            enhanced_device_types[dt_name] = {
                                **dt_rules,
                                "_counts": {
                                    "total_vendors": len(dt_rules.get("vendors", [])),
                                    "total_patterns": len(dt_rules.get("name_patterns", [])),
                                    "total_vlan_indicators": len(dt_rules.get("vlan_indicators", [])),
                                    "total_oui_vendors": len(dt_rules.get("oui_vendors", [])),
                                    "total_subnet_patterns": len(dt_rules.get("subnet_patterns", []))
                                }
                            }
                        
                        detailed_rule_sets.append({
                            "name": rs["name"],
                            "metadata": {
                                "display_name": rules.get("name", rs["name"]),
                                "version": rules.get("version", "unknown"),
                                "description": rules.get("description", ""),
                                "author": rules.get("author", ""),
                                "last_updated": rules.get("last_updated", "")
                            },
                            "scoring_weights": rules.get("scoring_weights", {}),
                            "confidence_thresholds": rules.get("confidence_thresholds", {}),
                            "device_types_full": enhanced_device_types,
                            "fallback_rules": rules.get("fallback_rules", {})
                        })
                
                summary = f"FULL DETAILS: Found {len(rule_sets)} classification rule set(s) with complete device type definitions."
                
                return {
                    "ok": True,
                    "detail_level": "FULL",
                    "rule_sets_full": detailed_rule_sets,
                    "summary": summary
                }
            
            # Otherwise just return summary list
            summary = f"Found {len(rule_sets)} classification rule set(s)."
            
            return {
                "ok": True,
                "detail_level": "SUMMARY",
                "rule_sets": rule_sets,
                "summary": summary,
                "note": "Set show_details=True to see full rule definitions for all rule sets, or specify rule_set='name' to view a specific one"
            }
        
        # Mode 2 & 3: View specific rule set
        logger.info(f"Loading rule set: {rule_set_name}")
        
        rules = load_rule_set(rule_set_name)
        
        if rules is None:
            available = list_available_rule_sets()
            available_names = [rs["name"] for rs in available]
            
            return {
                "ok": False,
                "error": f"Rule set '{rule_set_name}' not found",
                "available_rule_sets": available_names,
                "note": f"Available rule sets: {', '.join(available_names)}"
            }
        
        # Build response based on detail level
        if show_details:
            # Mode 3: Full details - return complete rule definitions
            device_types = rules.get("device_types", {})
            
            # Add helpful metrics to each device type
            enhanced_device_types = {}
            for dt_name, dt_rules in device_types.items():
                enhanced_device_types[dt_name] = {
                    **dt_rules,
                    "_counts": {
                        "total_vendors": len(dt_rules.get("vendors", [])),
                        "total_patterns": len(dt_rules.get("name_patterns", [])),
                        "total_vlan_indicators": len(dt_rules.get("vlan_indicators", [])),
                        "total_oui_vendors": len(dt_rules.get("oui_vendors", [])),
                        "total_subnet_patterns": len(dt_rules.get("subnet_patterns", []))
                    }
                }
            
            result = {
                "ok": True,
                "detail_level": "FULL",
                "rule_set": {
                    "name": rule_set_name,
                    "metadata": {
                        "display_name": rules.get("name", rule_set_name),
                        "version": rules.get("version", "unknown"),
                        "description": rules.get("description", ""),
                        "author": rules.get("author", ""),
                        "last_updated": rules.get("last_updated", "")
                    },
                    "scoring_weights": rules.get("scoring_weights", {}),
                    "confidence_thresholds": rules.get("confidence_thresholds", {}),
                    "device_types_full": enhanced_device_types,
                    "fallback_rules": rules.get("fallback_rules", {})
                },
                "summary": f"FULL DETAILS: Rule set '{rule_set_name}' with {len(device_types)} device types. All vendors, patterns, and rules included."
            }
        else:
            # Mode 2: Summary only - just show counts and samples
            device_type_summaries = [
                summarize_device_type(dt, dt_rules)
                for dt, dt_rules in rules.get("device_types", {}).items()
            ]
            
            result = {
                "ok": True,
                "detail_level": "SUMMARY",
                "rule_set": {
                    "name": rule_set_name,
                    "metadata": {
                        "display_name": rules.get("name", rule_set_name),
                        "version": rules.get("version", "unknown"),
                        "description": rules.get("description", ""),
                        "last_updated": rules.get("last_updated", "")
                    },
                    "scoring_weights": rules.get("scoring_weights", {}),
                    "confidence_thresholds": rules.get("confidence_thresholds", {}),
                    "device_types_summary": device_type_summaries,
                    "total_device_types": len(device_type_summaries)
                },
                "summary": f"SUMMARY: Rule set '{rule_set_name}' with {len(device_type_summaries)} device types. Showing samples only (first 3 of each). Set show_details=True for complete rules.",
                "note": "Set show_details=True to see ALL vendors, patterns, VLAN indicators, OUI vendors, and subnet patterns"
            }
        
        return result
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error listing classification rules: {error_msg}")
        import traceback
        logger.error(traceback.format_exc())
        return {
            "ok": False,
            "error": error_msg,
            "rule_sets": []
        }

