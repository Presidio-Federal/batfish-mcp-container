"""
Network Update Classification Rules Tool

Allows users to modify device classification rules without editing JSON files directly.
Provides safe, validated updates to classification rule sets with smart input normalization.

Uses category-based approach for simpler, more intuitive rule management.
"""

import logging
import json
from pathlib import Path
from typing import Dict, Any, List
from pydantic import BaseModel, Field
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class NetworkUpdateClassificationRulesInput(BaseModel):
    """Input model for updating classification rules."""
    rule_set: str = Field(..., description="Rule set name to update (e.g., 'default', 'purdue_aligned')")
    device_type: str = Field(..., description="Device type to modify (e.g., 'plc', 'scada', 'workstation', 'firewall', 'router')")
    category: str = Field(..., description="Category to modify: 'vendors', 'oui_vendors', 'name_patterns', 'config_formats', 'vlan_indicators', 'subnet_patterns'")
    operation: str = Field(..., description="Operation: 'add' or 'remove'")
    value: str = Field(..., description="Value to add or remove (will be normalized for subnets/VLANs)")
    create_backup: bool = Field(True, description="Create backup before modifying")


def get_classification_rules_directory() -> Path:
    """Get the path to the classification_rules directory."""
    tool_file = Path(__file__)
    # Go up from tools/ to batfish/, then to classification_rules/
    # Path: .../tools/this_file.py -> .../batfish/ -> .../batfish/classification_rules/
    rules_dir = tool_file.parent.parent / 'classification_rules'
    return rules_dir


def load_rule_set(rule_set_name: str) -> tuple[Dict[str, Any] | None, Path | None]:
    """
    Load a specific rule set from JSON file.
    
    Args:
        rule_set_name: Name of rule set
        
    Returns:
        Tuple of (rule set dictionary, file path) or (None, None) if not found
    """
    rules_dir = get_classification_rules_directory()
    rule_file = rules_dir / f"{rule_set_name}.json"
    
    if not rule_file.exists():
        return None, None
    
    try:
        with open(rule_file, 'r') as f:
            return json.load(f), rule_file
    except Exception as e:
        logger.error(f"Error loading rule set {rule_set_name}: {e}")
        return None, None


def save_rule_set(rule_set: Dict[str, Any], rule_file: Path) -> bool:
    """
    Save rule set to JSON file.
    
    Args:
        rule_set: Rule set dictionary
        rule_file: Path to save to
        
    Returns:
        True if successful, False otherwise
    """
    try:
        with open(rule_file, 'w') as f:
            json.dump(rule_set, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"Error saving rule set: {e}")
        return False


def create_backup(rule_file: Path) -> Path | None:
    """
    Create a timestamped backup of the rule file.
    
    Args:
        rule_file: Path to rule file
        
    Returns:
        Path to backup file or None if failed
    """
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = rule_file.parent / f"{rule_file.stem}_backup_{timestamp}.json"
        
        with open(rule_file, 'r') as src:
            content = src.read()
        
        with open(backup_file, 'w') as dst:
            dst.write(content)
        
        logger.info(f"Created backup: {backup_file}")
        return backup_file
    except Exception as e:
        logger.error(f"Error creating backup: {e}")
        return None


def normalize_subnet_pattern(subnet_input: str) -> str:
    """
    Normalize subnet input to regex pattern.
    
    Accepts:
        - "10.42.100.0/24" -> "10\\.42\\.100\\..*"
        - "192.168.1.*" -> "192\\.168\\.1\\..*"
        - "10.42.100.0/255.255.255.0" -> "10\\.42\\.100\\..*"
        - "10.42.100" -> "10\\.42\\.100\\..*"
    
    Args:
        subnet_input: Subnet in various formats
        
    Returns:
        Regex pattern for subnet matching
    """
    import ipaddress
    import re
    
    subnet_input = subnet_input.strip()
    
    # If already a regex pattern, return as-is
    if '\\.' in subnet_input or '.*' in subnet_input:
        return subnet_input
    
    # Handle wildcard notation (10.42.100.*)
    if subnet_input.endswith('.*'):
        parts = subnet_input.rstrip('.*').split('.')
        escaped_parts = [p.replace('.', '\\.') for p in parts]
        return '\\.'.join(escaped_parts) + '\\..*'
    
    # Handle CIDR notation (10.42.100.0/24)
    if '/' in subnet_input:
        try:
            network = ipaddress.ip_network(subnet_input, strict=False)
            # Extract first 3 octets for /24, first 2 for /16, etc.
            octets = str(network.network_address).split('.')
            prefix_len = network.prefixlen
            
            if prefix_len >= 24:
                # /24 or higher - match first 3 octets
                pattern = f"{octets[0]}\\.{octets[1]}\\.{octets[2]}\\..*"
            elif prefix_len >= 16:
                # /16 to /23 - match first 2 octets
                pattern = f"{octets[0]}\\.{octets[1]}\\..*"
            elif prefix_len >= 8:
                # /8 to /15 - match first octet
                pattern = f"{octets[0]}\\..*"
            else:
                # Less than /8 - match anything
                pattern = ".*"
            
            return pattern
        except:
            # If parsing fails, escape dots and add wildcard
            return subnet_input.replace('.', '\\.') + '\\..*'
    
    # Handle partial IP (10.42.100)
    if re.match(r'^\d+\.\d+\.\d+$', subnet_input) or re.match(r'^\d+\.\d+$', subnet_input):
        return subnet_input.replace('.', '\\.') + '\\..*'
    
    # Default: escape dots and return
    return subnet_input.replace('.', '\\.')


def normalize_vlan_indicator(vlan_input: str) -> str:
    """
    Normalize VLAN input to simple format.
    
    Accepts:
        - "400" -> "400"
        - "vlan400" -> "400"
        - "Vlan400" -> "400"
        - "VLAN_400" -> "400"
        - "voice" -> "voice" (keep text indicators)
    
    Args:
        vlan_input: VLAN in various formats
        
    Returns:
        Normalized VLAN indicator
    """
    import re
    
    vlan_input = vlan_input.strip().lower()
    
    # Extract numeric VLAN from patterns like "vlan400" or "vlan_400"
    match = re.match(r'^vlan[_-]?(\d+)$', vlan_input)
    if match:
        return match.group(1)
    
    # If it's just a number, return it
    if vlan_input.isdigit():
        return vlan_input
    
    # Otherwise return as-is (text indicators like "voice", "ot", "process")
    return vlan_input


def validate_device_type(rule_set: Dict[str, Any], device_type: str) -> bool:
    """
    Check if device type exists in rule set.
    
    Args:
        rule_set: Rule set dictionary
        device_type: Device type to check
        
    Returns:
        True if exists, False otherwise
    """
    return device_type in rule_set.get("device_types", {})


def execute(input_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Update device classification rules using category-based approach.
    
    Categories:
    - vendors: List of vendor keywords
    - oui_vendors: List of OUI vendor identifiers (MAC prefixes)
    - name_patterns: List of regex patterns for device names
    - config_formats: List of config format identifiers
    - vlan_indicators: List of VLAN indicators (numbers or keywords)
    - subnet_patterns: List of subnet regex patterns
    
    Operations:
    - add: Add value to category
    - remove: Remove value from category
    
    Smart Input Normalization:
    - Subnets: Accepts CIDR, wildcard, or partial IP formats
    - VLANs: Accepts "vlan400", "VLAN_400", "400", or text indicators
    
    Args:
        input_data: Dictionary containing rule_set, device_type, category, operation, value, create_backup
        
    Returns:
        Dictionary with:
        - ok: Success status
        - message: Description of what was changed
        - backup_file: Path to backup (if created)
        - normalized_value: The value after normalization (for subnets/VLANs)
        
    Example:
        Move juniper from firewall to router:
        1. rule_set="default", device_type="firewall", category="vendors", operation="remove", value="juniper"
        2. rule_set="default", device_type="router", category="vendors", operation="add", value="juniper"
    """
    try:
        # Validate input
        validated_input = NetworkUpdateClassificationRulesInput(**input_data)
        
        rule_set_name = validated_input.rule_set
        device_type = validated_input.device_type
        category = validated_input.category
        operation = validated_input.operation
        value = validated_input.value
        create_backup_flag = validated_input.create_backup
        
        logger.info(f"Updating classification rules: {rule_set_name}/{device_type}/{category} - {operation} '{value}'")
        
        # Validate category
        valid_categories = ["vendors", "oui_vendors", "name_patterns", "config_formats", "vlan_indicators", "subnet_patterns"]
        if category not in valid_categories:
            return {
                "ok": False,
                "error": f"Invalid category '{category}'",
                "valid_categories": valid_categories,
                "note": f"Category must be one of: {', '.join(valid_categories)}"
            }
        
        # Validate operation
        if operation not in ["add", "remove"]:
            return {
                "ok": False,
                "error": f"Invalid operation '{operation}'",
                "valid_operations": ["add", "remove"],
                "note": "Operation must be 'add' or 'remove'"
            }
        
        # Load rule set
        rule_set, rule_file = load_rule_set(rule_set_name)
        
        if rule_set is None or rule_file is None:
            return {
                "ok": False,
                "error": f"Rule set '{rule_set_name}' not found",
                "note": "Check available rule sets with network_list_classification_rules"
            }
        
        # Validate device type exists
        if not validate_device_type(rule_set, device_type):
            available_types = list(rule_set.get("device_types", {}).keys())
            return {
                "ok": False,
                "error": f"Device type '{device_type}' not found in rule set '{rule_set_name}'",
                "available_device_types": available_types,
                "note": f"Available types: {', '.join(available_types)}"
            }
        
        # Create backup if requested
        backup_file = None
        if create_backup_flag:
            backup_file = create_backup(rule_file)
            if backup_file is None:
                return {
                    "ok": False,
                    "error": "Failed to create backup file",
                    "note": "Set create_backup=False to skip backup"
                }
        
        # Get device type rules
        device_rules = rule_set["device_types"][device_type]
        
        # Ensure category exists
        if category not in device_rules:
            device_rules[category] = []
        
        # Normalize value based on category
        normalized_value = value
        if category == "subnet_patterns":
            normalized_value = normalize_subnet_pattern(value)
            logger.info(f"Normalized subnet '{value}' -> '{normalized_value}'")
        elif category == "vlan_indicators":
            normalized_value = normalize_vlan_indicator(value)
            logger.info(f"Normalized VLAN '{value}' -> '{normalized_value}'")
        else:
            # For other categories, convert to lowercase
            normalized_value = value.lower()
        
        # Perform operation
        changed = False
        message = ""
        
        if operation == "add":
            if normalized_value not in device_rules[category]:
                device_rules[category].append(normalized_value)
                changed = True
                message = f"Added '{value}' to {device_type}.{category}"
                if normalized_value != value and normalized_value != value.lower():
                    message += f" (normalized to '{normalized_value}')"
            else:
                message = f"'{value}' already exists in {device_type}.{category}"
        
        elif operation == "remove":
            if normalized_value in device_rules[category]:
                device_rules[category].remove(normalized_value)
                changed = True
                message = f"Removed '{value}' from {device_type}.{category}"
            else:
                # Also try original value in case it wasn't normalized
                if value.lower() in device_rules[category]:
                    device_rules[category].remove(value.lower())
                    changed = True
                    message = f"Removed '{value}' from {device_type}.{category}"
                else:
                    message = f"'{value}' not found in {device_type}.{category}"
        
        # Save changes if modified
        if changed:
            # Update last_updated timestamp
            rule_set["last_updated"] = datetime.now().strftime("%Y-%m-%d")
            
            # Save rule set
            if save_rule_set(rule_set, rule_file):
                result = {
                    "ok": True,
                    "changed": True,
                    "message": message,
                    "rule_set": rule_set_name,
                    "device_type": device_type,
                    "category": category,
                    "operation": operation,
                    "original_value": value,
                    "normalized_value": normalized_value
                }
                
                if backup_file:
                    result["backup_file"] = str(backup_file)
                
                logger.info(message)
                return result
            else:
                return {
                    "ok": False,
                    "error": "Failed to save changes to rule set",
                    "backup_file": str(backup_file) if backup_file else None,
                    "note": "Backup file created but changes not saved"
                }
        else:
            return {
                "ok": True,
                "changed": False,
                "message": message,
                "rule_set": rule_set_name,
                "device_type": device_type,
                "category": category,
                "note": "No changes made"
            }
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error updating classification rules: {error_msg}")
        import traceback
        logger.error(traceback.format_exc())
        return {
            "ok": False,
            "error": error_msg
        }
