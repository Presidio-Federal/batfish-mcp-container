"""
Network Analyze ACL Rules Tool

Provides detailed analysis of ACL rule content (not just existence).
Critical for validating security policy enforcement and identifying what traffic is actually permitted/denied.

Analyzes ACL rules to show exact permit/deny decisions for protocol/port combinations.
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


class NetworkAnalyzeACLRulesInput(BaseModel):
    """Input model for ACL rules analysis."""
    network: str = Field(..., description="Batfish network name")
    snapshot: str = Field(..., description="Batfish snapshot name")
    acl_name: str | None = Field(None, description="Optional: specific ACL to analyze. If None, analyzes all ACLs")
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


def parse_ip_range(ip_str: str) -> str:
    """
    Format IP address or range for readability.
    
    Examples:
        0.0.0.0/0 -> "any"
        10.42.88.0/24 -> "10.42.88.0/24"
    """
    if not ip_str or ip_str == 'nan':
        return "any"
    
    ip_str = str(ip_str).strip()
    
    if ip_str == "0.0.0.0/0":
        return "any"
    
    return ip_str


def parse_port_range(port_str: str) -> str:
    """
    Format port or range for readability.
    
    Examples:
        0-65535 -> "any"
        80 -> "80"
        80-443 -> "80-443"
    """
    if not port_str or port_str == 'nan':
        return "any"
    
    port_str = str(port_str).strip()
    
    if port_str in ["0-65535", "1-65535"]:
        return "any"
    
    return port_str


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
        "src_ports": "any",
        "dst_ports": "any"
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


def categorize_acl_rule(rule: Dict[str, Any]) -> str:
    """
    Categorize ACL rule by purpose.
    
    Examples:
        - "default_deny" - catches all traffic at end
        - "permit_specific" - allows specific service
        - "deny_specific" - blocks specific service
        - "permit_broad" - allows broad traffic range
    """
    action = rule.get("action", "").lower()
    src = rule.get("src", "any")
    dst = rule.get("dst", "any")
    protocol = rule.get("protocol", "ip")
    dst_ports = rule.get("dst_ports", "any")
    
    # Default deny (deny any any)
    if action == "deny" and src == "any" and dst == "any":
        return "default_deny"
    
    # Default permit (permit any any)
    if action == "permit" and src == "any" and dst == "any":
        return "default_permit"
    
    # Specific service rules
    if dst_ports != "any":
        if action == "permit":
            return "permit_specific_service"
        else:
            return "deny_specific_service"
    
    # Specific subnet rules
    if src != "any" or dst != "any":
        if action == "permit":
            return "permit_specific_subnet"
        else:
            return "deny_specific_subnet"
    
    # Broad rules
    if action == "permit":
        return "permit_broad"
    else:
        return "deny_broad"


def execute(input_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze ACL rule content in detail.
    
    For each ACL in the network (or a specific ACL if specified):
    - Shows every rule line-by-line
    - Parses source/destination IP ranges
    - Shows protocol and port information
    - Categorizes rules by purpose
    - Identifies potential security issues
    
    This provides the "WHAT" of ACL enforcement - what exactly is permitted/denied.
    
    Args:
        input_data: Dictionary containing network, snapshot, optional acl_name, and host
        
    Returns:
        Dictionary with:
        - ok: Success status
        - acls: List of ACL analysis objects
        - summary: Statistics and security findings
    """
    try:
        # Validate input
        validated_input = NetworkAnalyzeACLRulesInput(**input_data)
        
        network = validated_input.network
        snapshot = validated_input.snapshot
        acl_name_filter = validated_input.acl_name
        host = validated_input.host
        
        logger.info(f"Analyzing ACL rules for '{network}', snapshot '{snapshot}'")
        if acl_name_filter:
            logger.info(f"Filtering to ACL: {acl_name_filter}")
        
        # Initialize Batfish session
        bf = Session(host=host)
        bf.set_network(network)
        bf.set_snapshot(snapshot)
        
        logger.info(f"Connected to Batfish host: {host}")
        
        # Step 1: Get ALL ACL rules using findMatchingFilterLines
        logger.info("Step 1: Retrieving ALL ACL rules using findMatchingFilterLines...")
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
                "acls": [],
                "summary": {
                    "total_acls": 0,
                    "total_rules": 0,
                    "permit_rules": 0,
                    "deny_rules": 0
                },
                "message": "No ACL data found in snapshot."
            }
        
        logger.info(f"Retrieved {len(filter_lines_df)} ACL rule records")
        
        # Step 2: Parse and organize ACL rules
        acl_data = defaultdict(lambda: {
            "name": "",
            "rules": [],
            "applied_on": [],
            "statistics": {
                "total_rules": 0,
                "permit_rules": 0,
                "deny_rules": 0,
                "default_deny": False,
                "default_permit": False
            },
            "categories": defaultdict(int)
        })
        
        for _, row in filter_lines_df.iterrows():
            filter_name = str(row.get('Filter', ''))
            node = str(row.get('Node', ''))
            line_text = str(row.get('Line', ''))
            line_num = row.get('Line_Index', 0)
            action = str(row.get('Action', 'unknown'))
            
            # Apply ACL name filter if specified
            if acl_name_filter and filter_name != acl_name_filter:
                continue
            
            # Parse the ACL line text to extract protocol info
            protocol_info = parse_acl_line_text(line_text)
            
            # Build rule object
            rule = {
                "line": int(line_num) if isinstance(line_num, (int, np.integer)) else line_num,
                "action": action.lower(),
                "src": protocol_info["src"],
                "dst": protocol_info["dst"],
                "protocol": protocol_info["protocol"],
                "src_ports": protocol_info["src_ports"],
                "dst_ports": protocol_info["dst_ports"]
            }
            
            # Categorize rule
            category = categorize_acl_rule(rule)
            rule["category"] = category
            
            # Add to ACL data
            acl_data[filter_name]["name"] = filter_name
            acl_data[filter_name]["rules"].append(rule)
            acl_data[filter_name]["statistics"]["total_rules"] += 1
            acl_data[filter_name]["categories"][category] += 1
            
            if 'permit' in action.lower():
                acl_data[filter_name]["statistics"]["permit_rules"] += 1
            elif 'deny' in action.lower():
                acl_data[filter_name]["statistics"]["deny_rules"] += 1
            
            # Check for default actions
            if category == "default_deny":
                acl_data[filter_name]["statistics"]["default_deny"] = True
            elif category == "default_permit":
                acl_data[filter_name]["statistics"]["default_permit"] = True
        
        if not acl_data:
            logger.warning("No ACLs matched the criteria")
            return {
                "ok": True,
                "acls": [],
                "summary": {
                    "total_acls": 0,
                    "total_rules": 0,
                    "permit_rules": 0,
                    "deny_rules": 0
                },
                "message": f"No ACLs found{' matching: ' + acl_name_filter if acl_name_filter else ''}."
            }
        
        # Step 3: Use searchFilters to find where ACLs are applied
        # This is more reliable than interfaceProperties for finding ACL applications
        logger.info("Step 3: Using searchFilters to map ACL applications to interfaces...")
        
        # Build a case-insensitive ACL name lookup
        acl_name_lookup = {name.lower(): name for name in acl_data.keys()}
        logger.info(f"ACL names from findMatchingFilterLines: {list(acl_data.keys())}")
        
        for acl_name in acl_data.keys():
            try:
                search_df, error = safe_batfish_query(
                    bf,
                    f"searchFilters query for {acl_name}",
                    lambda acl=acl_name: bf.q.searchFilters(filters=acl),
                    timeout=15
                )
                
                if error or search_df is None or search_df.empty:
                    logger.debug(f"No application locations found for ACL '{acl_name}'")
                    continue
                
                logger.info(f"Found {len(search_df)} application location(s) for ACL '{acl_name}'")
                logger.debug(f"searchFilters columns for '{acl_name}': {list(search_df.columns)}")
                
                # Parse each result - searchFilters shows where the ACL is referenced
                for _, row in search_df.iterrows():
                    node = str(row.get('Node', ''))
                    trace = str(row.get('Trace', ''))
                    
                    # Log what we got for debugging
                    logger.debug(f"  searchFilters result: Node={node}, Trace={trace[:100]}...")
                    
                    # searchFilters shows the ACL exists but doesn't give interface details
                    # Mark it as detected, interfaceProperties will fill in details below
                    if node:
                        acl_data[acl_name]["applied_on"].append({
                            "device": node,
                            "interface": "TBD",  # Will be filled by interfaceProperties below
                            "direction": "TBD",
                            "note": "Found via searchFilters, awaiting interface details..."
                        })
                        logger.info(f"  → ACL '{acl_name}' found on device '{node}' (will look up interface...)")
                        
            except Exception as e:
                logger.warning(f"Error searching for ACL '{acl_name}': {e}")
                continue
        
        # ALSO try interfaceProperties as a secondary source to get interface details
        logger.info("Step 4: Checking interfaceProperties to fill in interface/direction details...")
        interfaces_df, error = safe_batfish_query(
            bf,
            "interfaceProperties query",
            lambda: bf.q.interfaceProperties(),
            timeout=30
        )
        
        if interfaces_df is not None and not interfaces_df.empty:
            interfaces_found_count = 0
            
            for _, row in interfaces_df.iterrows():
                interface_obj = row.get('Interface')
                if not interface_obj:
                    continue
                
                node = interface_obj.hostname if hasattr(interface_obj, 'hostname') else str(interface_obj).split('[')[0]
                interface_name = interface_obj.interface if hasattr(interface_obj, 'interface') else str(interface_obj).split('[')[-1].rstrip(']')
                
                # Try both old and new Batfish column names for ACL filters
                inbound_filter = row.get('Incoming_Filter_Name') or row.get('Inbound_Filter')
                outbound_filter = row.get('Outgoing_Filter_Name') or row.get('Outbound_Filter')
                
                # Map inbound ACL
                if inbound_filter and str(inbound_filter) != 'nan':
                    filter_name = str(inbound_filter).strip()
                    matched_acl = filter_name if filter_name in acl_data else acl_name_lookup.get(filter_name.lower())
                    
                    if matched_acl:
                        # Remove any "TBD" entries for this ACL on this device
                        acl_data[matched_acl]["applied_on"] = [
                            x for x in acl_data[matched_acl]["applied_on"] 
                            if not (x["device"] == node and x["interface"] == "TBD")
                        ]
                        
                        # Add the detailed entry
                        acl_data[matched_acl]["applied_on"].append({
                            "device": node,
                            "interface": interface_name,
                            "direction": "inbound"
                        })
                        logger.info(f"  ✓ ACL '{filter_name}' → {node}[{interface_name}] inbound")
                        interfaces_found_count += 1
                
                # Map outbound ACL
                if outbound_filter and str(outbound_filter) != 'nan':
                    filter_name = str(outbound_filter).strip()
                    matched_acl = filter_name if filter_name in acl_data else acl_name_lookup.get(filter_name.lower())
                    
                    if matched_acl:
                        # Remove any "TBD" entries for this ACL on this device
                        acl_data[matched_acl]["applied_on"] = [
                            x for x in acl_data[matched_acl]["applied_on"] 
                            if not (x["device"] == node and x["interface"] == "TBD")
                        ]
                        
                        # Add the detailed entry
                        acl_data[matched_acl]["applied_on"].append({
                            "device": node,
                            "interface": interface_name,
                            "direction": "outbound"
                        })
                        logger.info(f"  ✓ ACL '{filter_name}' → {node}[{interface_name}] outbound")
                        interfaces_found_count += 1
            
            if interfaces_found_count == 0:
                logger.warning("⚠️  interfaceProperties found NO ACLs on interfaces - this may be a Batfish parsing issue")
                logger.warning("    ACLs were detected via searchFilters but interface details are missing")
            else:
                logger.info(f"✓ Found interface details for {interfaces_found_count} ACL application(s)")
            
            # Clean up any remaining "TBD" entries - these are ACLs searchFilters found but interfaceProperties didn't
            for acl_name in acl_data.keys():
                tbd_entries = [x for x in acl_data[acl_name]["applied_on"] if x.get("interface") == "TBD"]
                if tbd_entries:
                    logger.warning(f"⚠️  ACL '{acl_name}' found by searchFilters but interface details unavailable from interfaceProperties")
                    # Update the note to explain this
                    for entry in acl_data[acl_name]["applied_on"]:
                        if entry.get("interface") == "TBD":
                            entry["interface"] = "unknown (Batfish parsing issue)"
                            entry["direction"] = "unknown"
                            entry["note"] = "ACL exists but Batfish interfaceProperties didn't show which interface - likely a parsing issue"
        else:
            logger.warning("⚠️  interfaceProperties returned no data - all interface details will remain unknown")
        
        # Step 4: Build final result and identify security findings
        acls_result = []
        security_findings = []
        
        total_rules = 0
        total_permit = 0
        total_deny = 0
        
        for acl_name, data in sorted(acl_data.items()):
            # Sort rules by line number
            sorted_rules = sorted(data["rules"], key=lambda r: r["line"])
            
            # Security findings
            if data["statistics"]["default_permit"]:
                security_findings.append({
                    "severity": "high",
                    "acl": acl_name,
                    "finding": "Default permit rule detected - allows all traffic by default"
                })
            
            if not data["statistics"]["default_deny"] and data["statistics"]["permit_rules"] > 0:
                security_findings.append({
                    "severity": "medium",
                    "acl": acl_name,
                    "finding": "No explicit default deny - may allow unintended traffic"
                })
            
            if data["statistics"]["permit_rules"] == 0:
                security_findings.append({
                    "severity": "info",
                    "acl": acl_name,
                    "finding": "ACL only contains deny rules - blocking only (no permits)"
                })
            
            acls_result.append({
                "name": acl_name,
                "applied_on": data["applied_on"],
                "rules": sorted_rules,
                "statistics": dict(data["statistics"]),
                "rule_categories": dict(data["categories"])
            })
            
            total_rules += data["statistics"]["total_rules"]
            total_permit += data["statistics"]["permit_rules"]
            total_deny += data["statistics"]["deny_rules"]
        
        # Build summary
        summary = {
            "total_acls": len(acls_result),
            "total_rules": total_rules,
            "permit_rules": total_permit,
            "deny_rules": total_deny,
            "security_findings": len(security_findings)
        }
        
        summary_text = (
            f"Analyzed {len(acls_result)} ACL(s) with {total_rules} total rule(s). "
            f"{total_permit} permit rules, {total_deny} deny rules. "
            f"{len(security_findings)} security finding(s)."
        )
        
        logger.info(summary_text)
        
        result = {
            "ok": True,
            "acls": acls_result,
            "security_findings": security_findings,
            "summary": summary,
            "summary_text": summary_text
        }
        
        return convert_to_native_types(result)
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error analyzing ACL rules: {error_msg}")
        import traceback
        logger.error(traceback.format_exc())
        return {
            "ok": False,
            "error": error_msg,
            "acls": []
        }

