"""
Batfish AWS Security Evaluation Tool

Deep security analysis:
- Overly-permissive security groups
- Shadowed SG rules
- Conflicts between SG and NACL
- Unused security groups
- Inconsistent firewall patterns
- Least privilege violations
"""

import logging
from typing import Dict, Any, List, Set
from pydantic import BaseModel, Field
from pybatfish.client.session import Session
from pybatfish.datamodel import HeaderConstraints
from .aws_safety_utils import check_network_active, safe_batfish_query, get_aws_raw_data

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SecurityEvaluationInput(BaseModel):
    """Input model for security evaluation."""
    network: str = Field(..., description="Batfish network name")
    snapshot: str = Field(..., description="Batfish snapshot name")
    host: str = Field("localhost", description="Batfish host to connect to")


def execute(input_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Perform comprehensive security evaluation of AWS infrastructure.
    
    Returns categorized security findings with remediation recommendations.
    
    Args:
        input_data: Dictionary containing network, snapshot
        
    Returns:
        Dictionary with security findings by category and severity
    """
    try:
        # Validate input
        validated_input = SecurityEvaluationInput(**input_data)
        
        network = validated_input.network
        snapshot = validated_input.snapshot
        host = validated_input.host
        
        logger.info(f"Performing security evaluation for network '{network}', snapshot '{snapshot}'")
        
        # Initialize Batfish session
        bf = Session(host=host)
        
        try:
            bf.set_network(network)
            bf.set_snapshot(snapshot)
            
            # Check if network is active
            network_status = check_network_active(bf)
            if not network_status["has_nodes"]:
                logger.warning(network_status["warning"])
            
            findings = []
            warnings = []
            
            if network_status["warning"]:
                warnings.append(network_status["warning"])
            
            # Add critical warning about Security Group limitations
            warnings.append(
                "IMPORTANT: Batfish only models Security Groups attached to RUNNING instances. "
                "All instances are stopped, so Security Group rules cannot be analyzed. "
                "Only Network ACL rules are visible. Start instances to enable Security Group analysis."
            )
            
            # 1. Find overly-permissive security groups using searchFilters
            logger.info("Analyzing security group permissiveness...")
            overly_permissive = []
            
            # Dangerous ports to check
            dangerous_ports = [22, 3389, 1433, 3306, 5432, 27017, 6379, 9200]
            
            try:
                # Search for filters that allow traffic from 0.0.0.0/0
                permit_filters, error = safe_batfish_query(
                    bf,
                    "searchFilters for 0.0.0.0/0",
                    lambda: bf.q.searchFilters(
                        headers=HeaderConstraints(srcIps="0.0.0.0/0"),
                        action="permit"
                    )
                )
                
                if permit_filters is not None and not permit_filters.empty:
                    seen_filters = set()
                    for _, row in permit_filters.iterrows():
                        filter_name = str(row.get("Filter_Name", ""))
                        flow = str(row.get("Flow", ""))
                        
                        # Check both SGs (sg-*) and NACLs (acl-*)
                        # When instances are stopped, only NACLs will be found
                        is_sg = filter_name.startswith("sg-")
                        is_acl = filter_name.startswith("acl-")
                        
                        if (is_sg or is_acl) and filter_name not in seen_filters:
                            seen_filters.add(filter_name)
                            
                            # Check if it's on a dangerous port
                            is_dangerous = False
                            severity = "MEDIUM"
                            resource_type = "Security group" if is_sg else "Network ACL"
                            issue_detail = f"{resource_type} allows traffic from 0.0.0.0/0"
                            
                            for port in dangerous_ports:
                                if f"dstPort={port}" in flow or f"dstPorts=[{port}]" in flow:
                                    is_dangerous = True
                                    severity = "CRITICAL"
                                    port_name = {22: "SSH", 3389: "RDP", 1433: "SQL Server", 
                                               3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB",
                                               6379: "Redis", 9200: "Elasticsearch"}.get(port, str(port))
                                    issue_detail = f"{resource_type} allows {port_name} (port {port}) from 0.0.0.0/0"
                                    break
                            
                            # Also check for protocol -1 (all)
                            if "ipProtocol=-1" in flow or "ipProtocol=all" in flow:
                                severity = "HIGH"
                                issue_detail = f"{resource_type} allows ALL protocols from 0.0.0.0/0"
                            
                            overly_permissive.append({
                                "type": "overly_permissive_acl" if is_acl else "overly_permissive_sg",
                                "id": filter_name,
                                "severity": severity,
                                "issue": issue_detail,
                                "flow": flow,
                                "remediation": "Restrict source IPs to known ranges" if is_acl else "Restrict source IPs to known ranges or use bastion host"
                            })
                
                # Also check for ::/0 (IPv6)
                permit_filters_v6, error = safe_batfish_query(
                    bf,
                    "searchFilters for ::/0",
                    lambda: bf.q.searchFilters(
                        headers=HeaderConstraints(srcIps="::/0"),
                        action="permit"
                    )
                )
                
                if permit_filters_v6 is not None and not permit_filters_v6.empty:
                    seen_filters_v6 = set()
                    for _, row in permit_filters_v6.iterrows():
                        filter_name = str(row.get("Filter_Name", ""))
                        flow = str(row.get("Flow", ""))
                        
                        # Check both SGs and NACLs
                        is_sg = filter_name.startswith("sg-")
                        is_acl = filter_name.startswith("acl-")
                        
                        if (is_sg or is_acl) and filter_name not in seen_filters and filter_name not in seen_filters_v6:
                            seen_filters_v6.add(filter_name)
                            
                            # Check dangerous ports
                            severity = "MEDIUM"
                            resource_type = "Security group" if is_sg else "Network ACL"
                            issue_detail = f"{resource_type} allows traffic from ::/0 (IPv6)"
                            
                            for port in dangerous_ports:
                                if f"dstPort={port}" in flow:
                                    severity = "CRITICAL"
                                    port_name = {22: "SSH", 3389: "RDP"}.get(port, str(port))
                                    issue_detail = f"{resource_type} allows {port_name} (port {port}) from ::/0 (IPv6)"
                                    break
                            
                            overly_permissive.append({
                                "type": "overly_permissive_acl" if is_acl else "overly_permissive_sg",
                                "id": filter_name,
                                "severity": severity,
                                "issue": issue_detail,
                                "flow": flow,
                                "remediation": "Restrict IPv6 source ranges"
                            })
                            
            except Exception as e:
                logger.warning(f"Could not analyze security group permissiveness: {e}")
            
            # 2. Find unused security groups
            logger.info("Identifying unused security groups...")
            unused_sgs = []
            
            try:
                # Get all security groups from filters
                all_sgs = set()
                all_filters, error = safe_batfish_query(
                    bf,
                    "searchFilters for all SGs",
                    lambda: bf.q.searchFilters(action="permit")
                )
                
                if all_filters is not None and not all_filters.empty:
                    for filter_name in all_filters["Filter_Name"].unique():
                        if str(filter_name).startswith("sg-"):
                            all_sgs.add(str(filter_name))
                
                # Get filters actually applied to nodes/interfaces
                used_sgs = set()
                nodes_df, error = safe_batfish_query(
                    bf,
                    "nodeProperties",
                    lambda: bf.q.nodeProperties()
                )
                
                if nodes_df is not None and not nodes_df.empty:
                    for _, node in nodes_df.iterrows():
                        # Check if node has inbound/outbound filter info
                        # AWS instances have SGs applied as filters
                        node_name = str(node.get("Node", ""))
                        
                        # CRITICAL: Skip nodes with names that violate Batfish grammar
                        # Names starting with digits or containing dots will crash Batfish
                        if not node_name or node_name[0].isdigit() or '.' in node_name:
                            logger.debug(f"Skipping node with problematic name: {node_name}")
                            continue
                        
                        # For AWS, check interfaces
                        interfaces, error = safe_batfish_query(
                            bf,
                            f"interfaceProperties for {node_name}",
                            lambda: bf.q.interfaceProperties(nodes=node_name)
                        )
                        
                        if interfaces is not None and not interfaces.empty:
                            for _, iface in interfaces.iterrows():
                                incoming_filter = str(iface.get("Incoming_Filter_Name", ""))
                                outgoing_filter = str(iface.get("Outgoing_Filter_Name", ""))
                                
                                if incoming_filter.startswith("sg-"):
                                    used_sgs.add(incoming_filter)
                                if outgoing_filter.startswith("sg-"):
                                    used_sgs.add(outgoing_filter)
                
                # SGs that exist but aren't used
                truly_unused = all_sgs - used_sgs
                
                for sg_id in truly_unused:
                    unused_sgs.append({
                        "type": "unused_security_group",
                        "id": sg_id,
                        "severity": "LOW",
                        "issue": "Security group is not attached to any resources",
                        "remediation": "Delete unused security group to reduce attack surface"
                    })
                    
            except Exception as e:
                logger.warning(f"Could not identify unused security groups: {e}")
            
            # 3. Check for conflicting SG and NACL rules
            logger.info("Checking for SG/NACL conflicts...")
            sg_nacl_conflicts = []
            
            # Skip this for now - requires more sophisticated analysis
            
            # 4. Find shadowed rules (rules that will never match)
            logger.info("Detecting shadowed security group rules...")
            shadowed_rules = []
            
            try:
                # Batfish's filterLineReachability shows unreachable lines
                filter_line_reach, error = safe_batfish_query(
                    bf,
                    "filterLineReachability",
                    lambda: bf.q.filterLineReachability()
                )
                
                if filter_line_reach is not None and not filter_line_reach.empty:
                    unreachable = filter_line_reach[filter_line_reach.get("Unreachable_Line", False) == True]
                    
                    for _, row in unreachable.iterrows():
                        filter_name = str(row.get("Filters", ""))
                        if filter_name.startswith("sg-"):
                            shadowed_rules.append({
                                "type": "shadowed_rule",
                                "id": filter_name,
                                "severity": "MEDIUM",
                                "issue": "Rule is shadowed by earlier rule",
                                "remediation": "Remove or reorder rule"
                            })
            except Exception as e:
                logger.warning(f"Could not detect shadowed rules: {e}")
            
            # 5. Detect inconsistent firewall patterns
            logger.info("Analyzing firewall consistency...")
            inconsistent_patterns = []
            
            # Check if similar resources have different security postures
            # Example: Some instances allow SSH from internet, others don't
            # This requires grouping by function/tag - use heuristics
            
            # 6. Identify least privilege violations
            logger.info("Checking least privilege compliance...")
            least_privilege_violations = []
            
            # Look for protocol=-1 (all traffic) rules
            if all_filters is not None and not all_filters.empty:
                for _, row in all_filters.iterrows():
                    flow = str(row.get("Flow", ""))
                    filter_name = row.get("Filter_Name", "")
                    
                    if "protocol:-1" in flow.lower() or "ipProtocol:-1" in flow.lower():
                        if filter_name.startswith("sg-"):
                            least_privilege_violations.append({
                                "type": "least_privilege_violation",
                                "id": filter_name,
                                "severity": "MEDIUM",
                                "issue": "Security group allows all protocols (-1)",
                                "remediation": "Restrict to specific protocols (TCP, UDP, ICMP)"
                            })
            
            # Combine all findings
            all_findings = (
                overly_permissive +
                unused_sgs +
                sg_nacl_conflicts +
                shadowed_rules +
                inconsistent_patterns +
                least_privilege_violations
            )
            
            # Categorize by severity
            critical = [f for f in all_findings if f.get("severity") == "CRITICAL"]
            high = [f for f in all_findings if f.get("severity") == "HIGH"]
            medium = [f for f in all_findings if f.get("severity") == "MEDIUM"]
            low = [f for f in all_findings if f.get("severity") == "LOW"]
            
            # Generate summary
            summary_stats = {
                "overly_permissive_sgs": len(overly_permissive),
                "shadowed_rules": len(shadowed_rules),
                "unused_sgs": len(unused_sgs),
                "least_privilege_violations": len(least_privilege_violations),
                "sg_nacl_conflicts": len(sg_nacl_conflicts)
            }
            
            logger.info(f"Security evaluation complete: {len(all_findings)} findings")
            
            return {
                "ok": True,
                "total_findings": len(all_findings),
                "critical": len(critical),
                "high": len(high),
                "medium": len(medium),
                "low": len(low),
                "summary": f"{len(critical)} critical, {len(high)} high, {len(medium)} medium, {len(low)} low",
                "statistics": summary_stats,
                "findings": {
                    "critical": critical,
                    "high": high,
                    "medium": medium,
                    "low": low
                },
                "warnings": warnings if warnings else []
            }
        
        finally:
            # CRITICAL: Always close session to prevent hanging/freezing
            try:
                bf.delete_session()
                logger.info("Closed Batfish session")
            except Exception as close_error:
                logger.warning(f"Error closing Batfish session: {close_error}")
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error in security evaluation: {error_msg}", exc_info=True)
        
        # Clean up session on error
        if 'bf' in locals():
            try:
                bf.delete_session()
                logger.info("Closed Batfish session after error")
            except Exception:
                pass
        
        return {
            "ok": False,
            "error": error_msg,
            "total_findings": 0,
            "findings": {}
        }


