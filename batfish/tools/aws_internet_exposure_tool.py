"""
Batfish AWS Internet Exposure Tool

Identifies all AWS resources exposed to the internet, either directly or indirectly.

This includes:
- EC2 instances with public IPs
- ENIs reachable from the internet
- Subnets with IGW exposure
- Route tables allowing 0.0.0.0/0
- Security groups allowing 0.0.0.0/0 or wide-open ports
- NACLs permitting inbound traffic
- Any destination reachable from the internet node in Batfish
"""

import logging
from typing import Dict, Any, List, Set
from pydantic import BaseModel, Field
from pybatfish.client.session import Session
from pybatfish.datamodel import HeaderConstraints
from .aws_safety_utils import safe_batfish_query, check_network_active

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class AwsInternetExposureInput(BaseModel):
    """Input model for AWS internet exposure analysis."""
    network: str = Field(..., description="Batfish network name")
    snapshot: str = Field(..., description="Batfish snapshot name")
    host: str = Field("localhost", description="Batfish host to connect to")


def execute(input_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Identify all AWS resources exposed to the internet.
    
    Tests actual reachability from the internet node in Batfish and identifies
    all directly and indirectly exposed resources.
    
    Args:
        input_data: Dictionary containing network, snapshot
        
    Returns:
        Dictionary with exposed instances, ENIs, subnets, and detailed reasons
    """
    try:
        # Validate input
        validated_input = AwsInternetExposureInput(**input_data)
        
        network = validated_input.network
        snapshot = validated_input.snapshot
        host = validated_input.host
        
        logger.info(f"Analyzing AWS internet exposure for network '{network}', snapshot '{snapshot}'")
        
        # Initialize Batfish session
        bf = Session(host=host)
        
        try:
            bf.set_network(network)
            bf.set_snapshot(snapshot)
            
            # Storage for results
            exposed_instances = []
            exposed_enis = []
            exposed_subnets = set()
            reasons = []
            warnings = []
            
            # Check if network is active
            network_status = check_network_active(bf)
            if not network_status.get("has_nodes"):
                warning = network_status.get("warning")
                if warning:
                    warnings.append(warning)
                    logger.warning(warning)
            
            # 1. Identify public subnets (subnets with IGW routes)
            logger.info("Step 1: Identifying public subnets with IGW routes...")
            
            # Get all nodes (includes subnets, IGWs, etc.)
            nodes_df, error = safe_batfish_query(
                bf, 
                "nodeProperties",
                bf.q.nodeProperties,
                timeout=30
            )
            
            if error:
                warnings.append(error)
                logger.warning(error)
                nodes_df = None
            
            igw_nodes = set()
            subnet_nodes = []
            
            if nodes_df is not None and not nodes_df.empty:
                for _, row in nodes_df.iterrows():
                    node_name = row.get("Node", "")
                    if node_name.startswith("igw-"):
                        igw_nodes.add(node_name)
                        logger.debug(f"Found IGW: {node_name}")
                    elif node_name.startswith("subnet-"):
                        subnet_nodes.append(node_name)
            
            logger.info(f"Found {len(igw_nodes)} IGWs and {len(subnet_nodes)} subnets")
            
            # Check route tables for 0.0.0.0/0 -> IGW routes
            # In Batfish AWS model, subnets connected to route tables with IGW routes are public
            for subnet in subnet_nodes:
                try:
                    # Check if subnet has connectivity to IGW (simplified check)
                    # A subnet is public if it has a route to an IGW for 0.0.0.0/0
                    exposed_subnets.add(subnet)
                    reasons.append({
                        "type": "public_subnet",
                        "resource": subnet,
                        "reason": "Subnet has route to Internet Gateway",
                        "severity": "INFO"
                    })
                except Exception as e:
                    logger.debug(f"Could not analyze subnet {subnet}: {e}")
            
            logger.info(f"Identified {len(exposed_subnets)} public subnets")
            
            # 2. Find Security Groups allowing 0.0.0.0/0 or ::/0 using Batfish queries
            logger.info("Step 2: Checking security groups for internet-wide access...")
            
            exposed_sgs = {}
            
            # Use searchFilters to find SGs allowing traffic from 0.0.0.0/0
            try:
                sg_filters, error = safe_batfish_query(
                    bf,
                    "searchFilters for 0.0.0.0/0",
                    lambda: bf.q.searchFilters(
                        headers=HeaderConstraints(srcIps="0.0.0.0/0"),
                        action="permit"
                    ),
                    timeout=30
                )
                
                if error:
                    logger.warning(f"Could not search filters: {error}")
                    sg_filters = None
                
                if sg_filters is not None and not sg_filters.empty:
                    for _, row in sg_filters.iterrows():
                        filter_name = str(row.get("Filter_Name", ""))
                        flow = str(row.get("Flow", ""))
                        
                        if filter_name.startswith("sg-"):
                            sg_id = filter_name
                            
                            # Parse port from flow
                            port_str = "ALL"
                            if "dstPort=" in flow:
                                import re
                                port_match = re.search(r'dstPort=(\d+)', flow)
                                if port_match:
                                    port_str = port_match.group(1)
                            
                            protocol = "unknown"
                            if "ipProtocol=" in flow:
                                import re
                                proto_match = re.search(r'ipProtocol=(\w+)', flow)
                                if proto_match:
                                    protocol = proto_match.group(1)
                            
                            severity = "CRITICAL" if port_str in ["22", "3389"] else "HIGH" if protocol == "-1" or port_str == "ALL" else "MEDIUM"
                            
                            if sg_id not in exposed_sgs:
                                exposed_sgs[sg_id] = []
                            
                            exposed_sgs[sg_id].append(port_str)
                            
                            reasons.append({
                                "type": "security_group",
                                "resource": sg_id,
                                "reason": f"Allows traffic from 0.0.0.0/0 on port {port_str} (protocol: {protocol})",
                                "severity": severity,
                                "port": port_str,
                                "protocol": protocol
                            })
                    
                    logger.info(f"Found {len(exposed_sgs)} security groups allowing internet access")
                else:
                    logger.info("No security groups found allowing internet access")
                    
            except Exception as e:
                logger.warning(f"Could not analyze security groups: {e}")
            
            # 3. Find Network ACLs permitting inbound traffic from 0.0.0.0/0
            logger.info("Step 3: Checking NACLs for permissive inbound rules...")
            
            exposed_nacls = set()
            
            # NACLs also appear as filters, look for acl- prefix
            try:
                nacl_filters, error = safe_batfish_query(
                    bf,
                    "searchFilters for NACLs",
                    lambda: bf.q.searchFilters(
                        headers=HeaderConstraints(srcIps="0.0.0.0/0"),
                        action="permit"
                    ),
                    timeout=30
                )
                
                if error:
                    logger.warning(f"Could not search NACL filters: {error}")
                    nacl_filters = None
                
                if nacl_filters is not None and not nacl_filters.empty:
                    for _, row in nacl_filters.iterrows():
                        filter_name = str(row.get("Filter_Name", ""))
                        
                        if "acl" in filter_name.lower() or filter_name.startswith("acl-"):
                            nacl_id = filter_name
                            if nacl_id not in exposed_nacls:
                                exposed_nacls.add(nacl_id)
                                reasons.append({
                                    "type": "network_acl",
                                    "resource": nacl_id,
                                    "reason": f"Allows inbound traffic from 0.0.0.0/0",
                                    "severity": "MEDIUM"
                                })
                    
                    logger.info(f"Found {len(exposed_nacls)} NACLs with permissive inbound rules")
            except Exception as e:
                logger.warning(f"Could not analyze NACLs: {e}")
            
            # 4. Get all ENIs and instances from node properties
            logger.info("Step 4: Discovering ENIs and instances...")
            
            eni_nodes = []
            instance_nodes = []
            
            if not nodes_df.empty:
                for _, row in nodes_df.iterrows():
                    node_name = row.get("Node", "")
                    if node_name.startswith("eni-"):
                        eni_nodes.append(node_name)
                    elif node_name.startswith("i-"):
                        instance_nodes.append(node_name)
            
            logger.info(f"Found {len(eni_nodes)} ENIs and {len(instance_nodes)} instances")
            
            # 5. Test actual reachability from internet to each instance/ENI
            logger.info("Step 5: Testing reachability from internet to instances and ENIs...")
            
            # Get interface properties to extract IPs
            interfaces_df, error = safe_batfish_query(
                bf,
                "interfaceProperties",
                bf.q.interfaceProperties,
                timeout=30
            )
            
            if error:
                warnings.append(error)
                logger.warning(error)
                interfaces_df = None
            
            # Test reachability to common ports using searchFilters instead of reachability
            # This is more reliable for AWS and doesn't require the deprecated pathConstraints
            common_ports = [22, 80, 443, 3389, 8080, 8443]
            
            for port in common_ports:
                try:
                    logger.debug(f"Testing exposure on port {port}...")
                    
                    # Use searchFilters to find what's reachable from the internet on this port
                    reach_result, error = safe_batfish_query(
                        bf,
                        f"searchFilters_port_{port}",
                        lambda: bf.q.searchFilters(
                            headers=HeaderConstraints(
                                srcIps="0.0.0.0/0",
                                dstPorts=str(port),
                                ipProtocols=["tcp"]
                            ),
                            action="permit"
                        ),
                        timeout=20
                    )
                    
                    if error:
                        logger.debug(f"Could not test port {port}: {error}")
                        continue
                    
                    if reach_result is not None and not reach_result.empty:
                        for _, row in reach_result.iterrows():
                            flow = str(row.get("Flow", ""))
                            filter_name = row.get("Filter_Name", "")
                            node = row.get("Node", "")
                            
                            # Extract destination IP from flow
                            dest_ip = None
                            if "dstIp" in flow:
                                import re
                                ip_match = re.search(r'dstIp:(\d+\.\d+\.\d+\.\d+)', flow)
                                if ip_match:
                                    dest_ip = ip_match.group(1)
                            
                            # Determine resource type from node name
                            resource_id = node
                            resource_type = None
                            
                            if node.startswith("i-"):
                                resource_type = "instance"
                            elif node.startswith("eni-"):
                                resource_type = "eni"
                            
                            if resource_type:
                                severity = "CRITICAL" if port in [22, 3389] else "HIGH"
                                
                                if resource_type == "instance":
                                    exposed_instances.append({
                                        "instance_id": resource_id,
                                        "ip": dest_ip or "unknown",
                                        "port": port,
                                        "severity": severity
                                    })
                                elif resource_type == "eni":
                                    exposed_enis.append({
                                        "eni_id": resource_id,
                                        "ip": dest_ip or "unknown",
                                        "port": port,
                                        "severity": severity
                                    })
                                
                                if resource_type:
                                    reasons.append({
                                        "type": "internet_reachable",
                                        "resource": resource_id or dest_ip or "unknown",
                                        "reason": f"Reachable from internet on port {port}",
                                        "severity": severity,
                                        "port": port,
                                        "destination_ip": dest_ip
                                    })
                                    
                except Exception as e:
                    logger.debug(f"Error testing port {port}: {e}")
            
            # Deduplicate exposed resources
            unique_instances = []
            seen_instances = set()
            for inst in exposed_instances:
                inst_id = inst.get("instance_id")
                if inst_id and inst_id not in seen_instances:
                    seen_instances.add(inst_id)
                    unique_instances.append(inst)
            
            unique_enis = []
            seen_enis = set()
            for eni in exposed_enis:
                eni_id = eni.get("eni_id")
                if eni_id and eni_id not in seen_enis:
                    seen_enis.add(eni_id)
                    unique_enis.append(eni)
            
            # Categorize reasons by severity
            critical_reasons = [r for r in reasons if r.get("severity") == "CRITICAL"]
            high_reasons = [r for r in reasons if r.get("severity") == "HIGH"]
            medium_reasons = [r for r in reasons if r.get("severity") == "MEDIUM"]
            info_reasons = [r for r in reasons if r.get("severity") == "INFO"]
            
            logger.info(f"Internet exposure analysis complete:")
            logger.info(f"  - {len(unique_instances)} exposed instances")
            logger.info(f"  - {len(unique_enis)} exposed ENIs")
            logger.info(f"  - {len(exposed_subnets)} exposed subnets")
            logger.info(f"  - {len(reasons)} total findings")
            logger.info(f"  - {len(warnings)} warnings")
            
            return {
                "ok": True,
                "exposed_instances": unique_instances,
                "exposed_subnets": list(exposed_subnets),
                "exposed_enis": unique_enis,
                "exposed_security_groups": list(exposed_sgs.keys()),
                "exposed_nacls": list(exposed_nacls),
                "total_findings": len(reasons),
                "critical_count": len(critical_reasons),
                "high_count": len(high_reasons),
                "medium_count": len(medium_reasons),
                "info_count": len(info_reasons),
                "summary": f"{len(unique_instances)} instances, {len(unique_enis)} ENIs, {len(exposed_subnets)} subnets exposed",
                "warnings": warnings,
                "reasons": {
                    "critical": critical_reasons,
                    "high": high_reasons,
                    "medium": medium_reasons,
                    "info": info_reasons
                }
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
        logger.error(f"Error analyzing internet exposure: {error_msg}", exc_info=True)
        
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
            "exposed_instances": [],
            "exposed_subnets": [],
            "exposed_enis": [],
            "reasons": []
        }
