"""
Batfish AWS Change Impact Tool

Pre-deployment change validation - compares two snapshots to identify:
- Breaking changes (flows that will stop working)
- New reachability (new paths opened)
- Lost reachability (paths that will be blocked)
- Risk assessment

Prevents outages by validating changes BEFORE deployment.
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


class AwsChangeImpactInput(BaseModel):
    """Input model for AWS change impact analysis."""
    network: str = Field(..., description="Batfish network name")
    base_snapshot: str = Field(..., description="Current/baseline snapshot name")
    candidate_snapshot: str = Field(..., description="Proposed change snapshot name")
    critical_flows: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Critical flows to test (optional) - format: [{'src': 'subnet-a', 'dst': '8.8.8.8', 'port': 443}]"
    )
    host: str = Field("localhost", description="Batfish host to connect to")


def execute(input_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compare two snapshots and identify change impact.
    
    Tests reachability differences between base and candidate snapshots
    to identify breaking changes, new paths, and lost connectivity.
    
    Args:
        input_data: Dictionary containing network, snapshots, test flows
        
    Returns:
        Dictionary with breaking changes, new/lost reachability, risk level
    """
    try:
        # Validate input
        validated_input = AwsChangeImpactInput(**input_data)
        
        network = validated_input.network
        base_snapshot = validated_input.base_snapshot
        candidate_snapshot = validated_input.candidate_snapshot
        critical_flows = validated_input.critical_flows
        host = validated_input.host
        
        logger.info(f"Starting change impact analysis: {base_snapshot} → {candidate_snapshot}")
        
        # Initialize Batfish session
        bf = Session(host=host)
        
        try:
            bf.set_network(network)
            
            # Storage for results
            breaking_changes = []
            new_reachability = []
            lost_reachability = []
            unchanged_flows = []
            warnings = []
            
            # Check if network is active in both snapshots
            logger.info(f"Checking base snapshot: {base_snapshot}")
            bf.set_snapshot(base_snapshot)
            network_status = check_network_active(bf)
            if not network_status.get("has_nodes"):
                warning = network_status.get("warning")
                if warning:
                    warnings.append(f"Base snapshot: {warning}")
                    logger.warning(warning)
            
            logger.info(f"Checking candidate snapshot: {candidate_snapshot}")
            bf.set_snapshot(candidate_snapshot)
            network_status = check_network_active(bf)
            if not network_status.get("has_nodes"):
                warning = network_status.get("warning")
                if warning:
                    warnings.append(f"Candidate snapshot: {warning}")
                    logger.warning(warning)
            
            # 1. Test critical flows if provided
            if critical_flows:
                logger.info(f"Testing {len(critical_flows)} critical flows...")
            
            for flow in critical_flows:
                src = flow.get("src", "")
                dst = flow.get("dst", "")
                port = flow.get("port")
                protocol = flow.get("protocol", "tcp")
                
                flow_name = f"{src} → {dst}:{port}/{protocol}"
                
                # Test in base snapshot
                bf.set_snapshot(base_snapshot)
                
                try:
                    base_headers = HeaderConstraints(
                        dstIps=dst,
                        ipProtocols=[protocol]
                    )
                    if port is not None:
                        base_headers = HeaderConstraints(
                            dstIps=dst,
                            dstPorts=str(port),
                            ipProtocols=[protocol]
                        )
                    
                    base_result, error = safe_batfish_query(
                        bf,
                        f"base_traceroute_{flow_name}",
                        lambda: bf.q.traceroute(
                            startLocation=src,
                            headers=base_headers
                        ),
                        timeout=20
                    )
                    
                    if error:
                        logger.warning(error)
                        base_works = False
                    elif base_result is not None and not base_result.empty:
                        traces = base_result.iloc[0].get("Traces", [])
                        if traces:
                            disposition = str(traces[0].disposition) if hasattr(traces[0], 'disposition') else ""
                            base_works = "ACCEPT" in disposition.upper()
                    else:
                        base_works = False
                    
                except Exception as e:
                    logger.warning(f"Error testing base flow {flow_name}: {e}")
                    base_works = False
                
                # Test in candidate snapshot
                bf.set_snapshot(candidate_snapshot)
                
                try:
                    candidate_headers = HeaderConstraints(
                        dstIps=dst,
                        ipProtocols=[protocol]
                    )
                    if port is not None:
                        candidate_headers = HeaderConstraints(
                            dstIps=dst,
                            dstPorts=str(port),
                            ipProtocols=[protocol]
                        )
                    
                    candidate_result, error = safe_batfish_query(
                        bf,
                        f"candidate_traceroute_{flow_name}",
                        lambda: bf.q.traceroute(
                            startLocation=src,
                            headers=candidate_headers
                        ),
                        timeout=20
                    )
                    
                    if error:
                        logger.warning(error)
                        candidate_works = False
                    elif candidate_result is not None and not candidate_result.empty:
                        traces = candidate_result.iloc[0].get("Traces", [])
                        if traces:
                            disposition = str(traces[0].disposition) if hasattr(traces[0], 'disposition') else ""
                            candidate_works = "ACCEPT" in disposition.upper()
                    else:
                        candidate_works = False
                    
                except Exception as e:
                    logger.warning(f"Error testing candidate flow {flow_name}: {e}")
                    candidate_works = False
                
                # Compare results
                if base_works and not candidate_works:
                    # BREAKING CHANGE
                    breaking_changes.append({
                        "flow": flow_name,
                        "source": src,
                        "destination": dst,
                        "port": port,
                        "protocol": protocol,
                        "severity": "CRITICAL",
                        "impact": "Flow will be BLOCKED after change",
                        "was_working": True,
                        "will_work": False
                    })
                elif not base_works and candidate_works:
                    # NEW REACHABILITY
                    new_reachability.append({
                        "flow": flow_name,
                        "source": src,
                        "destination": dst,
                        "port": port,
                        "protocol": protocol,
                        "severity": "INFO",
                        "impact": "New connectivity will be enabled",
                        "was_working": False,
                        "will_work": True
                    })
                elif base_works and candidate_works:
                    # NO CHANGE
                    unchanged_flows.append({
                        "flow": flow_name,
                        "status": "unchanged"
                    })
                else:
                    # STILL BLOCKED
                    unchanged_flows.append({
                        "flow": flow_name,
                        "status": "still_blocked"
                    })
            
            # 2. Use Batfish's built-in differential reachability
            logger.info("Running Batfish differential reachability analysis...")
            
            try:
                # Compare reachability between snapshots
                bf.set_snapshot(base_snapshot)
                
                # Get baseline reachability for common flows
                common_test_flows = [
                    {"dst": "8.8.8.8", "port": 443, "name": "Internet HTTPS"},
                    {"dst": "8.8.8.8", "port": 80, "name": "Internet HTTP"},
                    {"dst": "8.8.8.8", "port": 22, "name": "Internet SSH"},
                ]
                
                # Get all subnets from base
                base_nodes, error = safe_batfish_query(
                    bf,
                    "base_nodeProperties",
                    bf.q.nodeProperties,
                    timeout=30
                )
                
                if error:
                    warnings.append(error)
                    logger.warning(error)
                    base_nodes = None
                
                base_subnets = []
                if base_nodes is not None and not base_nodes.empty:
                    for _, row in base_nodes.iterrows():
                        node = row.get("Node", "")
                        if node.startswith("subnet-"):
                            base_subnets.append(node)
                
                logger.info(f"Testing {len(base_subnets)} subnets against {len(common_test_flows)} common flows")
                
                # Test each subnet against common flows
                for subnet in base_subnets[:5]:  # Limit to first 5 subnets for performance
                    for test_flow in common_test_flows:
                        dst = test_flow["dst"]
                        port = test_flow.get("port")
                        name = test_flow["name"]
                        
                        flow_name = f"{subnet} → {name}"
                        
                        # Test base
                        try:
                            bf.set_snapshot(base_snapshot)
                            base_reach, error = safe_batfish_query(
                                bf,
                                f"base_flow_{flow_name}",
                                lambda: bf.q.traceroute(
                                    startLocation=subnet,
                                    headers=HeaderConstraints(
                                        dstIps=dst,
                                        dstPorts=str(port) if port else None,
                                        ipProtocols=["tcp"]
                                    )
                                ),
                                timeout=15
                            )
                            
                            base_works = False
                            if error:
                                logger.debug(f"Base test failed for {flow_name}: {error}")
                            elif base_reach is not None and not base_reach.empty:
                                traces = base_reach.iloc[0].get("Traces", [])
                                if traces:
                                    disposition = str(traces[0].disposition) if hasattr(traces[0], 'disposition') else ""
                                    base_works = "ACCEPT" in disposition.upper()
                        except Exception as e:
                            logger.debug(f"Base test failed for {flow_name}: {e}")
                            base_works = False
                        
                        # Test candidate
                        try:
                            bf.set_snapshot(candidate_snapshot)
                            candidate_reach, error = safe_batfish_query(
                                bf,
                                f"candidate_flow_{flow_name}",
                                lambda: bf.q.traceroute(
                                    startLocation=subnet,
                                    headers=HeaderConstraints(
                                        dstIps=dst,
                                        dstPorts=str(port) if port else None,
                                        ipProtocols=["tcp"]
                                    )
                                ),
                                timeout=15
                            )
                            
                            candidate_works = False
                            if error:
                                logger.debug(f"Candidate test failed for {flow_name}: {error}")
                            elif candidate_reach is not None and not candidate_reach.empty:
                                traces = candidate_reach.iloc[0].get("Traces", [])
                                if traces:
                                    disposition = str(traces[0].disposition) if hasattr(traces[0], 'disposition') else ""
                                    candidate_works = "ACCEPT" in disposition.upper()
                        except Exception as e:
                            logger.debug(f"Candidate test failed for {flow_name}: {e}")
                            candidate_works = False
                        
                        # Check for differences
                        if base_works and not candidate_works:
                            lost_reachability.append({
                                "flow": flow_name,
                                "source": subnet,
                                "destination": dst,
                                "port": port,
                                "severity": "HIGH",
                                "impact": "Connectivity will be lost"
                            })
                        elif not base_works and candidate_works:
                            new_reachability.append({
                                "flow": flow_name,
                                "source": subnet,
                                "destination": dst,
                                "port": port,
                                "severity": "INFO",
                                "impact": "New connectivity enabled"
                            })
            
            except Exception as e:
                logger.warning(f"Could not run differential analysis: {e}")
            
            # 3. Calculate risk level
            total_breaking = len(breaking_changes)
            total_lost = len(lost_reachability)
            total_new = len(new_reachability)
            
            if total_breaking > 0:
                risk_level = "CRITICAL"
                risk_summary = f"{total_breaking} critical flow(s) will break"
            elif total_lost > 5:
                risk_level = "HIGH"
                risk_summary = f"{total_lost} connectivity paths will be lost"
            elif total_lost > 0:
                risk_level = "MEDIUM"
                risk_summary = f"{total_lost} connectivity paths will be lost"
            elif total_new > 0:
                risk_level = "LOW"
                risk_summary = f"Change opens {total_new} new paths (review for security)"
            else:
                risk_level = "SAFE"
                risk_summary = "No reachability impact detected"
            
            # Generate recommendations
            recommendations = []
            if total_breaking > 0:
                recommendations.append("DO NOT DEPLOY - Critical flows will break")
            elif total_lost > 10:
                recommendations.append("HIGH RISK - Review lost connectivity carefully")
            elif total_new > 10:
                recommendations.append("Review new connectivity for security implications")
            else:
                recommendations.append("Change appears safe to deploy")
            
            logger.info(f"Change impact analysis complete:")
            logger.info(f"  - Risk Level: {risk_level}")
            logger.info(f"  - Breaking Changes: {total_breaking}")
            logger.info(f"  - Lost Reachability: {total_lost}")
            logger.info(f"  - New Reachability: {total_new}")
            
            return {
                "ok": True,
                "risk_level": risk_level,
                "risk_summary": risk_summary,
                "breaking_changes": breaking_changes,
                "lost_reachability": lost_reachability,
                "new_reachability": new_reachability,
                "unchanged_flows": len(unchanged_flows),
                "recommendations": recommendations,
                "warnings": warnings,
                "summary": f"Risk: {risk_level} | {total_breaking} breaking, {total_lost} lost, {total_new} new"
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
        logger.error(f"Error in change impact analysis: {error_msg}", exc_info=True)
        
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
            "breaking_changes": [],
            "lost_reachability": [],
            "new_reachability": [],
            "risk_level": "UNKNOWN"
        }


