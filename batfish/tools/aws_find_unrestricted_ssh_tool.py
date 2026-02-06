"""
Batfish AWS Find Unrestricted SSH Tool

Finds AWS Security Groups that allow SSH (port 22) from 0.0.0.0/0 or ::/0.
This is a critical security finding - SSH should only be allowed from specific IPs.
"""

import logging
from typing import Dict, Any, List
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


class FindUnrestrictedSshInput(BaseModel):
    """Input model for finding unrestricted SSH access."""
    network: str = Field(..., description="Batfish network name")
    snapshot: str = Field(..., description="Batfish snapshot name")
    host: str = Field("localhost", description="Batfish host to connect to")


def execute(input_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Find AWS Security Groups allowing SSH from 0.0.0.0/0 or ::/0.
    
    Args:
        input_data: Dictionary containing network, snapshot, and optional host
        
    Returns:
        Dictionary with findings of unrestricted SSH access
    """
    try:
        # Validate input
        validated_input = FindUnrestrictedSshInput(**input_data)
        
        network = validated_input.network
        snapshot = validated_input.snapshot
        host = validated_input.host
        
        logger.info(f"Finding unrestricted SSH access in network '{network}', snapshot '{snapshot}'")
        
        # Initialize Batfish session
        bf = Session(host=host)
        
        try:
            bf.set_network(network)
            bf.set_snapshot(snapshot)
            
            # Check if network is active
            network_status = check_network_active(bf)
            warnings = []
            if not network_status.get("has_nodes"):
                warning = network_status.get("warning")
                if warning:
                    warnings.append(warning)
                    logger.warning(warning)
            
            # Search for filters allowing SSH (port 22) on TCP
            logger.info("Querying Batfish for SSH filters...")
            results_df, error = safe_batfish_query(
                bf,
                "searchFilters_SSH",
                lambda: bf.q.searchFilters(
                    headers=HeaderConstraints(
                        dstPorts="22",
                        ipProtocols=["tcp"]
                    ),
                    action="permit"
                ),
                timeout=30
            )
            
            if error:
                warnings.append(error)
                return {
                    "ok": False,
                    "error": error,
                    "count": 0,
                    "unrestricted_count": 0,
                    "warnings": warnings,
                    "findings": []
                }
            
            if results_df is None or results_df.empty:
                logger.info("No SSH rules found")
                return {
                    "ok": True,
                    "count": 0,
                    "unrestricted_count": 0,
                    "message": "No SSH rules found in this snapshot",
                    "warnings": warnings,
                    "findings": []
                }
            
            logger.info(f"Found {len(results_df)} total SSH rules, filtering for unrestricted access...")
            
            # Filter for rules with 0.0.0.0/0 or ::/0 source
            unrestricted = results_df[
                results_df["Flow"].str.contains("0\\.0\\.0\\.0/0|::/0", regex=True, na=False)
            ]
            
            # Extract security group IDs and details
            findings = []
            security_groups = set()
            
            for _, row in unrestricted.iterrows():
                filter_name = row.get("Filter_Name", "")
                flow = row.get("Flow", "")
                action = row.get("Action", "")
                
                # Extract security group ID from filter name (format: sg-xxx)
                if filter_name.startswith("sg-"):
                    sg_id = filter_name
                    security_groups.add(sg_id)
                else:
                    sg_id = "unknown"
                
                finding = {
                    "security_group": sg_id,
                    "filter_name": filter_name,
                    "flow": flow,
                    "action": action,
                    "severity": "HIGH",
                    "issue": "SSH (port 22) is accessible from the internet (0.0.0.0/0 or ::/0)"
                }
                findings.append(finding)
            
            logger.info(f"Found {len(findings)} unrestricted SSH rules across {len(security_groups)} security groups")
            
            return {
                "ok": True,
                "count": len(results_df),
                "unrestricted_count": len(findings),
                "security_groups_affected": sorted(list(security_groups)),
                "severity": "HIGH" if findings else "NONE",
                "message": f"Found {len(findings)} unrestricted SSH rules" if findings else "No unrestricted SSH access found",
                "warnings": warnings,
                "findings": findings
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
        logger.error(f"Error finding unrestricted SSH: {error_msg}", exc_info=True)
        
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
            "count": 0,
            "unrestricted_count": 0,
            "findings": []
        }


