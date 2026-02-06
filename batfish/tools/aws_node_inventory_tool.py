"""
Batfish AWS Node Inventory Tool

Returns a highly compact, token-efficient summary of AWS network objects.
Gets data from Batfish's parsed network model.

TOON-style compressed inventory with:
- Object IDs only
- Minimal key fields
- ID references (no nested raw structures)
"""

import logging
import json
from typing import Dict, Any, List, Set
from pydantic import BaseModel, Field
from pybatfish.client.session import Session
from .aws_safety_utils import safe_batfish_query

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class AwsNodeInventoryInput(BaseModel):
    """Input model for AWS node inventory."""
    network: str = Field(..., description="Batfish network name")
    snapshot: str = Field(..., description="Batfish snapshot name")
    host: str = Field("localhost", description="Batfish host to connect to")


def execute(input_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Return AWS inventory from Batfish's parsed network model.
    
    Gets all data from Batfish queries (nodes, interfaces, routes, etc.)
    instead of trying to read raw vendor files.
    
    Args:
        input_data: Dictionary containing network, snapshot
        
    Returns:
        Compressed inventory with IDs and essential fields only
    """
    try:
        # Validate input
        validated_input = AwsNodeInventoryInput(**input_data)
        
        network = validated_input.network
        snapshot = validated_input.snapshot
        host = validated_input.host
        
        logger.info(f"Building AWS inventory from Batfish model for network '{network}', snapshot '{snapshot}'")
        
        # Initialize Batfish session
        bf = Session(host=host)
        
        try:
            bf.set_network(network)
            bf.set_snapshot(snapshot)
            
            # Storage
            vpcs = {}
            subnets = {}
            instances = {}
            security_groups = {}
            enis = {}
            route_tables = {}
            igws = {}
            nat_gws = {}
            
            # Get all nodes
            logger.info("Querying Batfish for nodes...")
            nodes_df, error = safe_batfish_query(
                bf,
                "nodeProperties query",
                lambda: bf.q.nodeProperties(),
                timeout=30
            )
            
            if error or nodes_df is None or nodes_df.empty:
                logger.warning(f"No nodes found: {error}")
                return {
                    "ok": True,
                    "vpcs": {},
                    "subnets": {},
                    "instances": {},
                    "security_groups": {},
                    "enis": {},
                    "route_tables": {},
                    "internet_gateways": {},
                    "nat_gateways": {},
                    "summary": "0 objects found"
                }
            
            logger.info(f"Found {len(nodes_df)} nodes")
            
            # Parse nodes by type
            for _, row in nodes_df.iterrows():
                node = str(row.get("Node", ""))
                
                if node.startswith("vpc-"):
                    vpcs[node] = {"subnets": []}
                elif node.startswith("subnet-"):
                    subnets[node] = {"vpc": "unknown", "instances": [], "enis": [], "type": "unknown"}
                elif node.startswith("i-"):
                    instances[node] = {"subnet": "unknown", "state": "running", "active_in_batfish": True}
                elif node.startswith("igw-"):
                    igws[node] = {"vpc": "unknown"}
                elif node.startswith("nat-"):
                    nat_gws[node] = {"subnet": "unknown"}
                elif node.startswith("eni-"):
                    enis[node] = {"subnet": "unknown", "instance": None}
            
            # Get interfaces to enrich data
            logger.info("Querying for interfaces...")
            interfaces_df, error = safe_batfish_query(
                bf,
                "interfaceProperties query",
                lambda: bf.q.interfaceProperties(),
                timeout=30
            )
            
            if interfaces_df is not None and not interfaces_df.empty:
                for _, row in interfaces_df.iterrows():
                    interface = row.get("Interface", {})
                    if hasattr(interface, 'hostname'):
                        hostname = str(interface.hostname)
                        primary_addr = str(row.get("Primary_Address", ""))
                        
                        # Add IP info to instances/ENIs
                        if hostname.startswith("i-") and hostname in instances:
                            instances[hostname]["private_ip"] = primary_addr.split('/')[0] if '/' in primary_addr else primary_addr
                        elif hostname.startswith("eni-") and hostname in enis:
                            enis[hostname]["private_ip"] = primary_addr.split('/')[0] if '/' in primary_addr else primary_addr
            
            # Get security groups from namedStructures or filterTable
            logger.info("Querying for security groups...")
            try:
                # Security groups in AWS Batfish only appear if they're attached to active resources
                # Since all instances are stopped, we won't find any SGs in the active model
                # We can only see Network ACLs which are always present
                filters_df, error = safe_batfish_query(
                    bf,
                    "searchFilters query",
                    lambda: bf.q.searchFilters(action="permit"),
                    timeout=20
                )
                
                if filters_df is not None and not filters_df.empty:
                    unique_filters = filters_df['Filter_Name'].unique()
                    for filter_name in unique_filters:
                        filter_name = str(filter_name)
                        # Only Network ACLs show up when instances are stopped
                        if filter_name.startswith("acl-"):
                            if filter_name not in security_groups:
                                security_groups[filter_name] = {
                                    "name": filter_name,
                                    "type": "network_acl",
                                    "rules": 0
                                }
                    
                    logger.info(f"Found {len(security_groups)} network ACLs (Security Groups require running instances to appear)")
            except Exception as e:
                logger.warning(f"Could not get filters: {e}")
            
            # Get route tables
            logger.info("Querying for routes...")
            routes_df, error = safe_batfish_query(
                bf,
                "routes query",
                lambda: bf.q.routes(),
                timeout=30
            )
            
            if routes_df is not None and not routes_df.empty:
                route_table_nodes = set()
                for _, row in routes_df.iterrows():
                    node = str(row.get("Node", ""))
                    if node.startswith("rtb-") or "route" in node.lower():
                        route_table_nodes.add(node)
                
                for rtb in route_table_nodes:
                    if rtb not in route_tables:
                        route_tables[rtb] = {"routes": 0}
            
            # Calculate totals
            total_objects = (
                len(vpcs) + len(subnets) + len(instances) + 
                len(security_groups) + len(enis) + 
                len(route_tables) + len(igws) + len(nat_gws)
            )
            
            logger.info(f"Inventory complete: {total_objects} objects")
            logger.info(f"  VPCs: {len(vpcs)}, Subnets: {len(subnets)}, Instances: {len(instances)}")
            logger.info(f"  Security Groups: {len(security_groups)}, ENIs: {len(enis)}")
            logger.info(f"  Route Tables: {len(route_tables)}, IGWs: {len(igws)}, NAT GWs: {len(nat_gws)}")
            
            return {
                "ok": True,
                "vpcs": vpcs,
                "subnets": subnets,
                "instances": instances,
                "security_groups": security_groups,
                "enis": enis,
                "route_tables": route_tables,
                "internet_gateways": igws,
                "nat_gateways": nat_gws,
                "summary": f"{total_objects} objects: {len(vpcs)} VPCs, {len(subnets)} subnets, {len(instances)} instances, {len(security_groups)} ACLs/filters",
                "warning": "Note: Batfish only shows active network resources. Security Groups attached to stopped instances will not appear. Only Network ACLs are visible."
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
        logger.error(f"Error building AWS inventory: {error_msg}", exc_info=True)
        
        # Clean up session on error
        if 'bf' in locals():
            try:
                bf.delete_session()
                logger.info("Closed Batfish session after error")
            except Exception:
                pass
        
        return {
            "ok": False,
            "error": error_msg
        }



# Create tool instance
class AwsNodeInventoryTool:
    """Tool for getting AWS node inventory from Batfish."""
    
    def execute(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the inventory tool."""
        return execute(input_data)


# Create singleton instance
aws_node_inventory_tool = AwsNodeInventoryTool()
