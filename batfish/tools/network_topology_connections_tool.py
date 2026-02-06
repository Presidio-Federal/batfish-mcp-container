"""
Network Topology Connections Tool

Returns Layer 3 network topology connections as a simple connection mapping.
Pure data output - no CML-specific formatting. Agent can use this to create CML links.

Output includes:
- Node A name and interface
- Node B name and interface  
- IP addresses on each side
- Connection type (Layer 3)
"""

import logging
from typing import Dict, Any, List
from pydantic import BaseModel, Field
from pybatfish.client.session import Session

# Import safety utilities
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


class NetworkTopologyConnectionsInput(BaseModel):
    """Input model for topology connections."""
    network: str = Field(..., description="Batfish network name")
    snapshot: str = Field(..., description="Batfish snapshot name")
    host: str = Field(default="localhost", description="Batfish host")
    include_layer1: bool = Field(default=True, description="Include Layer 1 connections if available")


def execute(input_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Return network topology as a list of node-to-node connections.
    
    Provides raw connection data that an agent can use to:
    - Create CML topology links
    - Understand network connectivity
    - Generate network diagrams
    
    Args:
        input_data: Dictionary containing network, snapshot, optional host, and include_layer1
        
    Returns:
        Dictionary with:
        - ok: Success status
        - connections: List of connection objects
        - total_connections: Count of unique connections
        - connection_type: "layer1" or "layer3"
    """
    try:
        # Validate input
        validated_input = NetworkTopologyConnectionsInput(**input_data)
        
        network = validated_input.network
        snapshot = validated_input.snapshot
        host = validated_input.host
        include_layer1 = validated_input.include_layer1
        
        logger.info(f"Retrieving topology connections for network={network}, snapshot={snapshot}")
        
        # Initialize Batfish session
        bf = Session(host=host)
        bf.set_network(network)
        bf.set_snapshot(snapshot)
        
        connections = []
        connection_type = "layer3"  # Default
        
        # Try Layer 1 first if requested
        if include_layer1:
            logger.info("Querying Layer 1 edges...")
            layer1_df, error = safe_batfish_query(
                bf,
                "layer1Edges query",
                lambda: bf.q.layer1Edges(),
                timeout=30
            )
            
            if not error and layer1_df is not None and not layer1_df.empty:
                logger.info(f"Found {len(layer1_df)} Layer 1 connections")
                connection_type = "layer1"
                
                # Process Layer 1 connections
                for _, row in layer1_df.iterrows():
                    interface_str = str(row['Interface'])
                    remote_interface_str = str(row['Remote_Interface'])
                    
                    node_a = interface_str.split('[')[0]
                    interface_a = interface_str.split('[')[1].rstrip(']')
                    node_b = remote_interface_str.split('[')[0]
                    interface_b = remote_interface_str.split('[')[1].rstrip(']')
                    
                    connections.append({
                        "node_a": node_a,
                        "interface_a": interface_a,
                        "node_b": node_b,
                        "interface_b": interface_b,
                        "connection_type": "physical"
                    })
        
        # If no Layer 1 or Layer 1 not requested, use Layer 3
        if not connections:
            logger.info("Querying Layer 3 edges...")
            layer3_df, error = safe_batfish_query(
                bf,
                "layer3Edges query",
                lambda: bf.q.layer3Edges(),
                timeout=30
            )
            
            if error or layer3_df is None or layer3_df.empty:
                return {
                    "ok": False,
                    "error": f"No connectivity data found: {error}",
                    "connections": [],
                    "total_connections": 0
                }
            
            logger.info(f"Found {len(layer3_df)} Layer 3 adjacencies")
            connection_type = "layer3"
            
            # Process Layer 3 connections - deduplicate bidirectional links
            seen_links = set()
            
            for _, row in layer3_df.iterrows():
                interface_str = str(row['Interface'])
                remote_interface_str = str(row['Remote_Interface'])
                
                node_a = interface_str.split('[')[0]
                interface_a = interface_str.split('[')[1].rstrip(']')
                node_b = remote_interface_str.split('[')[0]
                interface_b = remote_interface_str.split('[')[1].rstrip(']')
                
                # Create bidirectional link identifier to avoid duplicates
                link_id = tuple(sorted([(node_a, interface_a), (node_b, interface_b)]))
                
                if link_id not in seen_links:
                    seen_links.add(link_id)
                    
                    # Extract IP addresses if available
                    ips_a = row.get('IPs', [])
                    ips_b = row.get('Remote_IPs', [])
                    
                    # Convert to strings
                    if isinstance(ips_a, list) and ips_a:
                        ip_a = str(ips_a[0]) if ips_a else None
                    else:
                        ip_a = str(ips_a) if ips_a else None
                        
                    if isinstance(ips_b, list) and ips_b:
                        ip_b = str(ips_b[0]) if ips_b else None
                    else:
                        ip_b = str(ips_b) if ips_b else None
                    
                    connection = {
                        "node_a": node_a,
                        "interface_a": interface_a,
                        "node_b": node_b,
                        "interface_b": interface_b,
                        "connection_type": "ip_adjacency"
                    }
                    
                    # Add IP addresses if available
                    if ip_a:
                        connection["ip_a"] = ip_a
                    if ip_b:
                        connection["ip_b"] = ip_b
                    
                    connections.append(connection)
        
        logger.info(f"Processed {len(connections)} unique connections")
        
        # Sort connections by node names for consistent output
        connections_sorted = sorted(connections, key=lambda x: (x['node_a'], x['node_b']))
        
        return {
            "ok": True,
            "connections": connections_sorted,
            "total_connections": len(connections_sorted),
            "connection_type": connection_type,
            "note": "Use node_a/interface_a and node_b/interface_b to create topology links"
        }
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error retrieving topology connections: {error_msg}")
        import traceback
        logger.error(traceback.format_exc())
        return {
            "ok": False,
            "error": error_msg,
            "connections": [],
            "total_connections": 0
        }
