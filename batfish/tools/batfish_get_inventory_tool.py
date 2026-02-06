"""
Batfish Get Inventory Tool
Returns inventory information (nodes, interfaces, VRFs, or routes) from a Batfish snapshot.
"""

import os
import logging
import json
from typing import Dict, Any, Union, List
from enum import Enum
from pydantic import BaseModel, Field
from pybatfish.client.session import Session

# Configure logging
logger = logging.getLogger(__name__)

# No global Batfish session - will be created per request


class ResourceType(str, Enum):
    """Enum for inventory resource types."""
    NODES = "nodes"
    INTERFACES = "interfaces"
    VRFS = "vrfs"
    ROUTES = "routes"


class GetInventoryInput(BaseModel):
    """Input model for Batfish inventory retrieval."""
    network: str = Field(..., description="Logical network name")
    snapshot: str = Field(..., description="Snapshot identifier")
    resource: ResourceType = Field(..., description="Resource type to retrieve (nodes, interfaces, vrfs, routes)")
    host: str = Field("localhost", description="Batfish host to connect to")


class GetInventoryOutput(BaseModel):
    """Output model for Batfish inventory."""
    items: List[Dict[str, Any]] = Field(..., description="Array of inventory records")


class BatfishEncoder(json.JSONEncoder):
    """Custom JSON encoder for Batfish objects."""
    def default(self, obj):
        # Convert any non-serializable objects to strings
        try:
            return super().default(obj)
        except TypeError:
            return str(obj)


def dataframe_to_serializable(df):
    """
    Convert a pandas DataFrame to a serializable format,
    handling Batfish-specific objects.
    """
    if df.empty:
        return []
    
    # First convert to dict
    records = df.to_dict(orient="records")
    
    # Then convert to JSON and back to handle any non-serializable objects
    json_str = json.dumps(records, cls=BatfishEncoder)
    return json.loads(json_str)


class GetInventoryTool:
    """Tool for retrieving inventory information from a Batfish snapshot."""
    
    def _get_nodes(self, bf: Session) -> List[Dict[str, Any]]:
        """Retrieve node properties from Batfish."""
        logger.info("Retrieving node inventory")
        result_df = bf.q.nodeProperties().answer().frame()
        
        # Select specific columns
        if not result_df.empty and all(col in result_df.columns for col in ["Node", "Hostname", "Configuration_Format"]):
            result_df = result_df[["Node", "Hostname", "Configuration_Format"]]
        
        return dataframe_to_serializable(result_df)
    
    def _get_interfaces(self, bf: Session) -> List[Dict[str, Any]]:
        """Retrieve interface properties from Batfish."""
        logger.info("Retrieving interface inventory")
        result_df = bf.q.interfaceProperties().answer().frame()
        
        # Select specific columns
        if not result_df.empty and all(col in result_df.columns for col in ["Interface", "Primary_Address", "VRF"]):
            result_df = result_df[["Interface", "Primary_Address", "VRF"]]
        
        return dataframe_to_serializable(result_df)
    
    def _get_vrfs(self, bf: Session) -> List[Dict[str, Any]]:
        """Retrieve VRF properties from Batfish."""
        logger.info("Retrieving VRF inventory")
        result_df = bf.q.vrfProperties().answer().frame()
        
        # Select specific columns
        if not result_df.empty and all(col in result_df.columns for col in ["Node", "VRF"]):
            result_df = result_df[["Node", "VRF"]]
        
        return dataframe_to_serializable(result_df)
    
    def _get_routes(self, bf: Session) -> List[Dict[str, Any]]:
        """Retrieve routes from Batfish."""
        logger.info("Retrieving routes inventory")
        result_df = bf.q.routes().answer().frame()
        
        # Select specific columns
        if not result_df.empty and all(col in result_df.columns for col in ["Node", "Network", "Next_Hop"]):
            result_df = result_df[["Node", "Network", "Next_Hop"]]
        
        return dataframe_to_serializable(result_df)
    
    def execute(self, input_data: Union[Dict[str, Any], GetInventoryInput]) -> Dict[str, Any]:
        """
        Retrieve inventory information from a Batfish snapshot.
        
        Args:
            input_data: Input parameters including network, snapshot, resource type, and host
                        Can be either a dictionary or GetInventoryInput object
            
        Returns:
            Dictionary containing inventory items
        """
        # Handle input as either dictionary or GetInventoryInput object
        if isinstance(input_data, dict):
            try:
                # Convert dictionary to GetInventoryInput
                input_model = GetInventoryInput(**input_data)
            except Exception as e:
                return {
                    "success": False,
                    "error": f"Invalid input parameters: {str(e)}",
                    "items": []
                }
        else:
            # Assume it's already a GetInventoryInput object
            input_model = input_data
        
        # Extract values from the model
        network = input_model.network
        snapshot = input_model.snapshot
        resource = input_model.resource
        host = input_model.host
        
        logger.info(f"Getting inventory '{resource}' for network '{network}', snapshot '{snapshot}'")
        
        try:
            # Initialize Batfish session with the provided host
            logger.info(f"Using Batfish host: {host}")
            bf = Session(host=host)
            
            # Set network and snapshot in Batfish
            bf.set_network(network)
            logger.info(f"Set Batfish network to: {network}")
            
            bf.set_snapshot(snapshot)
            logger.info(f"Set Batfish snapshot to: {snapshot}")
            
            # Get inventory based on resource type
            if resource == ResourceType.NODES:
                items = self._get_nodes(bf)
            elif resource == ResourceType.INTERFACES:
                items = self._get_interfaces(bf)
            elif resource == ResourceType.VRFS:
                items = self._get_vrfs(bf)
            elif resource == ResourceType.ROUTES:
                items = self._get_routes(bf)
            else:
                # This should not happen due to Pydantic validation, but just in case
                return {
                    "success": False,
                    "error": f"Unknown resource type: {resource}",
                    "items": []
                }
            
            logger.info(f"Retrieved {len(items)} {resource} items")
            
            # Return inventory items
            return {
                "success": True,
                "items": items
            }
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error retrieving inventory: {error_msg}")
            
            # Return error response
            return {
                "success": False,
                "error": error_msg,
                "items": []
            }


# Create singleton instance for FastMCP
get_inventory_tool = GetInventoryTool()
