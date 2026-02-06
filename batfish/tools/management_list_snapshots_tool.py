"""
Management: List Snapshots Tool
List all snapshots inside a given network.
"""

import logging
from typing import Dict, Any, Union
from pydantic import BaseModel, Field
from pybatfish.client.session import Session

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ListSnapshotsInput(BaseModel):
    """Input model for listing Batfish snapshots."""
    network: str = Field(..., description="Logical network name")
    host: str = Field("localhost", description="Batfish host to connect to")


class ListSnapshotsOutput(BaseModel):
    """Output model for listing Batfish snapshots."""
    ok: bool = Field(..., description="Whether the operation was successful")
    snapshots: list = Field(..., description="List of snapshot names in the network")


class ListSnapshotsTool:
    """Tool for listing snapshots within a Batfish network."""
    
    def execute(self, input_data: Union[Dict[str, Any], ListSnapshotsInput]) -> Dict[str, Any]:
        """
        List all snapshots inside a given network.
        
        Args:
            input_data: Input parameters including network and optional host
                        Can be either a dictionary or ListSnapshotsInput object
            
        Returns:
            Dictionary containing operation status and list of snapshots
        """
        # Handle input as either dictionary or ListSnapshotsInput object
        if isinstance(input_data, dict):
            try:
                # Convert dictionary to ListSnapshotsInput
                input_model = ListSnapshotsInput(**input_data)
            except Exception as e:
                logger.error(f"Invalid input parameters: {str(e)}")
                return {
                    "ok": False,
                    "error": f"Invalid input parameters: {str(e)}",
                    "snapshots": []
                }
        else:
            # Assume it's already a ListSnapshotsInput object
            input_model = input_data
        
        # Extract values from the model
        network = input_model.network
        host = input_model.host
        
        logger.info(f"Listing Batfish snapshots for network '{network}'")
        logger.info(f"Using Batfish host: {host}")
        
        try:
            # Initialize Batfish session with the provided host
            bf = Session(host=host)
            logger.info("Batfish session initialized")
            
            # Set the network
            bf.set_network(network)
            logger.info(f"Set Batfish network to: {network}")
            
            # Get list of snapshots
            snapshots = bf.list_snapshots()
            logger.info(f"Found {len(snapshots)} snapshots in network '{network}': {snapshots}")
            
            # Return success response
            return {
                "ok": True,
                "snapshots": snapshots
            }
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error listing Batfish snapshots: {error_msg}")
            
            # Return error response
            return {
                "ok": False,
                "error": error_msg,
                "snapshots": []
            }


# Create singleton instance for FastMCP
list_snapshots_tool = ListSnapshotsTool()

