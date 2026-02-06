"""
Management: Delete Snapshot Tool
Delete a snapshot within a network.
"""

import logging
from typing import Dict, Any, Union
from pydantic import BaseModel, Field
from pybatfish.client.session import Session

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DeleteSnapshotInput(BaseModel):
    """Input model for deleting a Batfish snapshot."""
    network: str = Field(..., description="Logical network name")
    snapshot: str = Field(..., description="Snapshot identifier to delete")
    host: str = Field("localhost", description="Batfish host to connect to")


class DeleteSnapshotOutput(BaseModel):
    """Output model for deleting a Batfish snapshot."""
    ok: bool = Field(..., description="Whether the operation was successful")
    deleted: str = Field(..., description="Name of the deleted snapshot")


class DeleteSnapshotTool:
    """Tool for deleting a snapshot within a Batfish network."""
    
    def execute(self, input_data: Union[Dict[str, Any], DeleteSnapshotInput]) -> Dict[str, Any]:
        """
        Delete a snapshot within a network.
        
        Args:
            input_data: Input parameters including network, snapshot, and optional host
                        Can be either a dictionary or DeleteSnapshotInput object
            
        Returns:
            Dictionary containing operation status and deleted snapshot name
        """
        # Handle input as either dictionary or DeleteSnapshotInput object
        if isinstance(input_data, dict):
            try:
                # Convert dictionary to DeleteSnapshotInput
                input_model = DeleteSnapshotInput(**input_data)
            except Exception as e:
                logger.error(f"Invalid input parameters: {str(e)}")
                return {
                    "ok": False,
                    "error": f"Invalid input parameters: {str(e)}"
                }
        else:
            # Assume it's already a DeleteSnapshotInput object
            input_model = input_data
        
        # Extract values from the model
        network = input_model.network
        snapshot = input_model.snapshot
        host = input_model.host
        
        logger.info(f"Deleting Batfish snapshot '{snapshot}' from network '{network}'")
        logger.info(f"Using Batfish host: {host}")
        
        try:
            # Initialize Batfish session with the provided host
            bf = Session(host=host)
            logger.info("Batfish session initialized")
            
            # Set the network
            bf.set_network(network)
            logger.info(f"Set Batfish network to: {network}")
            
            # Delete the snapshot
            bf.delete_snapshot(snapshot)
            logger.info(f"Successfully deleted snapshot '{snapshot}' from network '{network}'")
            
            # Return success response
            return {
                "ok": True,
                "deleted": snapshot
            }
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error deleting Batfish snapshot: {error_msg}")
            
            # Return error response
            return {
                "ok": False,
                "error": error_msg
            }


# Create singleton instance for FastMCP
delete_snapshot_tool = DeleteSnapshotTool()

