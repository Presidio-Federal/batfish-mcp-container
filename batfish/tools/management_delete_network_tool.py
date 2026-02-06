"""
Management: Delete Network Tool
Delete an entire network from Batfish.
"""

import logging
from typing import Dict, Any, Union
from pydantic import BaseModel, Field
from pybatfish.client.session import Session

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DeleteNetworkInput(BaseModel):
    """Input model for deleting a Batfish network."""
    network: str = Field(..., description="Logical network name to delete")
    host: str = Field("localhost", description="Batfish host to connect to")


class DeleteNetworkOutput(BaseModel):
    """Output model for deleting a Batfish network."""
    ok: bool = Field(..., description="Whether the operation was successful")
    deleted: str = Field(..., description="Name of the deleted network")


class DeleteNetworkTool:
    """Tool for deleting an entire network from Batfish."""
    
    def execute(self, input_data: Union[Dict[str, Any], DeleteNetworkInput]) -> Dict[str, Any]:
        """
        Delete an entire network from Batfish.
        
        Args:
            input_data: Input parameters including network and optional host
                        Can be either a dictionary or DeleteNetworkInput object
            
        Returns:
            Dictionary containing operation status and deleted network name
        """
        # Handle input as either dictionary or DeleteNetworkInput object
        if isinstance(input_data, dict):
            try:
                # Convert dictionary to DeleteNetworkInput
                input_model = DeleteNetworkInput(**input_data)
            except Exception as e:
                logger.error(f"Invalid input parameters: {str(e)}")
                return {
                    "ok": False,
                    "error": f"Invalid input parameters: {str(e)}"
                }
        else:
            # Assume it's already a DeleteNetworkInput object
            input_model = input_data
        
        # Extract values from the model
        network = input_model.network
        host = input_model.host
        
        logger.info(f"Deleting Batfish network '{network}'")
        logger.info(f"Using Batfish host: {host}")
        
        try:
            # Initialize Batfish session with the provided host
            bf = Session(host=host)
            logger.info("Batfish session initialized")
            
            # Delete the network
            bf.delete_network(network)
            logger.info(f"Successfully deleted network '{network}'")
            
            # Return success response
            return {
                "ok": True,
                "deleted": network
            }
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error deleting Batfish network: {error_msg}")
            
            # Return error response
            return {
                "ok": False,
                "error": error_msg
            }


# Create singleton instance for FastMCP
delete_network_tool = DeleteNetworkTool()

