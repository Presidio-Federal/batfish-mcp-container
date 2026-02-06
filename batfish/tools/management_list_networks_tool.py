"""
Management: List Networks Tool
Returns the list of available Batfish networks on the configured Batfish server.
"""

import logging
from typing import Dict, Any, Union
from pydantic import BaseModel, Field
from pybatfish.client.session import Session

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ListNetworksInput(BaseModel):
    """Input model for listing Batfish networks."""
    host: str = Field("localhost", description="Batfish host to connect to")


class ListNetworksOutput(BaseModel):
    """Output model for listing Batfish networks."""
    ok: bool = Field(..., description="Whether the operation was successful")
    networks: list = Field(..., description="List of available network names")


class ListNetworksTool:
    """Tool for listing available Batfish networks."""
    
    def execute(self, input_data: Union[Dict[str, Any], ListNetworksInput]) -> Dict[str, Any]:
        """
        List available Batfish networks on the configured Batfish server.
        
        Args:
            input_data: Input parameters including optional host
                        Can be either a dictionary or ListNetworksInput object
            
        Returns:
            Dictionary containing operation status and list of networks
        """
        # Handle input as either dictionary or ListNetworksInput object
        if isinstance(input_data, dict):
            try:
                # Convert dictionary to ListNetworksInput
                input_model = ListNetworksInput(**input_data)
            except Exception as e:
                logger.error(f"Invalid input parameters: {str(e)}")
                return {
                    "ok": False,
                    "error": f"Invalid input parameters: {str(e)}",
                    "networks": []
                }
        else:
            # Assume it's already a ListNetworksInput object
            input_model = input_data
        
        # Extract values from the model
        host = input_model.host
        
        logger.info(f"Listing Batfish networks")
        logger.info(f"Using Batfish host: {host}")
        
        try:
            # Initialize Batfish session with the provided host
            bf = Session(host=host)
            logger.info("Batfish session initialized")
            
            # Get list of networks
            networks = bf.list_networks()
            logger.info(f"Found {len(networks)} networks: {networks}")
            
            # Return success response
            return {
                "ok": True,
                "networks": networks
            }
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error listing Batfish networks: {error_msg}")
            
            # Return error response
            return {
                "ok": False,
                "error": error_msg,
                "networks": []
            }


# Create singleton instance for FastMCP
list_networks_tool = ListNetworksTool()

