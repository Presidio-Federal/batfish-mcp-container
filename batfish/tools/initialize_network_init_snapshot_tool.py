"""
Batfish Init Snapshot Tool
Initializes a Batfish snapshot with provided network configurations.
"""

import os
import tempfile
import shutil
import logging
from typing import Dict, Any, Union
from pydantic import BaseModel, Field
from pybatfish.client.session import Session

# Configure logging
logger = logging.getLogger(__name__)


class InitSnapshotInput(BaseModel):
    """Input model for Batfish init snapshot."""
    network: str = Field(..., description="Logical network name")
    snapshot: str = Field(..., description="Snapshot identifier")
    configs: Dict[str, str] = Field(..., description="Dictionary of {filename: configContent}")
    host: str = Field("localhost", description="Batfish host to connect to")


class InitSnapshotOutput(BaseModel):
    """Output model for Batfish init snapshot."""
    ok: bool = Field(..., description="Whether the operation was successful")
    network: str = Field(..., description="Logical network name")
    snapshot: str = Field(..., description="Snapshot identifier")


class InitSnapshotTool:
    """Tool for initializing a Batfish snapshot with network configurations."""
    
    def execute(self, input_data: Union[Dict[str, Any], InitSnapshotInput]) -> Dict[str, Any]:
        """
        Initialize a Batfish snapshot with provided network configurations.
        
        Args:
            input_data: Input parameters including network name, snapshot identifier, configs, and host
                        Can be either a dictionary or InitSnapshotInput object
            
        Returns:
            Dictionary containing operation status and snapshot details
        """
        # Handle input as either dictionary or InitSnapshotInput object
        if isinstance(input_data, dict):
            try:
                # Convert dictionary to InitSnapshotInput
                input_model = InitSnapshotInput(**input_data)
            except Exception as e:
                return {
                    "ok": False,
                    "error": f"Invalid input parameters: {str(e)}"
                }
        else:
            input_model = input_data
        
        # Extract values from the model
        network = input_model.network
        snapshot = input_model.snapshot
        configs = input_model.configs
        host = input_model.host
        
        logger.info(f"Initializing Batfish snapshot '{snapshot}' for network '{network}'")
        logger.info(f"Received {len(configs)} configuration files")
        
        try:
            # Create temporary directory structure
            temp_dir = tempfile.mkdtemp()
            configs_dir = os.path.join(temp_dir, "configs")
            os.makedirs(configs_dir, exist_ok=True)
            
            logger.info(f"Created temporary directory: {temp_dir}")
            
            # Write configuration files
            for filename, content in configs.items():
                file_path = os.path.join(configs_dir, filename)
                with open(file_path, "w") as f:
                    f.write(content)
                logger.info(f"Wrote configuration file: {filename}")
            
            # Initialize Batfish session with the provided host
            logger.info(f"Using Batfish host: {host}")
            bf = Session(host=host)
            
            # Set network in Batfish
            bf.set_network(network)
            logger.info(f"Set Batfish network to: {network}")
            
            # Initialize snapshot
            bf.init_snapshot(temp_dir, name=snapshot, overwrite=True)
            logger.info(f"Initialized Batfish snapshot: {snapshot}")
            
            # Clean up temporary directory
            shutil.rmtree(temp_dir)
            logger.info(f"Cleaned up temporary directory: {temp_dir}")
            
            # Return success response
            return {
                "ok": True,
                "network": network,
                "snapshot": snapshot
            }
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error initializing Batfish snapshot: {error_msg}")
            
            # Clean up temporary directory if it exists
            if 'temp_dir' in locals():
                try:
                    shutil.rmtree(temp_dir)
                    logger.info(f"Cleaned up temporary directory after error: {temp_dir}")
                except Exception:
                    pass
            
            # Return error response
            return {
                "ok": False,
                "network": network,
                "snapshot": snapshot,
                "error": error_msg
            }


# Create singleton instance for FastMCP
init_snapshot_tool = InitSnapshotTool()
