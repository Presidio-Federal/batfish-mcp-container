"""
Batfish Cleanup Tool
Cleans up after a test run by deleting snapshots and removing temp directories.
"""

import os
import shutil
import glob
import logging
from typing import Dict, Any, Union
from pydantic import BaseModel, Field
from pybatfish.client.session import Session

# Configure logging
logger = logging.getLogger(__name__)

# No global Batfish session - will be created per request


class CleanupInput(BaseModel):
    """Input model for Batfish cleanup."""
    network: str = Field(..., description="Logical network name")
    snapshot: str = Field(..., description="Snapshot identifier")
    host: str = Field("localhost", description="Batfish host to connect to")


class CleanupOutput(BaseModel):
    """Output model for Batfish cleanup."""
    ok: bool = Field(..., description="Whether the operation was successful")
    network: str = Field(..., description="Logical network name")
    snapshot: str = Field(..., description="Snapshot identifier")


class CleanupTool:
    """Tool for cleaning up Batfish snapshots and temporary directories."""
    
    def _cleanup_temp_directories(self, network: str, snapshot: str) -> Dict[str, Any]:
        """
        Clean up temporary directories used for Batfish snapshots.
        
        Args:
            network: Logical network name
            snapshot: Snapshot identifier
            
        Returns:
            Dictionary containing cleanup details
        """
        cleanup_details = {
            "temp_dirs_removed": [],
            "errors": []
        }
        
        # Define patterns to search for temp directories
        temp_patterns = [
            f"/tmp/batfish*{network}*{snapshot}*",
            f"/tmp/batfish*{snapshot}*",
            "/tmp/batfish*"
        ]
        
        # Search for and remove matching directories
        for pattern in temp_patterns:
            try:
                matching_dirs = glob.glob(pattern)
                for dir_path in matching_dirs:
                    if os.path.isdir(dir_path):
                        logger.info(f"Removing temporary directory: {dir_path}")
                        shutil.rmtree(dir_path)
                        cleanup_details["temp_dirs_removed"].append(dir_path)
            except Exception as e:
                error_msg = f"Error cleaning up {pattern}: {str(e)}"
                logger.error(error_msg)
                cleanup_details["errors"].append(error_msg)
        
        return cleanup_details
    
    def execute(self, input_data: Union[Dict[str, Any], CleanupInput]) -> Dict[str, Any]:
        """
        Clean up Batfish snapshot and temporary directories.
        
        Args:
            input_data: Input parameters including network name, snapshot identifier, and host
                        Can be either a dictionary or CleanupInput object
            
        Returns:
            Dictionary containing operation status and details
        """
        # Handle input as either dictionary or CleanupInput object
        if isinstance(input_data, dict):
            try:
                # Convert dictionary to CleanupInput
                input_model = CleanupInput(**input_data)
            except Exception as e:
                return {
                    "ok": False,
                    "error": f"Invalid input parameters: {str(e)}"
                }
        else:
            # Assume it's already a CleanupInput object
            input_model = input_data
        
        # Extract values from the model
        network = input_model.network
        snapshot = input_model.snapshot
        host = input_model.host
        
        logger.info(f"Cleaning up Batfish snapshot '{snapshot}' for network '{network}'")
        
        try:
            # Initialize Batfish session with the provided host
            logger.info(f"Using Batfish host: {host}")
            bf = Session(host=host)
            
            # Set network in Batfish
            bf.set_network(network)
            logger.info(f"Set Batfish network to: {network}")
            
            # Delete snapshot
            try:
                bf.delete_snapshot(snapshot)
                logger.info(f"Deleted Batfish snapshot: {snapshot}")
                snapshot_deleted = True
            except Exception as e:
                error_msg = str(e)
                logger.error(f"Error deleting snapshot: {error_msg}")
                snapshot_deleted = False
            
            # Clean up temporary directories
            temp_cleanup_results = self._cleanup_temp_directories(network, snapshot)
            
            # Return success response
            result = {
                "ok": snapshot_deleted or len(temp_cleanup_results["temp_dirs_removed"]) > 0,
                "network": network,
                "snapshot": snapshot,
                "details": {
                    "snapshot_deleted": snapshot_deleted,
                    "temp_cleanup": temp_cleanup_results
                }
            }
            
            # Add error information if there were any issues
            if not snapshot_deleted or temp_cleanup_results["errors"]:
                errors = []
                if not snapshot_deleted:
                    errors.append(f"Failed to delete snapshot '{snapshot}'")
                if temp_cleanup_results["errors"]:
                    errors.extend(temp_cleanup_results["errors"])
                
                result["warnings"] = errors
            
            return result
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error during cleanup: {error_msg}")
            
            # Return error response
            return {
                "ok": False,
                "network": network,
                "snapshot": snapshot,
                "error": error_msg
            }


# Create singleton instance for FastMCP
cleanup_tool = CleanupTool()
