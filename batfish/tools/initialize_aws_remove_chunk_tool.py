"""
Batfish Remove AWS Chunk Tool
Removes a specific resource type chunk from the AWS staging directory.
"""

import os
import json
import logging
from typing import Dict, Any, Union, Optional
from pydantic import BaseModel, Field

# Configure logging
logger = logging.getLogger(__name__)


class RemoveAwsChunkInput(BaseModel):
    """Input model for removing AWS data chunks."""
    snapshot_name: str = Field(..., description="Snapshot identifier (staging key)")
    region: str = Field(..., description="AWS region (e.g., 'us-east-1')")
    resource_type: str = Field(..., description="AWS resource type to remove (Vpcs, Subnets, Instances, etc.)")
    network_name: Optional[str] = Field(None, description="Logical network name (defaults to snapshot_name)")


class RemoveAwsChunkTool:
    """Tool for removing AWS data chunks from the staging directory."""
    
    def __init__(self):
        """Initialize the tool with a base staging directory."""
        self.base_staging_dir = "/tmp/batfish_aws_staging"
    
    def execute(self, input_data: Union[Dict[str, Any], RemoveAwsChunkInput]) -> Dict[str, Any]:
        """
        Remove a specific resource type chunk from the staging directory.
        
        Args:
            input_data: Input parameters including snapshot_name, region, and resource_type
            
        Returns:
            Dictionary containing operation status
        """
        # Handle input as either dictionary or RemoveAwsChunkInput object
        if isinstance(input_data, dict):
            try:
                input_model = RemoveAwsChunkInput(**input_data)
            except Exception as e:
                return {
                    "ok": False,
                    "error": f"Invalid input parameters: {str(e)}"
                }
        else:
            input_model = input_data
        
        # Extract values from the model
        snapshot_name = input_model.snapshot_name
        network_name = input_model.network_name or snapshot_name
        region = input_model.region
        resource_type = input_model.resource_type
        
        logger.info(f"Removing AWS data chunk: {resource_type} from snapshot '{snapshot_name}', region '{region}'")
        
        try:
            # Determine staging directory
            staging_key = f"{network_name}_{snapshot_name}_{region}"
            staging_dir = os.path.join(self.base_staging_dir, staging_key)
            
            if not os.path.exists(staging_dir):
                return {
                    "ok": False,
                    "error": f"Staging directory not found: {staging_dir}"
                }
            
            # Load metadata
            metadata_path = os.path.join(staging_dir, "_metadata.json")
            if not os.path.exists(metadata_path):
                return {
                    "ok": False,
                    "error": "No metadata found in staging directory"
                }
            
            with open(metadata_path, "r") as f:
                metadata = json.load(f)
            
            # Check if resource type exists
            if resource_type not in metadata["chunks"]:
                return {
                    "ok": False,
                    "error": f"Resource type '{resource_type}' not found in staged chunks. Available: {metadata['chunks']}"
                }
            
            # Remove the chunk file
            chunk_file = os.path.join(staging_dir, f"{resource_type}.json")
            if os.path.exists(chunk_file):
                os.remove(chunk_file)
                logger.info(f"Removed chunk file: {chunk_file}")
            else:
                logger.warning(f"Chunk file not found: {chunk_file}")
            
            # Update metadata
            metadata["chunks"].remove(resource_type)
            with open(metadata_path, "w") as f:
                json.dump(metadata, f, indent=2)
            
            logger.info(f"Removed '{resource_type}' from staging. Remaining chunks: {metadata['chunks']}")
            
            return {
                "ok": True,
                "snapshot": snapshot_name,
                "region": region,
                "removed_resource_type": resource_type,
                "remaining_chunks": metadata["chunks"],
                "staging_dir": staging_dir
            }
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error removing AWS data chunk: {error_msg}")
            
            return {
                "ok": False,
                "error": error_msg
            }


# Create singleton instance for FastMCP
remove_aws_chunk_tool = RemoveAwsChunkTool()

# Module-level execute function for imports
def execute(input_data: Union[Dict[str, Any], RemoveAwsChunkInput]) -> Dict[str, Any]:
    """Module-level execute function."""
    return remove_aws_chunk_tool.execute(input_data)

