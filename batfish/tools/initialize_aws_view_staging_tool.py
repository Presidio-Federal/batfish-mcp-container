"""
Batfish View AWS Staging Tool
Views what AWS data chunks have been staged for a snapshot.
"""

import os
import json
import logging
from typing import Dict, Any, Union, Optional
from pydantic import BaseModel, Field

# Configure logging
logger = logging.getLogger(__name__)


class ViewAwsStagingInput(BaseModel):
    """Input model for viewing AWS staging."""
    snapshot_name: str = Field(..., description="Snapshot identifier (staging key)")
    region: str = Field(..., description="AWS region (e.g., 'us-east-1')")
    network_name: Optional[str] = Field(None, description="Logical network name (defaults to snapshot_name)")


class ViewAwsStagingTool:
    """Tool for viewing AWS data chunks in the staging directory."""
    
    def __init__(self):
        """Initialize the tool with a base staging directory."""
        self.base_staging_dir = "/tmp/batfish_aws_staging"
    
    def execute(self, input_data: Union[Dict[str, Any], ViewAwsStagingInput]) -> Dict[str, Any]:
        """
        View what resource type chunks have been staged for a snapshot.
        
        Args:
            input_data: Input parameters including snapshot_name and region
            
        Returns:
            Dictionary containing staging details and resource counts
        """
        # Handle input as either dictionary or ViewAwsStagingInput object
        if isinstance(input_data, dict):
            try:
                input_model = ViewAwsStagingInput(**input_data)
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
        
        logger.info(f"Viewing AWS staging for snapshot '{snapshot_name}', region '{region}'")
        
        try:
            # Determine staging directory
            staging_key = f"{network_name}_{snapshot_name}_{region}"
            staging_dir = os.path.join(self.base_staging_dir, staging_key)
            
            if not os.path.exists(staging_dir):
                return {
                    "ok": True,
                    "snapshot": snapshot_name,
                    "region": region,
                    "staging_dir": staging_dir,
                    "exists": False,
                    "message": "No staging data found for this snapshot"
                }
            
            # Load metadata
            metadata_path = os.path.join(staging_dir, "_metadata.json")
            if not os.path.exists(metadata_path):
                return {
                    "ok": False,
                    "error": "Staging directory exists but no metadata found"
                }
            
            with open(metadata_path, "r") as f:
                metadata = json.load(f)
            
            # Get resource counts for each chunk
            resource_details = {}
            for resource_type in metadata["chunks"]:
                chunk_file = os.path.join(staging_dir, f"{resource_type}.json")
                if os.path.exists(chunk_file):
                    with open(chunk_file, "r") as f:
                        data = json.load(f)
                        resource_details[resource_type] = {
                            "count": len(data) if isinstance(data, list) else 1,
                            "file_size_kb": round(os.path.getsize(chunk_file) / 1024, 2)
                        }
                else:
                    resource_details[resource_type] = {
                        "count": 0,
                        "error": "File not found"
                    }
            
            logger.info(f"Found {len(metadata['chunks'])} chunks in staging")
            
            return {
                "ok": True,
                "snapshot": snapshot_name,
                "network": metadata.get("network_name", network_name),
                "region": region,
                "staging_dir": staging_dir,
                "exists": True,
                "chunks_staged": metadata["chunks"],
                "total_chunks": len(metadata["chunks"]),
                "resource_details": resource_details
            }
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error viewing AWS staging: {error_msg}")
            
            return {
                "ok": False,
                "error": error_msg
            }


# Create singleton instance for FastMCP
view_aws_staging_tool = ViewAwsStagingTool()

# Module-level execute function for imports
def execute(input_data: Union[Dict[str, Any], ViewAwsStagingInput]) -> Dict[str, Any]:
    """Module-level execute function."""
    return view_aws_staging_tool.execute(input_data)

