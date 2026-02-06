"""
Batfish Add AWS Data Chunk Tool
Incrementally adds AWS resource data chunks to a staging directory for later consolidation.
"""

import os
import json
import logging
from typing import Dict, Any, Union, Optional, List
from pydantic import BaseModel, Field

# Configure logging
logger = logging.getLogger(__name__)


class AddAwsDataChunkInput(BaseModel):
    """Input model for adding AWS data chunks."""
    snapshot_name: str = Field(..., description="Snapshot identifier (used as staging key)")
    region: str = Field(..., description="AWS region (e.g., 'us-east-1')")
    resource_type: str = Field(..., description="AWS resource type (Vpcs, Subnets, RouteTables, etc.)")
    data: List[Dict[str, Any]] = Field(..., description="List of AWS resources of this type")
    network_name: Optional[str] = Field(None, description="Logical network name (defaults to snapshot_name)")


class AddAwsDataChunkOutput(BaseModel):
    """Output model for adding AWS data chunks."""
    ok: bool = Field(..., description="Whether the operation was successful")
    snapshot: str = Field(..., description="Snapshot identifier")
    region: str = Field(..., description="AWS region")
    resource_type: str = Field(..., description="Resource type added")
    resource_count: int = Field(..., description="Number of resources added")
    staging_dir: str = Field(..., description="Staging directory path")


class AddAwsDataChunkTool:
    """Tool for incrementally adding AWS data chunks to a staging directory."""
    
    # Define valid resource types and their required fields
    VALID_RESOURCE_TYPES = {
        "Vpcs": ["VpcId", "CidrBlock"],
        "Subnets": ["SubnetId", "VpcId", "CidrBlock"],
        "RouteTables": ["RouteTableId", "VpcId"],
        "InternetGateways": ["InternetGatewayId"],
        "NatGateways": ["NatGatewayId", "VpcId"],
        "SecurityGroups": ["GroupId", "VpcId"],
        "NetworkAcls": ["NetworkAclId", "VpcId"],
        "NetworkInterfaces": ["NetworkInterfaceId", "VpcId"],
        "Reservations": ["ReservationId", "Instances"]
    }
    
    def __init__(self):
        """Initialize the tool with a base staging directory."""
        # Use /tmp for staging - persistent across tool calls within same session
        self.base_staging_dir = "/tmp/batfish_aws_staging"
        os.makedirs(self.base_staging_dir, exist_ok=True)
    
    def _validate_resource_type(self, resource_type: str) -> tuple[bool, str]:
        """Validate that the resource type is known."""
        if resource_type not in self.VALID_RESOURCE_TYPES:
            valid_types = ", ".join(self.VALID_RESOURCE_TYPES.keys())
            return False, f"Invalid resource_type '{resource_type}'. Valid types: {valid_types}"
        return True, ""
    
    def _validate_data_structure(self, resource_type: str, data: List[Dict[str, Any]]) -> tuple[bool, str]:
        """Validate that the data has the expected structure."""
        if not isinstance(data, list):
            return False, f"Data must be a list of {resource_type} objects"
        
        if len(data) == 0:
            logger.warning(f"Empty data array for {resource_type}")
            return True, ""  # Empty is valid
        
        # Check required fields on first item
        required_fields = self.VALID_RESOURCE_TYPES[resource_type]
        first_item = data[0]
        
        if not isinstance(first_item, dict):
            return False, f"Each item in data must be a dictionary. Got: {type(first_item)}"
        
        missing_fields = [field for field in required_fields if field not in first_item]
        if missing_fields:
            return False, f"Missing required fields in {resource_type}: {missing_fields}. Found fields: {list(first_item.keys())}"
        
        # Special validation for Reservations - must have Instances array
        if resource_type == "Reservations":
            instances = first_item.get("Instances", [])
            if not isinstance(instances, list):
                return False, "Reservations must contain an 'Instances' array"
            if len(instances) > 0 and not isinstance(instances[0], dict):
                return False, "Instances array must contain instance dictionaries"
            if len(instances) > 0 and "InstanceId" not in instances[0]:
                return False, "Each Instance must have an 'InstanceId' field"
        
        return True, ""
    
    def _detect_metadata_fields(self, data: List[Dict[str, Any]]) -> List[str]:
        """Detect any metadata fields (starting with _) that should be removed."""
        if not data or not isinstance(data, list) or len(data) == 0:
            return []
        
        first_item = data[0]
        if not isinstance(first_item, dict):
            return []
        
        metadata_fields = [k for k in first_item.keys() if k.startswith('_')]
        return metadata_fields
    
    def execute(self, input_data: Union[Dict[str, Any], AddAwsDataChunkInput]) -> Dict[str, Any]:
        """
        Add a chunk of AWS data to the staging directory.
        
        Each resource type is stored as a separate JSON file in the staging directory.
        Later, batfish_finalize_aws_snapshot will consolidate all chunks into a single aws.json.
        
        Args:
            input_data: Input parameters including snapshot_name, region, resource_type, and data
            
        Returns:
            Dictionary containing operation status and staging details
        """
        # Handle input as either dictionary or AddAwsDataChunkInput object
        if isinstance(input_data, dict):
            # Strip whitespace from string inputs before validation
            for key in ["snapshot_name", "region", "resource_type", "network_name"]:
                if key in input_data and isinstance(input_data[key], str):
                    input_data[key] = input_data[key].strip()
            
            try:
                input_model = AddAwsDataChunkInput(**input_data)
            except Exception as e:
                return {
                    "ok": False,
                    "error": f"Invalid input parameters: {str(e)}"
                }
        else:
            input_model = input_data
        
        # Extract values from the model
        snapshot_name = input_model.snapshot_name.strip() if isinstance(input_model.snapshot_name, str) else input_model.snapshot_name
        network_name = (input_model.network_name.strip() if input_model.network_name and isinstance(input_model.network_name, str) else input_model.network_name) or snapshot_name
        region = input_model.region.strip() if isinstance(input_model.region, str) else input_model.region
        resource_type = input_model.resource_type.strip() if isinstance(input_model.resource_type, str) else input_model.resource_type
        data = input_model.data
        
        logger.info(f"Adding AWS data chunk for snapshot '{snapshot_name}', region '{region}'")
        logger.info(f"Resource type: {resource_type}, count: {len(data)}")
        
        try:
            # Validate resource type
            valid, error_msg = self._validate_resource_type(resource_type)
            if not valid:
                logger.error(f"Validation error: {error_msg}")
                return {
                    "ok": False,
                    "error": error_msg
                }
            
            # Validate data structure
            valid, error_msg = self._validate_data_structure(resource_type, data)
            if not valid:
                logger.error(f"Validation error: {error_msg}")
                return {
                    "ok": False,
                    "error": error_msg
                }
            
            # Check for metadata fields that should be removed
            metadata_fields = self._detect_metadata_fields(data)
            if metadata_fields:
                logger.warning(f"Found metadata fields in {resource_type}: {metadata_fields}")
                logger.warning("These will be filtered out during finalization")
            
            # Create staging directory for this snapshot + region
            staging_key = f"{network_name}_{snapshot_name}_{region}"
            staging_dir = os.path.join(self.base_staging_dir, staging_key)
            os.makedirs(staging_dir, exist_ok=True)
            
            logger.info(f"Using staging directory: {staging_dir}")
            
            # Write metadata file (network name, snapshot name, region)
            metadata_path = os.path.join(staging_dir, "_metadata.json")
            metadata = {
                "network_name": network_name,
                "snapshot_name": snapshot_name,
                "region": region,
                "chunks": []
            }
            
            # Load existing metadata if it exists
            if os.path.exists(metadata_path):
                with open(metadata_path, "r") as f:
                    metadata = json.load(f)
            
            # Add this chunk to metadata
            if resource_type not in metadata["chunks"]:
                metadata["chunks"].append(resource_type)
            
            # Write updated metadata
            with open(metadata_path, "w") as f:
                json.dump(metadata, f, indent=2)
            
            # Write the resource data to a separate file
            chunk_file = os.path.join(staging_dir, f"{resource_type}.json")
            with open(chunk_file, "w") as f:
                json.dump(data, f, indent=2)
            
            logger.info(f"Wrote {len(data)} {resource_type} to {chunk_file}")
            logger.info(f"Total chunks in staging: {len(metadata['chunks'])}")
            
            # Prepare validation info for response
            validation_info = {
                "resource_type_valid": True,
                "structure_valid": True,
                "required_fields_present": True
            }
            
            if metadata_fields:
                validation_info["warnings"] = [f"Metadata fields detected: {metadata_fields}"]
            
            # Return success response
            return {
                "ok": True,
                "snapshot": snapshot_name,
                "region": region,
                "resource_type": resource_type,
                "resource_count": len(data),
                "staging_dir": staging_dir,
                "chunks_staged": metadata["chunks"],
                "validation": validation_info
            }
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error adding AWS data chunk: {error_msg}")
            
            return {
                "ok": False,
                "error": error_msg
            }


# Create singleton instance for FastMCP
add_aws_data_chunk_tool = AddAwsDataChunkTool()

# Module-level execute function for imports
def execute(input_data: Union[Dict[str, Any], AddAwsDataChunkInput]) -> Dict[str, Any]:
    """Module-level execute function."""
    return add_aws_data_chunk_tool.execute(input_data)

