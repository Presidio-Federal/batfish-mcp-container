"""
Batfish Finalize AWS Snapshot Tool
Consolidates all staged AWS data chunks into a single aws.json and initializes the Batfish snapshot.
"""

import os
import json
import tempfile
import shutil
import logging
import re
from typing import Dict, Any, Union, Optional, List
from pydantic import BaseModel, Field
from pybatfish.client.session import Session

# Configure logging
logger = logging.getLogger(__name__)


class FinalizeAwsSnapshotInput(BaseModel):
    """Input model for finalizing AWS snapshot."""
    snapshot_name: str = Field(..., description="Snapshot identifier (must match the one used in add_aws_data_chunk)")
    host: str = Field("localhost", description="Batfish host to connect to")
    clear_staging: bool = Field(True, description="Clear staging directory after successful initialization")


class FinalizeAwsSnapshotOutput(BaseModel):
    """Output model for finalizing AWS snapshot."""
    ok: bool = Field(..., description="Whether the operation was successful")
    snapshot: str = Field(..., description="Snapshot identifier")
    network: str = Field(..., description="Logical network name")
    region: str = Field(..., description="AWS region")
    resources_consolidated: Dict[str, int] = Field(..., description="Count of each resource type consolidated")


class FinalizeAwsSnapshotTool:
    """Tool for consolidating staged AWS data chunks and initializing Batfish snapshot."""
    
    # Required AWS resource types - Batfish expects these to be present (can be empty arrays)
    REQUIRED_RESOURCE_TYPES = [
        "Vpcs",
        "Subnets", 
        "RouteTables",
        "InternetGateways",
        "NatGateways",
        "SecurityGroups",
        "NetworkAcls",
        "NetworkInterfaces",
        "Reservations"
    ]
    
    def __init__(self):
        """Initialize the tool with base staging directory."""
        self.base_staging_dir = "/tmp/batfish_aws_staging"
    
    def _sanitize_name(self, name: str) -> str:
        """
        Sanitize AWS resource names to be Batfish-compatible.
        
        Batfish node names must follow specific grammar rules:
        - Cannot start with digits or hyphens
        - Dots have special meaning (field separators)
        - Hyphens at certain positions cause parsing issues
        
        Strategy:
        - Replace dots with underscores
        - Replace consecutive hyphens with single underscore
        - Add prefix if starts with digit or hyphen
        - Keep alphanumeric and single underscores/hyphens
        
        Args:
            name: Original AWS resource name
            
        Returns:
            Sanitized name safe for Batfish
        """
        if not name:
            return "unnamed_resource"
        
        # Replace dots with underscores (dots are field separators in Batfish)
        sanitized = name.replace(".", "_")
        
        # Replace multiple consecutive hyphens with single underscore
        sanitized = re.sub(r'-+', '_', sanitized)
        
        # Replace any remaining problematic characters with underscores
        sanitized = re.sub(r'[^a-zA-Z0-9_-]', '_', sanitized)
        
        # If starts with digit or hyphen, add prefix
        if sanitized and (sanitized[0].isdigit() or sanitized[0] in '-_'):
            sanitized = f"aws_{sanitized}"
        
        # Ensure we have a valid name
        if not sanitized or sanitized.strip('_') == '':
            sanitized = f"aws_resource_{hash(name) % 10000}"
        
        return sanitized
    
    def _sanitize_resource_names(self, data: Any, path: str = "") -> Any:
        """
        Recursively sanitize all name-related fields in AWS data structures.
        
        This prevents Batfish from crashing when parsing resource names with special characters.
        
        Args:
            data: AWS data structure (dict, list, or primitive)
            path: Current path in data structure (for logging)
            
        Returns:
            Sanitized data structure
        """
        if isinstance(data, dict):
            sanitized = {}
            for key, value in data.items():
                # Sanitize fields that typically contain resource names, IDs, or endpoints
                # This includes ANY field that might become a Batfish node name
                if key in ['DnsName', 'PrivateDnsName', 'PublicDnsName', 'Endpoint', 
                          'HostName', 'Name', 'DomainName', 'NodeName', 'Address',
                          'DBInstanceIdentifier', 'CacheClusterId', 'ReplicationGroupId',
                          'LoadBalancerName', 'TargetGroupName', 'FunctionName',
                          'ClusterIdentifier', 'DBClusterIdentifier', 'DomainEndpoint',
                          'Arn', 'ResourceName', 'ResourceId', 'Id']:
                    if isinstance(value, str):
                        original = value
                        sanitized[key] = self._sanitize_name(value)
                        if original != sanitized[key]:
                            logger.debug(f"Sanitized {path}.{key}: '{original}' -> '{sanitized[key]}'")
                    else:
                        sanitized[key] = value
                # Handle Tags specially - sanitize Value if Key is 'Name'
                elif key == 'Tags' and isinstance(value, list):
                    sanitized_tags = []
                    for tag in value:
                        if isinstance(tag, dict) and tag.get('Key') == 'Name':
                            tag_copy = tag.copy()
                            if 'Value' in tag_copy:
                                original = tag_copy['Value']
                                tag_copy['Value'] = self._sanitize_name(original)
                                if original != tag_copy['Value']:
                                    logger.debug(f"Sanitized {path}.Tags.Name: '{original}' -> '{tag_copy['Value']}'")
                            sanitized_tags.append(tag_copy)
                        else:
                            sanitized_tags.append(tag)
                    sanitized[key] = sanitized_tags
                else:
                    # Recursively process nested structures
                    sanitized[key] = self._sanitize_resource_names(value, f"{path}.{key}" if path else key)
            return sanitized
        elif isinstance(data, list):
            return [self._sanitize_resource_names(item, f"{path}[{i}]") for i, item in enumerate(data)]
        else:
            return data
    
    def _find_staging_directory(self, snapshot_name: str) -> Optional[str]:
        """
        Find the staging directory for a given snapshot name.
        Returns the full path if found, None otherwise.
        """
        if not os.path.exists(self.base_staging_dir):
            return None
        
        # List all staging directories and find one that matches the snapshot name
        for dirname in os.listdir(self.base_staging_dir):
            dir_path = os.path.join(self.base_staging_dir, dirname)
            if not os.path.isdir(dir_path):
                continue
            
            # Check metadata to see if this is the right snapshot
            metadata_path = os.path.join(dir_path, "_metadata.json")
            if os.path.exists(metadata_path):
                try:
                    with open(metadata_path, "r") as f:
                        metadata = json.load(f)
                    
                    if metadata.get("snapshot_name") == snapshot_name:
                        return dir_path
                except Exception:
                    continue
        
        return None
    
    def execute(self, input_data: Union[Dict[str, Any], FinalizeAwsSnapshotInput]) -> Dict[str, Any]:
        """
        Consolidate all staged AWS data chunks into a single aws.json file and initialize Batfish snapshot.
        
        Automatically discovers the staging directory, network name, and region from metadata.
        You only need to provide the snapshot_name you used when adding chunks.
        
        Args:
            input_data: Input parameters - only snapshot_name is required
            
        Returns:
            Dictionary containing operation status and consolidation details
        """
        # Handle input as either dictionary or FinalizeAwsSnapshotInput object
        if isinstance(input_data, dict):
            try:
                # Strip whitespace from string inputs before validation
                if "snapshot_name" in input_data and isinstance(input_data["snapshot_name"], str):
                    input_data["snapshot_name"] = input_data["snapshot_name"].strip()
                
                input_model = FinalizeAwsSnapshotInput(**input_data)
            except Exception as e:
                return {
                    "ok": False,
                    "error": f"Invalid input parameters: {str(e)}"
                }
        else:
            input_model = input_data
        
        # Extract values from the model and strip whitespace
        snapshot_name = input_model.snapshot_name.strip() if isinstance(input_model.snapshot_name, str) else input_model.snapshot_name
        host = input_model.host.strip() if isinstance(input_model.host, str) else input_model.host
        clear_staging = input_model.clear_staging
        
        logger.info(f"Finalizing AWS snapshot '{snapshot_name}'")
        
        try:
            # Find the staging directory automatically
            staging_dir = self._find_staging_directory(snapshot_name)
            
            if not staging_dir:
                return {
                    "ok": False,
                    "error": f"No staging directory found for snapshot '{snapshot_name}'. Use batfish_add_aws_data_chunk first."
                }
            
            logger.info(f"Found staging directory: {staging_dir}")
            
            # Read metadata to get network name and region
            metadata_path = os.path.join(staging_dir, "_metadata.json")
            if not os.path.exists(metadata_path):
                return {
                    "ok": False,
                    "error": f"No metadata found in staging directory. Staging may be corrupted."
                }
            
            with open(metadata_path, "r") as f:
                metadata = json.load(f)
            
            # Extract network name and region from metadata
            network_name = metadata.get("network_name", snapshot_name)
            region = metadata.get("region")
            
            if not region:
                return {
                    "ok": False,
                    "error": "Region not found in metadata. Staging may be corrupted."
                }
            
            logger.info(f"Network: {network_name}, Region: {region}")
            logger.info(f"Found {len(metadata['chunks'])} chunk types: {metadata['chunks']}")
            
            # Consolidate all chunks into a single AWS data structure
            # Initialize with empty arrays for all required resource types
            consolidated_data = {rt: [] for rt in self.REQUIRED_RESOURCE_TYPES}
            resource_counts = {}
            
            for resource_type in metadata["chunks"]:
                chunk_file = os.path.join(staging_dir, f"{resource_type}.json")
                
                if not os.path.exists(chunk_file):
                    logger.warning(f"Chunk file not found: {chunk_file}")
                    continue
                
                with open(chunk_file, "r") as f:
                    chunk_data = json.load(f)
                
                # Overwrite the empty array with actual data
                consolidated_data[resource_type] = chunk_data
                resource_counts[resource_type] = len(chunk_data) if isinstance(chunk_data, list) else 1
                
                logger.info(f"Loaded {resource_type}: {resource_counts[resource_type]} items")
            
            # Log which required types are missing (will use empty arrays)
            missing_types = [rt for rt in self.REQUIRED_RESOURCE_TYPES if rt not in metadata["chunks"]]
            if missing_types:
                logger.warning(f"Missing resource types (will use empty arrays): {missing_types}")
                for rt in missing_types:
                    resource_counts[rt] = 0
            
            # CRITICAL: Sanitize all resource names to prevent Batfish crashes
            logger.info("Sanitizing AWS resource names to prevent Batfish parsing errors...")
            sanitized_data = self._sanitize_resource_names(consolidated_data)
            logger.info("Resource name sanitization complete")
            
            # Create temporary directory structure for Batfish
            temp_dir = tempfile.mkdtemp()
            
            # Create AWS directory structure: aws_configs/<region>/
            aws_region_dir = os.path.join(temp_dir, "aws_configs", region)
            os.makedirs(aws_region_dir, exist_ok=True)
            
            logger.info(f"Created temporary directory: {temp_dir}")
            logger.info(f"Created AWS region directory: aws_configs/{region}/")
            
            # Write consolidated aws.json file
            # Remove any metadata fields (keys starting with '_') - Batfish doesn't expect these
            aws_api_data = {k: v for k, v in sanitized_data.items() if not k.startswith('_')}
            
            aws_json_path = os.path.join(aws_region_dir, "aws.json")
            with open(aws_json_path, "w") as f:
                json.dump(aws_api_data, f, indent=2)
            
            logger.info(f"Wrote consolidated AWS data to: aws_configs/{region}/aws.json")
            logger.info(f"AWS data contains: {', '.join(aws_api_data.keys())}")
            
            # Initialize Batfish session with the provided host
            logger.info(f"Using Batfish host: {host}")
            bf = Session(host=host)
            
            try:
                # Set network in Batfish
                bf.set_network(network_name)
                logger.info(f"Set Batfish network to: {network_name}")
                
                # Initialize snapshot
                bf.init_snapshot(temp_dir, name=snapshot_name, overwrite=True)
                logger.info(f"Initialized Batfish snapshot: {snapshot_name}")
                
                # Clean up temporary directory
                shutil.rmtree(temp_dir)
                logger.info(f"Cleaned up temporary directory: {temp_dir}")
                
                # Clear staging directory if requested
                if clear_staging:
                    shutil.rmtree(staging_dir)
                    logger.info(f"Cleared staging directory: {staging_dir}")
                
                # Return success response
                return {
                    "ok": True,
                    "snapshot": snapshot_name,
                    "network": network_name,
                    "region": region,
                    "resources_consolidated": resource_counts,
                    "total_resource_types": len(resource_counts)
                }
            finally:
                # CRITICAL: Always close the session to prevent hanging
                try:
                    bf.delete_session()
                    logger.info("Closed Batfish session")
                except Exception as close_error:
                    logger.warning(f"Error closing Batfish session: {close_error}")
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error finalizing AWS snapshot: {error_msg}")
            
            # Clean up Batfish session if it exists
            if 'bf' in locals():
                try:
                    bf.delete_session()
                    logger.info("Closed Batfish session after error")
                except Exception:
                    pass
            
            # Clean up temporary directory if it exists
            if 'temp_dir' in locals() and os.path.exists(temp_dir):
                try:
                    shutil.rmtree(temp_dir)
                    logger.info(f"Cleaned up temporary directory after error: {temp_dir}")
                except Exception:
                    pass
            
            return {
                "ok": False,
                "error": error_msg
            }


# Create singleton instance for FastMCP
finalize_aws_snapshot_tool = FinalizeAwsSnapshotTool()

# Module-level execute function for imports
def execute(input_data: Union[Dict[str, Any], FinalizeAwsSnapshotInput]) -> Dict[str, Any]:
    """Module-level execute function."""
    return finalize_aws_snapshot_tool.execute(input_data)

