"""
Batfish Init AWS Snapshot Tool
Initializes a Batfish snapshot with AWS Vendor Model JSON files.
"""

import os
import json
import tempfile
import shutil
import logging
import re
from typing import Dict, Any, Union, Optional
from pydantic import BaseModel, Field
from pybatfish.client.session import Session

# Configure logging
logger = logging.getLogger(__name__)


class InitAwsSnapshotInput(BaseModel):
    """Input model for Batfish init AWS snapshot."""
    snapshot_name: str = Field(..., description="Snapshot identifier")
    network_name: Optional[str] = Field(None, description="Logical network name (defaults to snapshot_name)")
    region: str = Field(..., description="AWS region (e.g., 'us-east-1')")
    aws_data: Dict[str, Any] = Field(..., description="Raw AWS API data from aws_collect_all tool")
    host: str = Field("localhost", description="Batfish host to connect to")


class InitAwsSnapshotOutput(BaseModel):
    """Output model for Batfish init AWS snapshot."""
    ok: bool = Field(..., description="Whether the operation was successful")
    snapshot: str = Field(..., description="Snapshot identifier")
    network: str = Field(..., description="Logical network name")
    region: str = Field(..., description="AWS region")


class InitAwsSnapshotTool:
    """Tool for initializing a Batfish snapshot with AWS Vendor Model JSON files."""
    
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
    
    def execute(self, input_data: Union[Dict[str, Any], InitAwsSnapshotInput]) -> Dict[str, Any]:
        """
        Initialize a Batfish snapshot with AWS Vendor Model JSON files.
        
        Creates the correct directory structure expected by Batfish for AWS snapshots:
        aws_configs/<region>/<filename>.json
        
        Args:
            input_data: Input parameters including snapshot_name, network_name, region, configs, and host
                        Can be either a dictionary or InitAwsSnapshotInput object
            
        Returns:
            Dictionary containing operation status and snapshot details
        """
        # Handle input as either dictionary or InitAwsSnapshotInput object
        if isinstance(input_data, dict):
            try:
                # Convert dictionary to InitAwsSnapshotInput
                input_model = InitAwsSnapshotInput(**input_data)
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
        aws_data = input_model.aws_data
        host = input_model.host
        
        logger.info(f"Initializing Batfish AWS snapshot '{snapshot_name}' for network '{network_name}'")
        logger.info(f"AWS region: {region}")
        logger.info(f"Received AWS data with {len(aws_data)} resource types")
        
        try:
            # Create temporary directory structure
            temp_dir = tempfile.mkdtemp()
            
            # Create AWS directory structure: aws_configs/<region>/
            # NOTE: Batfish requires 'aws_configs' not 'aws'
            aws_region_dir = os.path.join(temp_dir, "aws_configs", region)
            os.makedirs(aws_region_dir, exist_ok=True)
            
            logger.info(f"Created temporary directory: {temp_dir}")
            logger.info(f"Created AWS region directory: aws_configs/{region}/")
            
            # CRITICAL: Sanitize all resource names to prevent Batfish crashes
            logger.info("Sanitizing AWS resource names to prevent Batfish parsing errors...")
            sanitized_aws_data = self._sanitize_resource_names(aws_data)
            logger.info("Resource name sanitization complete")
            
            # Write single aws.json file with ALL AWS resources in RAW AWS API format
            # Batfish expects the EXACT format returned by AWS APIs
            # Remove any metadata fields that aren't part of AWS responses
            aws_api_data = {k: v for k, v in sanitized_aws_data.items() if not k.startswith('_')}
            
            aws_json_path = os.path.join(aws_region_dir, "aws.json")
            with open(aws_json_path, "w") as f:
                json.dump(aws_api_data, f, indent=2)
            
            logger.info(f"Wrote AWS data to: aws_configs/{region}/aws.json")
            logger.info(f"AWS data contains: {', '.join(aws_api_data.keys())}")
            
            # Initialize Batfish session with the provided host
            logger.info(f"Using Batfish host: {host}")
            bf = Session(host=host)
            
            try:
                # Set network in Batfish
                bf.set_network(network_name)
                logger.info(f"Set Batfish network to: {network_name}")
                
                # Initialize snapshot - pass the directory directly, not a tarball
                bf.init_snapshot(temp_dir, name=snapshot_name, overwrite=True)
                logger.info(f"Initialized Batfish snapshot: {snapshot_name}")
                
                # Clean up temporary directory
                shutil.rmtree(temp_dir)
                logger.info(f"Cleaned up temporary directory: {temp_dir}")
                
                # Return success response
                return {
                    "ok": True,
                    "snapshot": snapshot_name,
                    "network": network_name,
                    "region": region
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
            logger.error(f"Error initializing Batfish AWS snapshot: {error_msg}")
            
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
            
            # Return error response
            return {
                "ok": False,
                "error": error_msg
            }


# Create singleton instance for FastMCP
init_aws_snapshot_tool = InitAwsSnapshotTool()

# Module-level execute function for imports
def execute(input_data: Union[Dict[str, Any], InitAwsSnapshotInput]) -> Dict[str, Any]:
    """Module-level execute function."""
    return init_aws_snapshot_tool.execute(input_data)

