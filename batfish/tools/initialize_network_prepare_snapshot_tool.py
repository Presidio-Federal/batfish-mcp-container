"""
Network Prepare Snapshot Tool

Stages network device configurations for later initialization.
Allows incremental adding of configs before pushing to Batfish.

This tool:
1. Creates/manages a staging directory for a snapshot
2. Validates and formats configs for Batfish
3. Allows adding one or multiple configs at a time
4. Tracks what's been staged
"""

import os
import json
import logging
from typing import Dict, Any, List
from pydantic import BaseModel, Field

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Staging directory base path
STAGING_BASE = "/tmp/batfish_network_staging"


class NetworkPrepareSnapshotInput(BaseModel):
    """Input model for preparing network snapshot."""
    snapshot_name: str = Field(..., description="Snapshot identifier (used as staging key)")
    configs: Dict[str, str] = Field(..., description="Dictionary of {filename: configContent} to add")
    network_name: str = Field(None, description="Logical network name (defaults to snapshot_name if not provided)")


def validate_config_format(filename: str, content: str) -> tuple[bool, str, str]:
    """
    Validate and format configuration for Batfish.
    
    Args:
        filename: Original filename
        content: Configuration content
        
    Returns:
        Tuple of (is_valid, formatted_content, error_message)
    """
    try:
        # Ensure content is not empty
        if not content or not content.strip():
            return False, "", "Configuration content is empty"
        
        # Ensure filename has appropriate extension
        valid_extensions = ['.cfg', '.conf', '.txt', '.config']
        has_valid_ext = any(filename.endswith(ext) for ext in valid_extensions)
        
        if not has_valid_ext:
            # Add .cfg extension if missing
            filename = f"{filename}.cfg"
            logger.info(f"Added .cfg extension to filename: {filename}")
        
        # Basic validation: check for common config patterns
        content_lower = content.lower()
        
        # Check for common vendor patterns
        vendor_patterns = [
            'hostname',  # Cisco/Juniper
            'interface',  # Most vendors
            'router',  # Routing configs
            'system',  # Juniper
            'set',  # Juniper set commands
            'enable',  # Cisco
            'configure',  # Various
        ]
        
        has_valid_pattern = any(pattern in content_lower for pattern in vendor_patterns)
        
        if not has_valid_pattern:
            logger.warning(f"Config {filename} doesn't match common vendor patterns. Accepting anyway.")
        
        # Format: ensure proper line endings (Unix style)
        formatted_content = content.replace('\r\n', '\n').replace('\r', '\n')
        
        # Ensure file ends with newline
        if not formatted_content.endswith('\n'):
            formatted_content += '\n'
        
        return True, formatted_content, ""
        
    except Exception as e:
        return False, "", f"Validation error: {str(e)}"


def execute(input_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Stage network device configurations for a snapshot.
    
    Creates/updates staging directory and adds configs one or multiple at a time.
    
    Args:
        input_data: Dictionary containing snapshot_name, configs, and optional network_name
        
    Returns:
        Dictionary with staging status, list of staged configs, and file count
    """
    try:
        # Validate input
        validated_input = NetworkPrepareSnapshotInput(**input_data)
        
        snapshot_name = validated_input.snapshot_name
        configs = validated_input.configs
        network_name = validated_input.network_name or snapshot_name
        
        logger.info(f"Preparing network snapshot '{snapshot_name}' (network: {network_name})")
        logger.info(f"Adding {len(configs)} configuration(s)")
        
        # Create staging directory structure
        staging_dir = os.path.join(STAGING_BASE, network_name, snapshot_name)
        configs_dir = os.path.join(staging_dir, "configs")
        metadata_file = os.path.join(staging_dir, "metadata.json")
        
        os.makedirs(configs_dir, exist_ok=True)
        logger.info(f"Staging directory: {staging_dir}")
        
        # Load or create metadata
        if os.path.exists(metadata_file):
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
        else:
            metadata = {
                "network_name": network_name,
                "snapshot_name": snapshot_name,
                "configs": {}
            }
        
        # Process and add each config
        added_configs = []
        errors = []
        
        for filename, content in configs.items():
            # Validate and format the config
            is_valid, formatted_content, error_msg = validate_config_format(filename, content)
            
            if not is_valid:
                errors.append(f"{filename}: {error_msg}")
                logger.error(f"Failed to add {filename}: {error_msg}")
                continue
            
            # Ensure filename is clean (no path traversal)
            clean_filename = os.path.basename(filename)
            if not clean_filename.endswith('.cfg') and not clean_filename.endswith('.conf') and not clean_filename.endswith('.txt'):
                clean_filename = f"{clean_filename}.cfg"
            
            # Write config file
            config_path = os.path.join(configs_dir, clean_filename)
            with open(config_path, 'w') as f:
                f.write(formatted_content)
            
            # Update metadata
            metadata["configs"][clean_filename] = {
                "original_name": filename,
                "size": len(formatted_content),
                "lines": formatted_content.count('\n')
            }
            
            added_configs.append(clean_filename)
            logger.info(f"Added config: {clean_filename} ({len(formatted_content)} bytes)")
        
        # Save metadata
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        # Get list of all staged configs
        staged_configs = list(metadata["configs"].keys())
        
        logger.info(f"Successfully staged {len(added_configs)} config(s)")
        logger.info(f"Total staged configs: {len(staged_configs)}")
        
        return {
            "ok": True,
            "snapshot_name": snapshot_name,
            "network_name": network_name,
            "staging_dir": staging_dir,
            "added_configs": added_configs,
            "staged_configs": staged_configs,
            "total_configs": len(staged_configs),
            "errors": errors if errors else None,
            "message": f"Successfully staged {len(added_configs)} config(s). Total: {len(staged_configs)} configs ready for initialization."
        }
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error preparing network snapshot: {error_msg}")
        return {
            "ok": False,
            "error": error_msg,
            "staged_configs": []
        }

