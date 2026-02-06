"""
Network Remove Config Tool

Remove a specific configuration file from staging.

This tool allows you to:
1. Remove incorrectly added configs
2. Replace configs by removing then re-adding
3. Clean up before finalization
"""

import os
import json
import logging
from typing import Dict, Any
from pydantic import BaseModel, Field

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Staging directory base path
STAGING_BASE = "/tmp/batfish_network_staging"


class NetworkRemoveConfigInput(BaseModel):
    """Input model for removing staged config."""
    snapshot_name: str = Field(..., description="Snapshot identifier (staging key)")
    filename: str = Field(..., description="Config filename to remove")
    network_name: str = Field(None, description="Logical network name (will search if not provided)")


def execute(input_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Remove a configuration file from staging.
    
    Args:
        input_data: Dictionary containing snapshot_name, filename, and optional network_name
        
    Returns:
        Dictionary with removal status and remaining staged configs
    """
    try:
        # Validate input
        validated_input = NetworkRemoveConfigInput(**input_data)
        
        snapshot_name = validated_input.snapshot_name
        filename = validated_input.filename
        network_name = validated_input.network_name
        
        logger.info(f"Removing config '{filename}' from snapshot '{snapshot_name}'")
        
        # Try to find staging directory
        if network_name:
            staging_dir = os.path.join(STAGING_BASE, network_name, snapshot_name)
        else:
            # Search for staging directory
            staging_dir = None
            if os.path.exists(STAGING_BASE):
                for net_name in os.listdir(STAGING_BASE):
                    potential_dir = os.path.join(STAGING_BASE, net_name, snapshot_name)
                    if os.path.exists(potential_dir):
                        staging_dir = potential_dir
                        network_name = net_name
                        break
        
        if not staging_dir or not os.path.exists(staging_dir):
            return {
                "ok": False,
                "error": f"No staging directory found for snapshot '{snapshot_name}'.",
                "remaining_configs": []
            }
        
        # Load metadata
        metadata_file = os.path.join(staging_dir, "metadata.json")
        if not os.path.exists(metadata_file):
            return {
                "ok": False,
                "error": "Staging directory exists but no metadata found.",
                "remaining_configs": []
            }
        
        with open(metadata_file, 'r') as f:
            metadata = json.load(f)
        
        staged_configs = metadata.get("configs", {})
        
        # Check if config exists
        if filename not in staged_configs:
            return {
                "ok": False,
                "error": f"Config '{filename}' not found in staging. Available: {list(staged_configs.keys())}",
                "remaining_configs": list(staged_configs.keys())
            }
        
        # Remove config file
        configs_dir = os.path.join(staging_dir, "configs")
        config_path = os.path.join(configs_dir, filename)
        
        if os.path.exists(config_path):
            os.remove(config_path)
            logger.info(f"Removed config file: {config_path}")
        
        # Update metadata
        del staged_configs[filename]
        metadata["configs"] = staged_configs
        
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        remaining_configs = list(staged_configs.keys())
        
        logger.info(f"Successfully removed '{filename}'. {len(remaining_configs)} config(s) remaining.")
        
        return {
            "ok": True,
            "snapshot_name": snapshot_name,
            "network_name": network_name,
            "removed_config": filename,
            "remaining_configs": remaining_configs,
            "total_remaining": len(remaining_configs),
            "message": f"Removed '{filename}'. {len(remaining_configs)} config(s) remaining in staging."
        }
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error removing config: {error_msg}")
        return {
            "ok": False,
            "error": error_msg,
            "remaining_configs": []
        }

