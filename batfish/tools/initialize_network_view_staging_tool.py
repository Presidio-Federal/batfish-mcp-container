"""
Network View Staging Tool

View what network configurations have been staged for a snapshot.

This tool shows:
1. What configs have been staged
2. File sizes and line counts
3. Staging directory location
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


class NetworkViewStagingInput(BaseModel):
    """Input model for viewing staging status."""
    snapshot_name: str = Field(..., description="Snapshot identifier (staging key)")
    network_name: str = Field(None, description="Logical network name (will search if not provided)")


def execute(input_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    View staged network configurations for a snapshot.
    
    Args:
        input_data: Dictionary containing snapshot_name and optional network_name
        
    Returns:
        Dictionary with staging details including list of configs and their metadata
    """
    try:
        # Validate input
        validated_input = NetworkViewStagingInput(**input_data)
        
        snapshot_name = validated_input.snapshot_name
        network_name = validated_input.network_name
        
        logger.info(f"Viewing staging status for snapshot '{snapshot_name}'")
        
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
                "error": f"No staging directory found for snapshot '{snapshot_name}'. Use network_prepare_snapshot to create one.",
                "staged_configs": []
            }
        
        # Load metadata
        metadata_file = os.path.join(staging_dir, "metadata.json")
        if not os.path.exists(metadata_file):
            return {
                "ok": False,
                "error": "Staging directory exists but no metadata found. Directory may be corrupted.",
                "staged_configs": []
            }
        
        with open(metadata_file, 'r') as f:
            metadata = json.load(f)
        
        network_name = metadata.get("network_name", network_name)
        staged_configs = metadata.get("configs", {})
        
        # Build detailed config info
        config_details = []
        total_size = 0
        total_lines = 0
        
        for filename, config_meta in staged_configs.items():
            config_details.append({
                "filename": filename,
                "original_name": config_meta.get("original_name", filename),
                "size_bytes": config_meta.get("size", 0),
                "lines": config_meta.get("lines", 0)
            })
            total_size += config_meta.get("size", 0)
            total_lines += config_meta.get("lines", 0)
        
        logger.info(f"Found {len(staged_configs)} staged config(s)")
        
        return {
            "ok": True,
            "snapshot_name": snapshot_name,
            "network_name": network_name,
            "staging_dir": staging_dir,
            "total_configs": len(staged_configs),
            "total_size_bytes": total_size,
            "total_lines": total_lines,
            "staged_configs": config_details,
            "message": f"{len(staged_configs)} config(s) staged and ready for initialization"
        }
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error viewing staging status: {error_msg}")
        return {
            "ok": False,
            "error": error_msg,
            "staged_configs": []
        }

