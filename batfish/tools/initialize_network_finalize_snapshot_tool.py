"""
Network Finalize Snapshot Tool

Pushes staged network configurations to Batfish and initializes the snapshot.

This tool:
1. Reads all staged configs from the staging directory
2. Validates the snapshot is ready
3. Initializes the Batfish snapshot
4. Optionally clears the staging directory
"""

import os
import json
import shutil
import logging
from typing import Dict, Any
from pydantic import BaseModel, Field
from pybatfish.client.session import Session

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Staging directory base path
STAGING_BASE = "/tmp/batfish_network_staging"


class NetworkFinalizeSnapshotInput(BaseModel):
    """Input model for finalizing network snapshot."""
    snapshot_name: str = Field(..., description="Snapshot identifier (must match staging key)")
    host: str = Field("localhost", description="Batfish host to connect to")
    network_name: str = Field(None, description="Logical network name (defaults to snapshot_name if not provided)")
    clear_staging: bool = Field(True, description="Whether to clear staging directory after success")


def execute(input_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Finalize and initialize network snapshot in Batfish.
    
    Reads all staged configs and pushes them to Batfish as a snapshot.
    
    Args:
        input_data: Dictionary containing snapshot_name, host, optional network_name, and clear_staging flag
        
    Returns:
        Dictionary with initialization status and details
    """
    try:
        # Validate input
        validated_input = NetworkFinalizeSnapshotInput(**input_data)
        
        snapshot_name = validated_input.snapshot_name
        host = validated_input.host
        network_name = validated_input.network_name
        clear_staging = validated_input.clear_staging
        
        logger.info(f"Finalizing network snapshot '{snapshot_name}'")
        
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
                "error": f"No staging directory found for snapshot '{snapshot_name}'. Use network_prepare_snapshot first."
            }
        
        # Load metadata
        metadata_file = os.path.join(staging_dir, "metadata.json")
        if not os.path.exists(metadata_file):
            return {
                "ok": False,
                "error": f"Staging directory exists but no metadata found. Directory may be corrupted."
            }
        
        with open(metadata_file, 'r') as f:
            metadata = json.load(f)
        
        network_name = metadata.get("network_name", network_name or snapshot_name)
        staged_configs = metadata.get("configs", {})
        
        if not staged_configs:
            return {
                "ok": False,
                "error": "No configs staged. Use network_prepare_snapshot to add configurations first."
            }
        
        logger.info(f"Found {len(staged_configs)} staged config(s)")
        logger.info(f"Network: {network_name}")
        logger.info(f"Staging directory: {staging_dir}")
        
        # Verify all config files exist
        configs_dir = os.path.join(staging_dir, "configs")
        missing_files = []
        for config_file in staged_configs.keys():
            config_path = os.path.join(configs_dir, config_file)
            if not os.path.exists(config_path):
                missing_files.append(config_file)
        
        if missing_files:
            return {
                "ok": False,
                "error": f"Missing staged config files: {', '.join(missing_files)}"
            }
        
        # Initialize Batfish session
        logger.info(f"Connecting to Batfish host: {host}")
        bf = Session(host=host)
        
        # Set network
        bf.set_network(network_name)
        logger.info(f"Set Batfish network to: {network_name}")
        
        # Initialize snapshot with the staging directory
        logger.info(f"Initializing Batfish snapshot: {snapshot_name}")
        bf.init_snapshot(staging_dir, name=snapshot_name, overwrite=True)
        logger.info(f"Successfully initialized snapshot: {snapshot_name}")
        
        # Get snapshot info to verify
        try:
            nodes_df = bf.q.nodeProperties().answer().frame()
            node_count = len(nodes_df)
            logger.info(f"Snapshot contains {node_count} node(s)")
        except Exception as e:
            logger.warning(f"Could not verify snapshot: {e}")
            node_count = None
        
        result = {
            "ok": True,
            "network": network_name,
            "snapshot": snapshot_name,
            "configs_loaded": len(staged_configs),
            "config_files": list(staged_configs.keys()),
            "node_count": node_count,
            "message": f"Successfully initialized snapshot '{snapshot_name}' with {len(staged_configs)} configs"
        }
        
        # Clear staging directory if requested
        if clear_staging:
            try:
                logger.info(f"Clearing staging directory: {staging_dir}")
                shutil.rmtree(staging_dir)
                logger.info("Staging directory cleared")
                result["staging_cleared"] = True
            except Exception as e:
                logger.warning(f"Failed to clear staging directory: {e}")
                result["staging_cleared"] = False
                result["warning"] = f"Snapshot initialized but failed to clear staging: {e}"
        
        return result
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error finalizing network snapshot: {error_msg}")
        return {
            "ok": False,
            "error": error_msg
        }

