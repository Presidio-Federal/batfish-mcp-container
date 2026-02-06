"""
Network Upload ZIP Tool

Upload a complete zip file of network configurations to Batfish.
The zip file should be base64-encoded in the request.

This tool:
1. Accepts base64-encoded zip data
2. Validates the zip file
3. Extracts to temporary directory
4. Initializes Batfish snapshot directly
5. Cleans up temporary files
"""

import os
import json
import base64
import tempfile
import zipfile
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


class NetworkUploadZipInput(BaseModel):
    """Input model for uploading zip file."""
    snapshot_name: str = Field(..., description="Snapshot identifier")
    zip_data: str = Field(..., description="Base64-encoded zip file content")
    network_name: str = Field(None, description="Logical network name (defaults to snapshot_name)")
    host: str = Field("localhost", description="Batfish host to connect to")


def execute(input_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Upload a zip file of network configurations and initialize Batfish snapshot.
    
    The zip file should contain a 'configs/' directory with all config files.
    
    Expected structure:
    your-snapshot.zip
    └── configs/
        ├── router1.cfg
        ├── router2.cfg
        └── switch1.cfg
    
    If no 'configs/' directory exists, all files in the zip root will be treated as configs.
    
    Args:
        input_data: Dictionary containing snapshot_name, base64 zip_data, optional network_name, and host
        
    Returns:
        Dictionary with initialization status and details
    """
    temp_zip = None
    temp_extract_dir = None
    
    try:
        # Validate input
        validated_input = NetworkUploadZipInput(**input_data)
        
        snapshot_name = validated_input.snapshot_name
        zip_data_b64 = validated_input.zip_data
        network_name = validated_input.network_name or snapshot_name
        host = validated_input.host
        
        logger.info(f"Uploading zip for snapshot '{snapshot_name}' (network: {network_name})")
        
        # Decode base64 zip data
        try:
            zip_bytes = base64.b64decode(zip_data_b64)
            logger.info(f"Decoded zip data: {len(zip_bytes)} bytes")
        except Exception as e:
            return {
                "ok": False,
                "error": f"Failed to decode base64 zip data: {str(e)}"
            }
        
        # Validate minimum size (empty zips are usually < 100 bytes)
        if len(zip_bytes) < 100:
            return {
                "ok": False,
                "error": f"Zip file too small ({len(zip_bytes)} bytes). May be empty or corrupted."
            }
        
        # Write zip to temporary file
        temp_zip = tempfile.NamedTemporaryFile(suffix='.zip', delete=False)
        temp_zip.write(zip_bytes)
        temp_zip.close()
        logger.info(f"Wrote zip to temporary file: {temp_zip.name}")
        
        # Validate it's a valid zip file
        if not zipfile.is_zipfile(temp_zip.name):
            return {
                "ok": False,
                "error": "Uploaded data is not a valid zip file"
            }
        
        # Extract zip to temporary directory
        temp_extract_dir = tempfile.mkdtemp()
        try:
            with zipfile.ZipFile(temp_zip.name, 'r') as zip_ref:
                zip_ref.extractall(temp_extract_dir)
        except Exception as e:
            return {
                "ok": False,
                "error": f"Failed to extract zip file: {str(e)}"
            }
        
        logger.info(f"Extracted zip to: {temp_extract_dir}")
        
        # List all extracted files
        extracted_files = []
        for root, dirs, files in os.walk(temp_extract_dir):
            for file in files:
                if not file.startswith('.') and not file.startswith('__'):  # Skip hidden/system files
                    rel_path = os.path.relpath(os.path.join(root, file), temp_extract_dir)
                    extracted_files.append(rel_path)
        
        logger.info(f"Extracted {len(extracted_files)} files")
        
        # Determine snapshot directory structure
        configs_dir = os.path.join(temp_extract_dir, "configs")
        
        if os.path.exists(configs_dir) and os.path.isdir(configs_dir):
            # Standard structure with configs/ directory
            logger.info("Found 'configs/' directory, using standard structure")
            snapshot_dir = temp_extract_dir
            config_search_dir = configs_dir
        else:
            # No configs/ directory, treat root as configs
            logger.warning("No 'configs/' directory found, creating one and moving files")
            snapshot_dir = tempfile.mkdtemp()
            configs_dir = os.path.join(snapshot_dir, "configs")
            os.makedirs(configs_dir)
            
            # Move all files to configs/
            for file in extracted_files:
                src = os.path.join(temp_extract_dir, file)
                dst = os.path.join(configs_dir, os.path.basename(file))
                shutil.copy2(src, dst)
            
            config_search_dir = configs_dir
        
        # Count config files
        config_files = []
        for root, dirs, files in os.walk(config_search_dir):
            for file in files:
                if not file.startswith('.') and not file.startswith('__'):
                    config_files.append(file)
        
        if not config_files:
            return {
                "ok": False,
                "error": "No config files found in zip. Expected configuration files (.cfg, .conf, .txt, etc.)",
                "extracted_files": extracted_files
            }
        
        logger.info(f"Found {len(config_files)} config files: {config_files}")
        
        # Initialize Batfish session
        logger.info(f"Connecting to Batfish host: {host}")
        bf = Session(host=host)
        
        # Set network
        bf.set_network(network_name)
        logger.info(f"Set Batfish network to: {network_name}")
        
        # Initialize snapshot with the directory
        logger.info(f"Initializing Batfish snapshot: {snapshot_name} from {snapshot_dir}")
        bf.init_snapshot(snapshot_dir, name=snapshot_name, overwrite=True)
        logger.info(f"Successfully initialized snapshot: {snapshot_name}")
        
        # Get snapshot info to verify
        node_count = None
        node_names = []
        try:
            nodes_df = bf.q.nodeProperties().answer().frame()
            node_count = len(nodes_df)
            if not nodes_df.empty:
                node_names = list(nodes_df["Node"].unique())
            logger.info(f"Snapshot contains {node_count} node(s): {node_names}")
        except Exception as e:
            logger.warning(f"Could not verify snapshot: {e}")
        
        return {
            "ok": True,
            "network": network_name,
            "snapshot": snapshot_name,
            "zip_size_bytes": len(zip_bytes),
            "configs_loaded": len(config_files),
            "config_files": sorted(config_files),
            "node_count": node_count,
            "nodes": node_names if node_names else None,
            "message": f"Successfully initialized snapshot '{snapshot_name}' from zip with {len(config_files)} configs"
        }
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error uploading zip: {error_msg}")
        import traceback
        logger.error(traceback.format_exc())
        return {
            "ok": False,
            "error": error_msg
        }
        
    finally:
        # Cleanup temporary files
        if temp_zip and os.path.exists(temp_zip.name):
            try:
                os.unlink(temp_zip.name)
                logger.info(f"Cleaned up temporary zip: {temp_zip.name}")
            except Exception as e:
                logger.warning(f"Failed to cleanup temp zip: {e}")
        
        if temp_extract_dir and os.path.exists(temp_extract_dir):
            try:
                shutil.rmtree(temp_extract_dir)
                logger.info(f"Cleaned up extracted directory: {temp_extract_dir}")
            except Exception as e:
                logger.warning(f"Failed to cleanup extract dir: {e}")

