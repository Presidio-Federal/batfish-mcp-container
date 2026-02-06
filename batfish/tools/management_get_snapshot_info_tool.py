"""
Management: Get Snapshot Info Tool
Return metadata about a snapshot including nodes, vendors, warnings, errors, and interfaces.
"""

import logging
import json
from typing import Dict, Any, Union, List
from pydantic import BaseModel, Field
from pybatfish.client.session import Session

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class GetSnapshotInfoInput(BaseModel):
    """Input model for getting Batfish snapshot info."""
    network: str = Field(..., description="Logical network name")
    snapshot: str = Field(..., description="Snapshot identifier")
    host: str = Field("localhost", description="Batfish host to connect to")


class GetSnapshotInfoOutput(BaseModel):
    """Output model for getting Batfish snapshot info."""
    ok: bool = Field(..., description="Whether the operation was successful")
    nodes: List[str] = Field(..., description="List of node names in the snapshot")
    warnings: List[Dict[str, Any]] = Field(..., description="Parse warnings")
    errors: List[Dict[str, Any]] = Field(..., description="Parse errors")
    vendors: List[str] = Field(..., description="List of vendor types detected")
    interfaces: List[str] = Field(..., description="List of interface names")


class BatfishEncoder(json.JSONEncoder):
    """Custom JSON encoder for Batfish objects."""
    def default(self, obj):
        # Convert any non-serializable objects to strings
        try:
            return super().default(obj)
        except TypeError:
            return str(obj)


def dataframe_to_serializable(df):
    """
    Convert a pandas DataFrame to a serializable format,
    handling Batfish-specific objects.
    """
    if df.empty:
        return []
    
    # First convert to dict
    records = df.to_dict(orient="records")
    
    # Then convert to JSON and back to handle any non-serializable objects
    json_str = json.dumps(records, cls=BatfishEncoder)
    return json.loads(json_str)


class GetSnapshotInfoTool:
    """Tool for getting metadata about a Batfish snapshot."""
    
    def execute(self, input_data: Union[Dict[str, Any], GetSnapshotInfoInput]) -> Dict[str, Any]:
        """
        Return metadata about a snapshot including nodes, vendors, warnings, errors, and interfaces.
        
        Args:
            input_data: Input parameters including network, snapshot, and optional host
                        Can be either a dictionary or GetSnapshotInfoInput object
            
        Returns:
            Dictionary containing operation status and snapshot metadata
        """
        # Handle input as either dictionary or GetSnapshotInfoInput object
        if isinstance(input_data, dict):
            try:
                # Convert dictionary to GetSnapshotInfoInput
                input_model = GetSnapshotInfoInput(**input_data)
            except Exception as e:
                logger.error(f"Invalid input parameters: {str(e)}")
                return {
                    "ok": False,
                    "error": f"Invalid input parameters: {str(e)}",
                    "nodes": [],
                    "warnings": [],
                    "errors": [],
                    "vendors": [],
                    "interfaces": []
                }
        else:
            # Assume it's already a GetSnapshotInfoInput object
            input_model = input_data
        
        # Extract values from the model
        network = input_model.network
        snapshot = input_model.snapshot
        host = input_model.host
        
        logger.info(f"Getting snapshot info for network '{network}', snapshot '{snapshot}'")
        logger.info(f"Using Batfish host: {host}")
        
        try:
            # Initialize Batfish session with the provided host
            bf = Session(host=host)
            logger.info("Batfish session initialized")
            
            # Set network and snapshot
            bf.set_network(network)
            logger.info(f"Set Batfish network to: {network}")
            
            bf.set_snapshot(snapshot)
            logger.info(f"Set Batfish snapshot to: {snapshot}")
            
            # Get node properties
            nodes_df = bf.q.nodeProperties().answer().frame()
            nodes = list(nodes_df["Node"]) if not nodes_df.empty else []
            logger.info(f"Found {len(nodes)} nodes")
            
            # Get vendors
            vendors = []
            if not nodes_df.empty and "Configuration_Format" in nodes_df.columns:
                vendors = list(nodes_df["Configuration_Format"].unique())
            logger.info(f"Found vendors: {vendors}")
            
            # Get interface properties
            interfaces_df = bf.q.interfaceProperties().answer().frame()
            # Convert Interface objects to strings for serialization
            if not interfaces_df.empty and "Interface" in interfaces_df.columns:
                interfaces = [str(iface) for iface in interfaces_df["Interface"]]
            else:
                interfaces = []
            logger.info(f"Found {len(interfaces)} interfaces")
            
            # Get parse warnings
            warnings_df = bf.q.parseWarning().answer().frame()
            warnings = dataframe_to_serializable(warnings_df)
            logger.info(f"Found {len(warnings)} parse warnings")
            
            # Get parse errors
            errors_df = bf.q.fileParseStatus().answer().frame()
            # Filter for actual errors (Status != "PASSED")
            if not errors_df.empty and "Status" in errors_df.columns:
                errors_df = errors_df[errors_df["Status"] != "PASSED"]
            errors = dataframe_to_serializable(errors_df)
            logger.info(f"Found {len(errors)} parse errors")
            
            # Return success response
            return {
                "ok": True,
                "nodes": nodes,
                "warnings": warnings,
                "errors": errors,
                "vendors": vendors,
                "interfaces": interfaces
            }
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error getting snapshot info: {error_msg}")
            
            # Return error response
            return {
                "ok": False,
                "error": error_msg,
                "nodes": [],
                "warnings": [],
                "errors": [],
                "vendors": [],
                "interfaces": []
            }


# Create singleton instance for FastMCP
get_snapshot_info_tool = GetSnapshotInfoTool()

