"""
Management: Get Parse Status Tool
Return parse warnings and errors for a snapshot.
"""

import logging
import json
from typing import Dict, Any, Union, List
from pydantic import BaseModel, Field
from pybatfish.client.session import Session

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class GetParseStatusInput(BaseModel):
    """Input model for getting Batfish parse status."""
    network: str = Field(..., description="Logical network name")
    snapshot: str = Field(..., description="Snapshot identifier")
    host: str = Field("localhost", description="Batfish host to connect to")


class GetParseStatusOutput(BaseModel):
    """Output model for getting Batfish parse status."""
    ok: bool = Field(..., description="Whether the operation was successful")
    warnings: List[Dict[str, Any]] = Field(..., description="Parse warnings")
    errors: List[Dict[str, Any]] = Field(..., description="Parse errors")


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


class GetParseStatusTool:
    """Tool for getting parse warnings and errors from a Batfish snapshot."""
    
    def execute(self, input_data: Union[Dict[str, Any], GetParseStatusInput]) -> Dict[str, Any]:
        """
        Return parse warnings and errors for a snapshot.
        
        Args:
            input_data: Input parameters including network, snapshot, and optional host
                        Can be either a dictionary or GetParseStatusInput object
            
        Returns:
            Dictionary containing operation status, warnings, and errors
        """
        # Handle input as either dictionary or GetParseStatusInput object
        if isinstance(input_data, dict):
            try:
                # Convert dictionary to GetParseStatusInput
                input_model = GetParseStatusInput(**input_data)
            except Exception as e:
                logger.error(f"Invalid input parameters: {str(e)}")
                return {
                    "ok": False,
                    "error": f"Invalid input parameters: {str(e)}",
                    "warnings": [],
                    "errors": []
                }
        else:
            # Assume it's already a GetParseStatusInput object
            input_model = input_data
        
        # Extract values from the model
        network = input_model.network
        snapshot = input_model.snapshot
        host = input_model.host
        
        logger.info(f"Getting parse status for network '{network}', snapshot '{snapshot}'")
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
            
            # Get parse warnings
            warnings_df = bf.q.parseWarning().answer().frame()
            warnings = dataframe_to_serializable(warnings_df)
            logger.info(f"Found {len(warnings)} parse warnings")
            
            # Get parse errors using fileParseStatus
            errors_df = bf.q.fileParseStatus().answer().frame()
            # Filter for actual errors (Status != "PASSED")
            if not errors_df.empty and "Status" in errors_df.columns:
                errors_df = errors_df[errors_df["Status"] != "PASSED"]
            errors = dataframe_to_serializable(errors_df)
            logger.info(f"Found {len(errors)} parse errors")
            
            # Return success response
            return {
                "ok": True,
                "warnings": warnings,
                "errors": errors
            }
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error getting parse status: {error_msg}")
            
            # Return error response
            return {
                "ok": False,
                "error": error_msg,
                "warnings": [],
                "errors": []
            }


# Create singleton instance for FastMCP
get_parse_status_tool = GetParseStatusTool()

