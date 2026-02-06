"""
Network List Models Tool

Lists available security/compliance models (Purdue, ISA-95, NIST CSF, etc.) 
that can be used for network compliance analysis.

Can show:
- All available models (summary)
- Detailed view of a specific model
"""

import logging
import json
import os
from typing import Dict, Any, List
from pydantic import BaseModel, Field
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class NetworkListModelsInput(BaseModel):
    """Input model for listing security models."""
    model_name: str | None = Field(None, description="Optional: specific model to view in detail. If None, lists all models")
    show_details: bool = Field(False, description="Show full model details (zones, rules, etc.)")


def get_models_directory() -> Path:
    """Get the path to the models directory."""
    # Get the directory where this tool file is located
    current_file = Path(__file__)
    # Go up from tools/ to batfish/, then to models/
    # Path: .../tools/this_file.py -> .../batfish/ -> .../batfish/models/
    models_dir = current_file.parent.parent / "models"
    return models_dir


def load_model(model_path: Path) -> Dict[str, Any]:
    """Load a model JSON file."""
    try:
        with open(model_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading model from {model_path}: {e}")
        return None


def get_available_models() -> List[Dict[str, Any]]:
    """Get list of all available models."""
    models_dir = get_models_directory()
    
    if not models_dir.exists():
        logger.warning(f"Models directory does not exist: {models_dir}")
        return []
    
    models = []
    for model_file in models_dir.glob("*.json"):
        model_data = load_model(model_file)
        if model_data:
            models.append({
                "filename": model_file.name,
                "model_id": model_file.stem,
                "name": model_data.get("name", "Unknown"),
                "version": model_data.get("version", "1.0"),
                "type": model_data.get("type", "unknown"),
                "description": model_data.get("description", "No description available")
            })
    
    return models


def execute(input_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    List available security/compliance models or show details of a specific model.
    
    Args:
        input_data: Dictionary containing optional model_name and show_details flag
        
    Returns:
        Dictionary with:
        - ok: Success status
        - models: List of available models (if listing all)
        - model: Detailed model data (if viewing specific model)
        - summary: Human-readable summary
    """
    try:
        # Validate input
        validated_input = NetworkListModelsInput(**input_data)
        
        model_name = validated_input.model_name
        show_details = validated_input.show_details
        
        logger.info(f"Listing security/compliance models...")
        
        models_dir = get_models_directory()
        
        if not models_dir.exists():
            return {
                "ok": False,
                "error": f"Models directory not found: {models_dir}",
                "models": []
            }
        
        # If specific model requested
        if model_name:
            model_path = models_dir / f"{model_name}.json"
            
            if not model_path.exists():
                # Try to find by full name
                available_models = get_available_models()
                for m in available_models:
                    if m["name"].lower() == model_name.lower():
                        model_path = models_dir / m["filename"]
                        break
            
            if not model_path.exists():
                return {
                    "ok": False,
                    "error": f"Model '{model_name}' not found",
                    "available_models": [m["model_id"] for m in get_available_models()]
                }
            
            model_data = load_model(model_path)
            
            if not model_data:
                return {
                    "ok": False,
                    "error": f"Failed to load model '{model_name}'"
                }
            
            # Return full model data if show_details is True, otherwise just metadata
            if show_details:
                result = {
                    "ok": True,
                    "model_id": model_path.stem,
                    "model": model_data,
                    "summary": f"Loaded model: {model_data.get('name', 'Unknown')} v{model_data.get('version', '1.0')}"
                }
            else:
                # Return just metadata
                zones = model_data.get("zones", {})
                allowed_comms = model_data.get("allowed_communications", [])
                prohibited_comms = model_data.get("prohibited_communications", [])
                enforcement = model_data.get("required_enforcement_points", [])
                
                result = {
                    "ok": True,
                    "model_id": model_path.stem,
                    "name": model_data.get("name"),
                    "version": model_data.get("version"),
                    "description": model_data.get("description"),
                    "type": model_data.get("type"),
                    "reference": model_data.get("reference"),
                    "statistics": {
                        "total_zones": len(zones),
                        "allowed_communications": len(allowed_comms),
                        "prohibited_communications": len(prohibited_comms),
                        "required_enforcement_points": len(enforcement)
                    },
                    "zones": list(zones.keys()),
                    "compliance_standards": model_data.get("compliance_standards", []),
                    "summary": (
                        f"{model_data.get('name')} v{model_data.get('version')}: "
                        f"{len(zones)} zones, {len(allowed_comms)} allowed communications, "
                        f"{len(prohibited_comms)} prohibited communications"
                    )
                }
            
            logger.info(f"Loaded model: {model_path.stem}")
            return result
        
        # List all models
        else:
            available_models = get_available_models()
            
            if not available_models:
                return {
                    "ok": True,
                    "models": [],
                    "summary": "No security models found in models directory."
                }
            
            summary = f"Found {len(available_models)} security/compliance model(s)."
            
            logger.info(summary)
            
            return {
                "ok": True,
                "models": available_models,
                "summary": summary,
                "note": "Use model_name parameter to view detailed model information"
            }
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error listing models: {error_msg}")
        import traceback
        logger.error(traceback.format_exc())
        return {
            "ok": False,
            "error": error_msg,
            "models": []
        }

