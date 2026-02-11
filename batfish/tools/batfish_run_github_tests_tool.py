"""
Batfish GitHub Test Execution Tool

Downloads and executes standard pytest files from the ai-studio-network-tests GitHub repository.
This tool provides MCP access to the central test catalog, allowing AI agents to discover
and run portable Batfish tests.
"""

import logging
import subprocess
import tempfile
import os
import json
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
import requests

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

GITHUB_REPO = "Presidio-Federal/ai-studio-network-tests"
CATALOG_URL = f"https://raw.githubusercontent.com/{GITHUB_REPO}/main/catalog.json"


class BatfishTestDescribeInput(BaseModel):
    """Input for describing a specific Batfish test"""
    test_id: str = Field(..., description="Test ID from catalog (e.g., 'batfish-001-bidirectional-reachability')")


class BatfishGitHubTestInput(BaseModel):
    """Input for running Batfish tests from GitHub"""
    test_path: str = Field(..., description="Path to test in GitHub repo (e.g., 'batfish/purdue/test_level3_to_level4.py')")
    network: str = Field(..., description="Batfish network name")
    snapshot: str = Field(..., description="Batfish snapshot name")
    test_params: Optional[Dict[str, str]] = Field(None, description="Additional test parameters (e.g., {'level3_ip': '10.42.300.10'})")
    host: str = Field(default="localhost", description="Batfish host")


class BatfishTestCatalogInput(BaseModel):
    """Input for listing Batfish tests from GitHub catalog"""
    framework: Optional[str] = Field(None, description="Filter by framework (e.g., 'purdue', 'pci-dss', 'stig')")
    test_type: Optional[str] = Field(None, description="Filter by test type (should be 'batfish' or 'predictive_validation')")
    tags: Optional[List[str]] = Field(None, description="Filter by tags")


class BatfishGitHubTestTool:
    """
    Tool for executing Batfish tests from the central GitHub repository.
    Downloads pytest files and executes them against a Batfish instance.
    """
    
    def execute(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Download and execute a Batfish test from GitHub.
        
        Args:
            input_data: Test path, network, snapshot, and optional parameters
        
        Returns:
            Test execution results
        """
        try:
            validated_input = BatfishGitHubTestInput(**input_data)
            
            test_path = validated_input.test_path
            network = validated_input.network
            snapshot = validated_input.snapshot
            test_params = validated_input.test_params or {}
            host = validated_input.host
            
            logger.info(f"Downloading test: {test_path}")
            
            # Download test file from GitHub
            raw_url = f"https://raw.githubusercontent.com/{GITHUB_REPO}/main/{test_path}"
            response = requests.get(raw_url)
            
            if response.status_code != 200:
                return {
                    "ok": False,
                    "error": f"Failed to download test from GitHub: {response.status_code}"
                }
            
            # Create temporary directory for test execution
            with tempfile.TemporaryDirectory() as tmpdir:
                test_file = os.path.join(tmpdir, "test.py")
                
                with open(test_file, 'w') as f:
                    f.write(response.text)
                
                # Build pytest command with parameters
                pytest_args = [
                    "pytest",
                    test_file,
                    "-v",
                    "--tb=short",
                    f"--network={network}",
                    f"--snapshot={snapshot}",
                    f"--host={host}"
                ]
                
                # Add custom test parameters
                for key, value in test_params.items():
                    pytest_args.append(f"--{key}={value}")
                
                logger.info(f"Executing: {' '.join(pytest_args)}")
                
                # Execute pytest
                result = subprocess.run(
                    pytest_args,
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                
                passed = result.returncode == 0
                
                return {
                    "ok": passed,
                    "test_path": test_path,
                    "network": network,
                    "snapshot": snapshot,
                    "exit_code": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "passed": passed
                }
                
        except subprocess.TimeoutExpired:
            return {
                "ok": False,
                "error": "Test execution timed out after 120 seconds"
            }
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error executing GitHub test: {error_msg}", exc_info=True)
            return {
                "ok": False,
                "error": error_msg
            }


class BatfishTestCatalogTool:
    """
    Tool for browsing available Batfish tests from the GitHub catalog.
    """
    
    def execute(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        List available Batfish tests from GitHub catalog.
        
        Args:
            input_data: Optional filters (framework, test_type, tags)
        
        Returns:
            List of available tests
        """
        try:
            validated_input = BatfishTestCatalogInput(**input_data)
            
            logger.info("Fetching test catalog from GitHub")
            
            # Download catalog
            response = requests.get(CATALOG_URL)
            
            if response.status_code != 200:
                return {
                    "ok": False,
                    "error": f"Failed to download catalog from GitHub: {response.status_code}"
                }
            
            catalog = response.json()
            
            # Filter tests
            tests = []
            for test in catalog.get("tests", []):
                # Filter by test type (only Batfish tests)
                if test.get("test_type") not in ["batfish", "predictive_validation"]:
                    continue
                
                # Apply filters
                if validated_input.framework and test.get("framework") != validated_input.framework:
                    continue
                
                if validated_input.test_type and test.get("test_type") != validated_input.test_type:
                    continue
                
                if validated_input.tags:
                    test_tags = set(test.get("tags", []))
                    filter_tags = set(validated_input.tags)
                    if not filter_tags.intersection(test_tags):
                        continue
                
                tests.append(test)
            
            return {
                "ok": True,
                "count": len(tests),
                "tests": tests,
                "catalog_url": CATALOG_URL
            }
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error fetching catalog: {error_msg}", exc_info=True)
            return {
                "ok": False,
                "error": error_msg,
                "count": 0,
                "tests": []
            }


class BatfishTestDescribeTool:
    """
    Tool for getting detailed information about a specific Batfish test.
    Returns test metadata including required parameters, descriptions, and usage examples.
    """
    
    def execute(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get detailed information about a specific Batfish test.
        
        Args:
            input_data: Test ID to describe
        
        Returns:
            Detailed test information including parameter schema
        """
        try:
            validated_input = BatfishTestDescribeInput(**input_data)
            test_id = validated_input.test_id
            
            logger.info(f"Describing test: {test_id}")
            
            # Download catalog
            response = requests.get(CATALOG_URL)
            
            if response.status_code != 200:
                return {
                    "ok": False,
                    "error": f"Failed to download catalog from GitHub: {response.status_code}"
                }
            
            catalog = response.json()
            
            # Find the test
            test = None
            for t in catalog.get("tests", []):
                if t.get("test_id") == test_id:
                    test = t
                    break
            
            if not test:
                return {
                    "ok": False,
                    "error": f"Test '{test_id}' not found in catalog"
                }
            
            # Return full test details
            return {
                "ok": True,
                "test_id": test.get("test_id"),
                "name": test.get("name"),
                "description": test.get("description"),
                "test_type": test.get("test_type"),
                "framework": test.get("framework"),
                "test_path": test.get("test_path"),
                "required_parameters": test.get("required_parameters", []),
                "optional_parameters": test.get("optional_parameters", []),
                "parameter_descriptions": test.get("parameter_descriptions", {}),
                "tags": test.get("tags", []),
                "severity": test.get("severity"),
                "example_usage": test.get("example_usage"),
                "nist_controls": test.get("nist_controls", [])
            }
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error describing test: {error_msg}", exc_info=True)
            return {
                "ok": False,
                "error": error_msg
            }


# Create singleton instances
batfish_github_test_tool = BatfishGitHubTestTool()
batfish_test_catalog_tool = BatfishTestCatalogTool()
batfish_test_describe_tool = BatfishTestDescribeTool()
