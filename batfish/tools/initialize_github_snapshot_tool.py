"""
GitHub Snapshot Tool

Load Batfish snapshots directly from GitHub repositories.
Supports both public and private repositories (with authentication).

This tool:
1. Accepts a GitHub repository path
2. Clones the repository (or specific directory) to a temporary location
3. Supports private repositories via GitHub username and PAT
4. Initializes the snapshot in Batfish
5. Cleans up temporary files
"""

import os
import tempfile
import shutil
import logging
import subprocess
import zipfile
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field
from pybatfish.client.session import Session

# Configure logging
logger = logging.getLogger(__name__)


class GitHubSnapshotInput(BaseModel):
    """Input model for loading snapshot from GitHub."""
    repo_url: str = Field(..., description="GitHub repository URL (https://github.com/owner/repo or https://github.com/owner/repo/tree/branch/path)")
    snapshot_name: str = Field(..., description="Snapshot identifier")
    network_name: str = Field(None, description="Logical network name (defaults to snapshot_name)")
    github_username: str = Field(None, description="GitHub username (required for private repos)")
    github_pat: str = Field(None, description="GitHub Personal Access Token (required for private repos)")
    branch: str = Field("main", description="Branch to clone (default: main)")
    subpath: str = Field(None, description="Subdirectory path within repo containing snapshot data")
    host: str = Field("localhost", description="Batfish host to connect to")


def parse_github_url(url: str) -> Dict[str, str]:
    """
    Parse a GitHub URL to extract owner, repo, branch, and path.
    
    Supports formats:
    - https://github.com/owner/repo
    - https://github.com/owner/repo.git
    - https://github.com/owner/repo/tree/branch/path/to/dir
    
    Args:
        url: GitHub URL
        
    Returns:
        Dictionary with parsed components
    """
    # Remove trailing slashes and .git
    url = url.rstrip('/').replace('.git', '')
    
    # Parse URL parts
    parts = url.split('/')
    
    result = {
        'owner': None,
        'repo': None,
        'branch': None,
        'subpath': None,
        'base_url': None
    }
    
    # Find github.com in parts
    try:
        github_idx = parts.index('github.com')
        result['owner'] = parts[github_idx + 1]
        result['repo'] = parts[github_idx + 2]
        result['base_url'] = f"https://github.com/{result['owner']}/{result['repo']}"
        
        # Check if tree/branch/path is specified
        if len(parts) > github_idx + 3:
            if parts[github_idx + 3] == 'tree' and len(parts) > github_idx + 4:
                result['branch'] = parts[github_idx + 4]
                # Everything after branch is the path
                if len(parts) > github_idx + 5:
                    result['subpath'] = '/'.join(parts[github_idx + 5:])
    except (ValueError, IndexError) as e:
        logger.error(f"Failed to parse GitHub URL: {url}")
        raise ValueError(f"Invalid GitHub URL format: {url}")
    
    return result


def clone_github_repo(
    repo_url: str,
    target_dir: str,
    branch: str = "main",
    username: Optional[str] = None,
    pat: Optional[str] = None,
    subpath: Optional[str] = None
) -> Dict[str, Any]:
    """
    Clone a GitHub repository to a target directory.
    
    Args:
        repo_url: GitHub repository URL
        target_dir: Target directory for cloning
        branch: Branch to clone
        username: GitHub username for private repos
        pat: Personal Access Token for private repos
        subpath: Subdirectory path to clone (sparse checkout)
        
    Returns:
        Dictionary with status and clone information
    """
    try:
        # Parse the GitHub URL
        parsed = parse_github_url(repo_url)
        base_url = parsed['base_url']
        
        # Override branch and subpath if found in URL
        if parsed['branch']:
            branch = parsed['branch']
        if parsed['subpath']:
            subpath = parsed['subpath']
        
        logger.info(f"Cloning {base_url} (branch: {branch})")
        if subpath:
            logger.info(f"Using subpath: {subpath}")
        
        # Build authenticated URL if credentials provided
        if username and pat:
            # Replace https:// with https://username:token@
            auth_url = base_url.replace('https://', f'https://{username}:{pat}@')
            logger.info("Using authenticated clone for private repository")
        else:
            auth_url = base_url
            logger.info("Using unauthenticated clone for public repository")
        
        # If subpath is specified, use sparse checkout
        if subpath:
            logger.info(f"Setting up sparse checkout for subpath: {subpath}")
            
            # Initialize empty git repo
            subprocess.run(
                ['git', 'init'],
                cwd=target_dir,
                check=True,
                capture_output=True,
                text=True
            )
            
            # Add remote
            subprocess.run(
                ['git', 'remote', 'add', 'origin', auth_url],
                cwd=target_dir,
                check=True,
                capture_output=True,
                text=True
            )
            
            # Enable sparse checkout
            subprocess.run(
                ['git', 'config', 'core.sparseCheckout', 'true'],
                cwd=target_dir,
                check=True,
                capture_output=True,
                text=True
            )
            
            # Specify which paths to checkout
            sparse_checkout_file = os.path.join(target_dir, '.git', 'info', 'sparse-checkout')
            os.makedirs(os.path.dirname(sparse_checkout_file), exist_ok=True)
            with open(sparse_checkout_file, 'w') as f:
                f.write(f"{subpath}/*\n")
            
            # Pull the specific branch
            subprocess.run(
                ['git', 'pull', 'origin', branch],
                cwd=target_dir,
                check=True,
                capture_output=True,
                text=True
            )
            
            # The actual snapshot data is in target_dir/subpath
            snapshot_dir = os.path.join(target_dir, subpath)
        else:
            # Regular clone
            result = subprocess.run(
                ['git', 'clone', '--branch', branch, '--depth', '1', auth_url, target_dir],
                check=True,
                capture_output=True,
                text=True
            )
            logger.info(f"Clone completed: {result.stdout}")
            snapshot_dir = target_dir
        
        # Verify the directory exists and has content
        if not os.path.exists(snapshot_dir):
            raise FileNotFoundError(f"Snapshot directory not found: {snapshot_dir}")
        
        # Check for configs directory or any config files
        configs_dir = os.path.join(snapshot_dir, "configs")
        has_configs_dir = os.path.exists(configs_dir) and os.path.isdir(configs_dir)
        
        # Count files in the snapshot directory
        file_count = 0
        for root, dirs, files in os.walk(snapshot_dir):
            # Skip .git directory
            if '.git' in dirs:
                dirs.remove('.git')
            file_count += len([f for f in files if not f.startswith('.')])
        
        logger.info(f"Cloned repository contains {file_count} files")
        logger.info(f"Has configs/ directory: {has_configs_dir}")
        
        return {
            "ok": True,
            "snapshot_dir": snapshot_dir,
            "has_configs_dir": has_configs_dir,
            "file_count": file_count,
            "branch": branch,
            "subpath": subpath
        }
        
    except subprocess.CalledProcessError as e:
        error_msg = f"Git clone failed: {e.stderr if e.stderr else str(e)}"
        logger.error(error_msg)
        return {
            "ok": False,
            "error": error_msg
        }
    except Exception as e:
        error_msg = f"Failed to clone repository: {str(e)}"
        logger.error(error_msg)
        return {
            "ok": False,
            "error": error_msg
        }


def execute(input_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Load a Batfish snapshot from a GitHub repository.
    
    This tool clones the repo and passes the directory to Batfish.
    Batfish will handle all validation and extraction (including zip files).
    
    Args:
        input_data: Dictionary containing:
            - repo_url: GitHub repo URL
            - snapshot_name: Name for the snapshot
            - network_name: (optional) Network name
            - github_username: (optional) Username for private repos
            - github_pat: (optional) Personal Access Token for private repos
            - branch: (optional) Branch to clone (default: main)
            - subpath: (optional) Subdirectory within repo
            - host: Batfish host
        
    Returns:
        Dictionary with initialization status and details
    """
    temp_dir = None
    
    try:
        # Validate input
        validated_input = GitHubSnapshotInput(**input_data)
        
        repo_url = validated_input.repo_url
        snapshot_name = validated_input.snapshot_name
        network_name = validated_input.network_name or snapshot_name
        github_username = validated_input.github_username
        github_pat = validated_input.github_pat
        branch = validated_input.branch
        subpath = validated_input.subpath
        host = validated_input.host
        
        logger.info(f"Loading snapshot '{snapshot_name}' from GitHub: {repo_url}")
        
        # Validate that if username is provided, PAT must also be provided and vice versa
        if (github_username and not github_pat) or (github_pat and not github_username):
            return {
                "ok": False,
                "error": "Both github_username and github_pat must be provided together for private repositories"
            }
        
        # Create temporary directory for cloning
        temp_dir = tempfile.mkdtemp(prefix="batfish_github_")
        logger.info(f"Created temporary directory: {temp_dir}")
        
        # Clone the repository
        clone_result = clone_github_repo(
            repo_url=repo_url,
            target_dir=temp_dir,
            branch=branch,
            username=github_username,
            pat=github_pat,
            subpath=subpath
        )
        
        if not clone_result.get("ok"):
            return {
                "ok": False,
                "error": clone_result.get("error", "Unknown clone error")
            }
        
        snapshot_dir = clone_result["snapshot_dir"]
        
        # Check if there's a zip file in the snapshot directory
        zip_files = [f for f in os.listdir(snapshot_dir) if f.endswith('.zip') and not f.startswith('.')]
        
        if zip_files:
            logger.info(f"Found zip file(s): {zip_files}")
            # If there's a zip file, extract it to a new directory
            extract_dir = tempfile.mkdtemp(prefix="batfish_extracted_")
            logger.info(f"Extracting zip to: {extract_dir}")
            
            # Extract the first zip file found
            zip_path = os.path.join(snapshot_dir, zip_files[0])
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
            
            # Use the extracted directory as the snapshot directory
            snapshot_dir = extract_dir
            logger.info(f"Using extracted directory: {snapshot_dir}")
        
        # List what's in the snapshot directory for debugging
        contents = os.listdir(snapshot_dir)
        logger.info(f"Snapshot directory contents: {contents}")
        
        # Initialize Batfish session
        logger.info(f"Connecting to Batfish host: {host}")
        bf = Session(host=host)
        
        # Set network
        bf.set_network(network_name)
        logger.info(f"Set Batfish network to: {network_name}")
        
        # Initialize snapshot - let Batfish validate the structure
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
            logger.warning(f"Could not verify snapshot nodes: {e}")
        
        return {
            "ok": True,
            "network": network_name,
            "snapshot": snapshot_name,
            "repo_url": repo_url,
            "branch": clone_result.get("branch"),
            "subpath": clone_result.get("subpath"),
            "file_count": clone_result.get("file_count"),
            "node_count": node_count,
            "nodes": node_names if node_names else None,
            "message": f"Successfully initialized snapshot '{snapshot_name}' from GitHub repository"
        }
        
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Error loading GitHub snapshot: {error_msg}")
        import traceback
        logger.error(traceback.format_exc())
        return {
            "ok": False,
            "error": error_msg
        }
        
    finally:
        # Cleanup temporary directory
        if temp_dir and os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir)
                logger.info(f"Cleaned up temporary directory: {temp_dir}")
            except Exception as e:
                logger.warning(f"Failed to cleanup temp dir: {e}")


# Create singleton instance for export
github_snapshot_tool = execute

