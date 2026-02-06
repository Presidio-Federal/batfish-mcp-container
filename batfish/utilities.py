"""
Batfish MCP Server Utilities
Common utility functions for the Batfish MCP server.
"""

import os
import logging
from typing import Dict, Any, Optional

from fastmcp.server.dependencies import get_http_headers

# Configure logging
logger = logging.getLogger(__name__)

def parse_boolean_env_var(env_var_name: str, default: bool = False) -> bool:
    """
    Parse environment variable as boolean with multiple formats supported.
    
    Args:
        env_var_name: Name of the environment variable
        default: Default value if environment variable is not set
        
    Returns:
        Boolean value of the environment variable
    """
    val = os.getenv(env_var_name, '').lower().strip()
    return val in ['true', '1', 'yes', 't', 'y'] if val else default

def log_user_access(request: Optional[Dict[str, Any]], tool_name: str) -> None:
    """
    Log user access if enabled.
    
    Args:
        request: Request object containing authentication information
        tool_name: Name of the tool being accessed
    """
    if parse_boolean_env_var("ENABLE_AUTH_LOGGING") and request:
        claims = getattr(request, "auth", {}).get("claims", {})
        if claims:
            name = claims.get("name") or claims.get("preferred_username")
            email = claims.get("email") or claims.get("upn")
            logger.info(f"[BATFISH] Tool '{tool_name}' accessed by user: {name} ({email})")

def get_batfish_host() -> str:
    """
    Extract Batfish host from HTTP headers or environment.
    
    Returns:
        Batfish host to connect to
    """
    # Get headers directly using get_http_headers()
    headers = get_http_headers() or {}
    normalized_headers = {k.lower(): v for k, v in headers.items()}
    return normalized_headers.get('x-batfish-host') or os.getenv('BATFISH_HOST', 'localhost')

def configure_auth():
    """
    Configure authentication based on environment variables.
    
    Returns:
        Configured authentication provider or None if authentication is disabled
    """
    # Import FastMCP's native JWT verification
    from fastmcp.server.auth.providers.jwt import JWTVerifier
    
    # Get Azure AD tenant ID and client ID from environment variables
    tenant_id = os.getenv('AZURE_AD_TENANT_ID')
    client_id = os.getenv('AZURE_AD_CLIENT_ID')
    
    # Check for Docker environment and force disable auth if needed
    in_docker = os.path.exists('/.dockerenv')
    if in_docker:
        logger.warning("Running in Docker container - checking environment variables carefully")
    
    # Parse DISABLE_JWT_AUTH with multiple formats supported
    disable_jwt_auth = parse_boolean_env_var('DISABLE_JWT_AUTH')
    
    # Add explicit override for Docker if needed
    if in_docker and parse_boolean_env_var('DOCKER_DISABLE_AUTH'):
        logger.warning("Forcing authentication disabled due to DOCKER_DISABLE_AUTH")
        disable_jwt_auth = True
        
    logger.warning(f"DISABLE_JWT_AUTH value: '{os.getenv('DISABLE_JWT_AUTH')}', parsed as: {disable_jwt_auth}")
    
    # Configure authentication based on environment variables
    if disable_jwt_auth:
        logger.info("JWT authentication disabled by DISABLE_JWT_AUTH=true")
        return None
    
    # If auth is enabled, tenant_id is REQUIRED (client_id is optional)
    if not tenant_id:
        error_msg = "JWT authentication is enabled but AZURE_AD_TENANT_ID is not set. Set DISABLE_JWT_AUTH=true to explicitly disable authentication."
        logger.error(error_msg)
        raise ValueError(error_msg)
    
    # Configure JWT verification for Azure AD
    logger.info(f"Configuring JWT verification for Azure AD tenant {tenant_id}")
    if client_id:
        logger.info(f"Audience validation enabled with client_id: {client_id}")
    else:
        logger.warning("AZURE_AD_CLIENT_ID not set - audience validation will be skipped")
    
    jwks_uri = f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"
    issuer = f"https://login.microsoftonline.com/{tenant_id}/v2.0"
    
    return JWTVerifier(
        jwks_uri=jwks_uri,
        issuer=issuer,
        audience=client_id  # Can be None - FastMCP will skip audience validation
    )
