"""
AWS Batfish Safety Utilities

Provides safe wrappers around Batfish queries with:
- Timeout handling
- Empty network detection
- Graceful error handling
- Progress logging
"""

import logging
import signal
from typing import Dict, Any, Optional, Callable
from functools import wraps

logger = logging.getLogger(__name__)


class QueryTimeoutError(Exception):
    """Raised when a Batfish query times out"""
    pass


def timeout_handler(signum, frame):
    """Signal handler for query timeouts"""
    raise QueryTimeoutError("Batfish query timed out")


def safe_query(query_func: Callable, timeout_seconds: int = 30, query_name: str = "query") -> Optional[Any]:
    """
    Execute a Batfish query with timeout and error handling.
    
    Args:
        query_func: Function that executes the query
        timeout_seconds: Maximum time to wait for query
        query_name: Name of query for logging
        
    Returns:
        Query result or None if failed/timed out
    """
    try:
        logger.debug(f"Executing {query_name} (timeout: {timeout_seconds}s)...")
        
        # Set up timeout signal (Unix only, won't work on Windows)
        # For cross-platform, we'd need threading.Timer instead
        try:
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(timeout_seconds)
            
            result = query_func()
            
            signal.alarm(0)  # Cancel the alarm
            return result
            
        except AttributeError:
            # SIGALRM not available (Windows), run without timeout
            logger.warning(f"Timeout not supported on this platform, running {query_name} without timeout")
            return query_func()
            
    except QueryTimeoutError:
        logger.error(f"{query_name} timed out after {timeout_seconds} seconds")
        return None
        
    except Exception as e:
        logger.error(f"{query_name} failed: {e}")
        return None


def check_network_active(bf) -> Dict[str, Any]:
    """
    Check if the Batfish network has active nodes.
    
    Returns dict with:
    - has_nodes: bool
    - node_count: int
    - warning: str (if empty)
    """
    try:
        nodes_df = bf.q.nodeProperties().answer().frame()
        node_count = len(nodes_df)
        
        if node_count == 0:
            return {
                "has_nodes": False,
                "node_count": 0,
                "warning": "No active nodes found in Batfish snapshot. All EC2 instances may be stopped. Some analysis features require running instances."
            }
        
        return {
            "has_nodes": True,
            "node_count": node_count,
            "warning": None
        }
        
    except Exception as e:
        logger.warning(f"Could not check network status: {e}")
        return {
            "has_nodes": False,
            "node_count": 0,
            "warning": f"Could not determine network status: {e}"
        }


def get_aws_raw_data(bf):
    """
    Safely retrieve raw AWS data from the snapshot.
    
    NOTE: bf.q.fileText doesn't exist in pybatfish, so we can't read raw vendor files.
    This function now returns empty dict. Use Batfish queries instead.
    
    Returns:
        dict: Empty dict (raw file reading not supported)
    """
    logger.warning("Raw AWS vendor data reading not supported (bf.q.fileText doesn't exist)")
    logger.info("Use Batfish queries like bf.q.nodeProperties(), bf.q.filterTable(), etc. instead")
    return {}


def safe_batfish_query(bf, query_name: str, query_func: Callable, timeout: int = 30):
    """
    Execute a Batfish query with comprehensive error handling.
    
    Args:
        bf: Batfish session
        query_name: Name for logging
        query_func: Lambda/function that executes the query
        timeout: Timeout in seconds
        
    Returns:
        Tuple of (DataFrame or None, error_message or None)
    """
    try:
        logger.debug(f"Executing Batfish query: {query_name}")
        result = query_func()
        
        if hasattr(result, 'answer'):
            df = result.answer().frame()
            logger.debug(f"{query_name} returned {len(df)} rows")
            return df, None
        
        return result, None
        
    except Exception as e:
        error_msg = str(e)
        logger.warning(f"{query_name} failed: {error_msg}")
        return None, error_msg


def validate_inputs(**kwargs):
    """
    Validate required input parameters.
    
    Raises ValueError if any required param is missing or invalid.
    """
    for key, value in kwargs.items():
        if value is None or (isinstance(value, str) and value.strip() == ""):
            raise ValueError(f"Required parameter '{key}' is missing or empty")

