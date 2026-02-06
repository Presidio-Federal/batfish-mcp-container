"""
Main entry point for running the Batfish MCP Server as a Python module.
"""

try:
    from .server import main
except ImportError:
    from server import main

if __name__ == "__main__":
    main()
