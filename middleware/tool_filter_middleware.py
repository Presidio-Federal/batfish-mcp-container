from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any, Callable, DefaultDict, Dict, Optional, Protocol, Set, cast

from fastmcp.server.dependencies import get_http_headers
from fastmcp.server.middleware import Middleware, MiddlewareContext

logger = logging.getLogger(__name__)

# attribute name to store registry on the mcp instance
_REGISTRY_ATTR = "_toolset_registry"

# ============================================================================
# Type Definitions
# ============================================================================

ToolsetRegistry = DefaultDict[str, Set[str]]  # toolset -> {tool names}

# ============================================================================
# Registry Management
# ============================================================================


def get_registry(mcp: MCPInstance) -> ToolsetRegistry:
    """Return the per-server toolset registry attached to the FastMCP instance."""
    try:
        reg = getattr(mcp, _REGISTRY_ATTR, None)
        if reg is None:
            reg = defaultdict(set)
            setattr(mcp, _REGISTRY_ATTR, reg)
        return cast(ToolsetRegistry, reg)
    except (AttributeError, TypeError) as e:
        logger.error(f"Failed to access/create registry on MCP instance: {e}")
        # Return empty registry as fallback
        return defaultdict(set)


class MCPInstance(Protocol):
    # ============================================================================
    # Decorator
    # ============================================================================
    def tool(
        self, **tool_kwargs: Any
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]: ...


def tool(mcp: MCPInstance, *, toolset: str, **tool_kwargs: Any):
    """
    Decorator that registers a tool with a toolset for HTTP header-based filtering.

    This wraps mcp.tool(...) and automatically registers the tool in the specified
    toolset, enabling clients to request specific groups of tools via the
    x-mcp-tools HTTP header.

    Args:
        mcp: The FastMCP server instance
        toolset: The toolset name this tool belongs to (e.g., "monitoring", "policy")
                Clients can request all tools in a toolset by including the toolset
                name in the x-mcp-tools header
        **tool_kwargs: All standard mcp.tool() parameters (name, description, etc.)

    Usage:
        @tool(mcp, toolset="monitoring", name="meraki_monitor_clients",
            description="Monitor clients on a network")
        def meraki_monitor_clients(...):
            ...

    Header filtering:
        - x-mcp-tools: monitoring → Returns all tools in "monitoring" toolset
        - x-mcp-tools: monitoring,policy → Returns tools from both toolsets
        - x-mcp-tools: meraki_monitor_clients → Returns specific tool only
    """

    def decorator(fn: Callable):
        wrapped = mcp.tool(**tool_kwargs)(fn)
        tool_name = (
            getattr(wrapped, "name", None) or tool_kwargs.get("name") or fn.__name__
        )
        get_registry(mcp)[toolset].add(tool_name)
        return wrapped

    return decorator


class ToolFilterMiddleware(Middleware):
    """
    GitHub-style tool filtering middleware.
    Uses per-mcp toolset registry (no hardcoding).
    """

    def __init__(self, mcp: MCPInstance, header_name: str = "x-mcp-tools") -> None:
        self.header_name = header_name
        self._mcp = mcp  # capture the instance this middleware belongs to

    def _expand_toolsets(self, names: Set[str]) -> Set[str]:
        registry = get_registry(self._mcp)
        expanded: Set[str] = set()

        for name in names:
            # if value matches a toolset, expand it; else treat it as a tool name
            if name in registry:
                logger.debug(f"Expanding toolset '{name}' -> {registry[name]}")
                expanded.update(registry[name])
            else:
                logger.debug(f"Treating '{name}' as individual tool")
                expanded.add(name)

        return expanded

    def _get_header_value(self) -> Optional[str]:
        """Return raw header value, or None if header is missing or error occurs."""
        try:
            headers = get_http_headers(include_all=True)
        except Exception as e:
            logger.error(
                "ToolFilterMiddleware: failed to read HTTP headers: %s",
                e,
                exc_info=True,
            )
            # Consistent with _get_header_candidates: fail-safe by denying
            # Or change both to allow-all for better UX
            return None  # Current: allow-all

        for k, v in headers.items():
            if k.casefold() == self.header_name.casefold():
                return v
        return None

    def _get_header_candidates(self) -> Optional[Set[str]]:
        """
        Header semantics:
          - Missing => allow ALL tools (None)
          - Present but empty => allow NONE (empty set)
          - Otherwise => allow listed tools/toolsets
        """
        try:
            raw = self._get_header_value()

            if raw is None:
                return None  # allow all

            raw = raw.strip()
            if raw == "":
                return set()  # allow none

            items = {x.strip() for x in raw.split(",") if x.strip()}
            if not items:
                return set()

            return self._expand_toolsets(items)

        except Exception as e:
            logger.error(
                "ToolFilterMiddleware._get_header_candidates failed: %s",
                e,
                exc_info=True,
            )
            return set()  # safe deny-all

    async def on_list_tools(self, context: MiddlewareContext, call_next):
        tools = await call_next(context)
        header_candidates = self._get_header_candidates()

        if header_candidates is None:
            return tools

        if not header_candidates:
            return []

        allowed_names = {t.name for t in tools} & header_candidates
        if not allowed_names:
            return []

        return [t for t in tools if t.name in allowed_names]
