/**
 * Common Middleware Package for MCP Servers
 * 
 * Provides reusable middleware components for TypeScript MCP servers including:
 * - Tool filtering based on X-MCP-Tools headers
 * - Tag-based dynamic toolset generation
 * - FastMCP integration helpers
 */

// Tool Filter Middleware
export {
  ToolFilterMiddleware,
  createToolFilterMiddleware,
  createFilteredTool,
  type Tool,
  type ToolFilterOptions,
  type ToolFilterStatsResult
} from './tool-filter-middleware.js';

// Tag-Based Toolsets Manager
export {
  TagBasedToolsetsManager,
  createTagBasedToolsetsManager,
  initializeToolsets,
  isValidToolset,
  isValidTool,
  getToolTags,
  type TaggedTool,
  type ToolsetConfig
} from './tag-based-toolsets.js';

// Filtered FastMCP
export {
  FilteredFastMCP,
  createFilteredFastMCP,
  type FilteredFastMCPOptions
} from './filtered-fastmcp.js';

import {
  createTagBasedToolsetsManager,
  type TaggedTool
} from './tag-based-toolsets.js';
import {
  createToolFilterMiddleware,
  type Tool
} from './tool-filter-middleware.js';

/**
 * This function sets up both tag-based toolsets and tool filtering
 * for easy integration into any TypeScript MCP server.
 */
export function createMCPToolSystem(options: {
  serverName: string;
  toolsetDescriptions?: Record<string, string>;
  headerName?: string;
}) {
  // Create toolsets manager
  const toolsetsManager = createTagBasedToolsetsManager({
    serverName: options.serverName,
    descriptions: options.toolsetDescriptions
  });

  // Create tool filter middleware
  const filterMiddleware = createToolFilterMiddleware({
    serverName: options.serverName,
    headerName: options.headerName,
    getToolsets: () => toolsetsManager.getToolsetsMapping(),
    isValidTool: (toolName: string) => toolsetsManager.hasTool(toolName)
  });

  return {
    toolsetsManager,
    filterMiddleware,
    
    registerTools: (tools: TaggedTool[]) => toolsetsManager.registerTools(tools),
    filterTools: (tools: Tool[], headers: Record<string, any>) => filterMiddleware.filterTools(tools, headers),
    isToolAllowed: (toolName: string, headers: Record<string, any>) => filterMiddleware.isToolAllowed(toolName, headers),
    getToolsetInfo: () => toolsetsManager.getToolsetInfo(),
    
    TOOLSETS: toolsetsManager.createToolsetsProxy(),
    TOOLSETS_EXPANDED: toolsetsManager.createExpandedToolsetsProxy(),
    
    isValidToolset: (name: string) => toolsetsManager.hasToolset(name),
    isValidTool: (name: string) => toolsetsManager.hasTool(name),
    getToolTags: (toolName: string) => toolsetsManager.getToolTags(toolName)
  };
}

/**
 * Type for the complete MCP tool system
 */
export type MCPToolSystem = ReturnType<typeof createMCPToolSystem>;
