/**
 * Filtered FastMCP - Generic FastMCP wrapper with tool filtering
 *
 * This class extends FastMCP to provide single-layer access control at the FastMCP level
 * via the canAccess function. It integrates with MCPToolSystem to filter tools based on
 * X-MCP-Tools headers.
 *
 * Design Pattern:
 * - Access control implemented at FastMCP.addTool() level
 * - Tools are wrapped with canAccess() function that checks headers
 * - Integrates with tag-based toolsets and tool filter middleware
 *
 * This class is reusable across all TypeScript MCP servers that need tool filtering.
 */

import { FastMCP } from 'fastmcp';
import type { MCPToolSystem } from './index.js';

export interface FilteredFastMCPOptions {
  /**
   * The MCP tool system instance to use for filtering
   */
  toolSystem: MCPToolSystem;

  /**
   * Enable debug logging for access control decisions
   */
  enableDebugLogging?: boolean;

  /**
   * Header prefix to filter in debug logs (default: 'x-mcp')
   */
  debugHeaderPrefix?: string;
}

/**
 * FilteredFastMCP - FastMCP with built-in tool filtering
 *
 * Usage:
 * ```typescript
 * const toolSystem = createMCPToolSystem({ serverName: 'MyServer' });
 *
 * const server = createFilteredFastMCP(toolSystem, {
 *   name: 'My MCP Server',
 *   authenticate: async (request) => { ... }
 * });
 *
 * server.addTool(myTool); // Automatically filtered
 * ```
 */
export class FilteredFastMCP extends FastMCP {
  private toolSystem: MCPToolSystem;
  private enableDebugLogging: boolean;
  private debugHeaderPrefix: string;

  constructor(
    fastmcpOptions: ConstructorParameters<typeof FastMCP>[0],
    filterOptions: FilteredFastMCPOptions
  ) {
    super(fastmcpOptions);
    this.toolSystem = filterOptions.toolSystem;
    this.enableDebugLogging = filterOptions.enableDebugLogging ?? false;
    this.debugHeaderPrefix = filterOptions.debugHeaderPrefix ?? 'x-mcp';
  }

  /**
   * Override addTool to inject access control via canAccess function
   */
  addTool(tool: any) {
    // Add tool with single point of access control at FastMCP level
    const filteredTool = {
      ...tool,
      canAccess: (auth: any) => {
        const headers = auth?.headers || {};
        const allowed = this.toolSystem.isToolAllowed(tool.name, headers);

        // Optional debug logging for access control decisions
        if (this.enableDebugLogging) {
          console.log(
            `[Tool Access] ${tool.name}: ${allowed ? 'ALLOWED' : 'DENIED'} for headers:`,
            Object.keys(headers).filter(k => k.startsWith(this.debugHeaderPrefix))
          );
        }

        return allowed;
      }
    };

    // Call original addTool with filtered tool
    super.addTool(filteredTool);
  }
}

/**
 * Factory function to create a FilteredFastMCP instance
 *
 * @param toolSystem - The MCP tool system instance
 * @param fastmcpOptions - FastMCP constructor options
 * @param filterOptions - Optional filtering configuration
 */
export function createFilteredFastMCP(
  toolSystem: MCPToolSystem,
  fastmcpOptions: ConstructorParameters<typeof FastMCP>[0],
  filterOptions?: Omit<FilteredFastMCPOptions, 'toolSystem'>
): FilteredFastMCP {
  return new FilteredFastMCP(fastmcpOptions, {
    toolSystem,
    ...filterOptions
  });
}
