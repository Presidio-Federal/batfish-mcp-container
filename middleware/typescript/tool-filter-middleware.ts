/**
 * Generic Tool Filter Middleware for MCP Servers
 * 
 * Filters tools based on X-MCP-Tools header, supporting:
 * - Toolsets: repository, cicd, integration, users, monitoring, etc.
 * - Individual tools: server_specific_tool_name, another_tool_name
 * - Mixed: repository,specific_tool_name,cicd
 * 
 * Design Pattern:
 * - Header missing => allow ALL tools
 * - Header empty => allow NO tools  
 * - Header with values => allow only specified toolsets + individual tools
 * 
 * This middleware is reusable across all TypeScript MCP servers.
 */

export interface Tool {
  name: string;
  description: string;
  [key: string]: any;
}

export interface ToolFilterOptions {
  /**
   * The header name to look for (default: 'x-mcp-tools')
   */
  headerName?: string;
  
  /**
   * Server name for logging (e.g., 'GitLab', 'Meraki', 'AWS')
   */
  serverName?: string;
  
  /**
   * Function to get toolsets mapping (toolset name -> Set of tool names)
   */
  getToolsets: () => Record<string, Set<string>>;
  
  /**
   * Function to validate if a name is a valid individual tool
   */
  isValidTool: (toolName: string) => boolean;
}

export class ToolFilterMiddleware {
  private readonly headerName: string;
  private readonly serverName: string;
  private readonly getToolsets: () => Record<string, Set<string>>;
  private readonly isValidTool: (toolName: string) => boolean;

  constructor(options: ToolFilterOptions) {
    this.headerName = options.headerName || 'x-mcp-tools';
    this.serverName = options.serverName || 'MCP';
    this.getToolsets = options.getToolsets;
    this.isValidTool = options.isValidTool;
  }

  /**
   * Expand toolset names into individual tool names.
   * 
   */
  private expandToolsets(names: Set<string>): Set<string> {
    const expanded = new Set<string>();

    try {
      const toolsets = this.getToolsets();

      // Validate toolsets is a valid object
      if (!toolsets || typeof toolsets !== 'object') {
        console.error(`[${this.serverName}] Invalid toolsets data returned`);
        return expanded; // Return empty set as fallback
      }

      // Process each name with individual error handling
      for (const name of names) {
        try {
          const toolset = toolsets[name];

          if (toolset && toolset.size > 0) {
            // It's a toolset with tools - expand to multiple tools
            console.log(`[${this.serverName}] Expanding toolset '${name}' -> ${[...toolset].join(', ')}`);
            toolset.forEach(tool => expanded.add(tool));
          } else {
            // Check if it's a valid individual tool name
            if (this.isValidTool(name)) {
              // It's a valid individual tool - add it
              console.log(`[${this.serverName}] Adding individual tool '${name}'`);
              expanded.add(name);
            } else {
              // Unknown name - log warning but don't fail
              console.warn(`[${this.serverName}] Unknown toolset or tool name: '${name}'`);
            }
          }
        } catch (itemError) {
          // Log error for this specific item but continue processing others
          console.error(`[${this.serverName}] Error processing item '${name}':`, itemError);
          // Continue processing other items
        }
      }
    } catch (error) {
      console.error(`[${this.serverName}] ToolFilterMiddleware.expandToolsets failed:`, error);
    }

    return expanded;
  }

  /**
   * Extract and parse the X-MCP-Tools header value.
   * Returns null if header missing (allow all), Set if present
   */
  private getHeaderCandidates(headers: Record<string, any>): Set<string> | null {
    try {
      // Normalize headers to lowercase for case-insensitive lookup
      const normalizedHeaders: Record<string, any> = {};
      Object.keys(headers).forEach(key => {
        normalizedHeaders[key.toLowerCase()] = headers[key];
      });

      const rawValue = normalizedHeaders[this.headerName.toLowerCase()];

      // Header missing or undefined => allow ALL tools
      if (rawValue === undefined) {
        console.log(`[${this.serverName}] Header '${this.headerName}' missing => allow ALL tools`);
        return null;
      }

      const trimmedValue = String(rawValue).trim();

      // Header present but empty => allow NO tools
      if (trimmedValue === '') {
        console.log(`[${this.serverName}] Header '${this.headerName}' empty => allow NO tools`);
        return new Set();
      }

      // Parse comma-separated values
      const items = new Set(
        trimmedValue.split(',')
          .map(item => item.trim())
          .filter(item => item.length > 0)
      );

      if (items.size === 0) {
        return new Set();
      }

      console.log(`[${this.serverName}] Header '${this.headerName}' items: ${[...items].join(', ')}`);
      return this.expandToolsets(items);

    } catch (error) {
      console.error(`[${this.serverName}] ToolFilterMiddleware.getHeaderCandidates failed:`, error);
      // Safe fallback: deny all tools
      return new Set();
    }
  }

  /**
   * Filter tools based on X-MCP-Tools header.
   */
  public filterTools(tools: Tool[], headers: Record<string, any> = {}): Tool[] {
    try {
      const headerCandidates = this.getHeaderCandidates(headers);

      // Header missing => return all tools
      if (headerCandidates === null) {
        console.log(`[${this.serverName}] No tool filtering - returning all ${tools.length} tools`);
        return tools;
      }

      // Header empty => return no tools
      if (headerCandidates.size === 0) {
        console.log(`[${this.serverName}] Empty tool filter - returning 0 tools`);
        return [];
      }

      // Filter tools by allowed names
      const allowedNames = new Set([...tools.map(t => t.name)].filter(name => headerCandidates.has(name)));
      
      if (allowedNames.size === 0) {
        console.log(`[${this.serverName}] No matching tools found - returning 0 tools`);
        return [];
      }

      const filteredTools = tools.filter(tool => allowedNames.has(tool.name));
      console.log(`[${this.serverName}] Filtered to ${filteredTools.length} tools: ${[...allowedNames].join(', ')}`);
      
      return filteredTools;

    } catch (error) {
      console.error(`[${this.serverName}] ToolFilterMiddleware.filterTools failed:`, error);
      throw error;
    }
  }

  /**
   * Check if a specific tool is allowed by current headers
   */
  public isToolAllowed(toolName: string, headers: Record<string, any> = {}): boolean {
    const headerCandidates = this.getHeaderCandidates(headers);
    
    // Header missing => allow all
    if (headerCandidates === null) {
      return true;
    }
    
    // Header empty => allow none
    if (headerCandidates.size === 0) {
      return false;
    }
    
    return headerCandidates.has(toolName);
  }

  /**
   * Get statistics about filtering
   */
  public getFilterStats(headers: Record<string, any> = {}): {
    headerPresent: boolean;
    allowAll: boolean;
    allowNone: boolean;
    allowedTools: string[];
    serverName: string;
  } {
    const headerCandidates = this.getHeaderCandidates(headers);
    
    return {
      headerPresent: headerCandidates !== null,
      allowAll: headerCandidates === null,
      allowNone: headerCandidates !== null && headerCandidates.size === 0,
      allowedTools: headerCandidates ? [...headerCandidates] : [],
      serverName: this.serverName,
    };
  }
}

/**
 * Factory function to create a configured tool filter middleware
 */
export function createToolFilterMiddleware(options: ToolFilterOptions): ToolFilterMiddleware {
  return new ToolFilterMiddleware(options);
}

/**
 * Type definitions for better TypeScript integration
 */
export type ToolFilterStatsResult = ReturnType<ToolFilterMiddleware['getFilterStats']>;

/**
 * Helper function for common FastMCP integration pattern
 */
export function createFilteredTool<T extends Tool>(
  tool: T,
  middleware: ToolFilterMiddleware
): T & { canAccess: (auth: any) => boolean } {
  return {
    ...tool,
    canAccess: (auth: any) => {
      const headers = auth?.headers || {};
      const allowed = middleware.isToolAllowed(tool.name, headers);
      return allowed;
    }
  };
}
