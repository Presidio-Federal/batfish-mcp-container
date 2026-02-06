/**
 * Generic Tag-Based Dynamic Toolset 
 * 
 * Usage examples:
 * - X-MCP-Tools: repository,cicd
 * - X-MCP-Tools: repository,specific_tool_name,cicd
 * - X-MCP-Tools: tool1,tool2,toolset3
 */

/**
 * Interface for tools with tags
 */
export interface TaggedTool {
  name: string;
  description?: string;
  tags?: string[];
  [key: string]: any;
}

/**
 * Configuration for toolset descriptions
 */
export interface ToolsetConfig {
  /**
   * Custom descriptions for toolsets
   */
  descriptions?: Record<string, string>;

  /**
   * Server name for logging
   */
  serverName?: string;
}

/**
 * Dynamic Tag-Based Toolsets Manager
 * Builds toolsets from tool tags at runtime
 */
export class TagBasedToolsetsManager {
  private registeredTools: Map<string, TaggedTool> = new Map();
  private toolsetCache: Map<string, Set<string>> = new Map();
  private readonly serverName: string;
  private readonly descriptions: Record<string, string>;

  constructor(config: ToolsetConfig = {}) {
    this.serverName = config.serverName || 'MCP';
    this.descriptions = {
      // Common toolset descriptions
      repository: 'Repository Management - Projects, branches, merge requests, issues, and files',
      cicd: 'CI/CD Management - Pipeline triggers, variables, and automation',
      integration: 'Integration Management - Webhooks, external services, and integrations', 
      users: 'User & Group Management - User operations, groups, and membership',
      monitoring: 'Monitoring & Analytics - Metrics, logs, and monitoring tools',
      security: 'Security & Permissions - Access control and security features',
      api: 'API Management - API keys, tokens, and API operations',
      deployment: 'Deployment & Infrastructure - Container and infrastructure management',
      network: 'Network Management - Networking, routing, and connectivity tools',
      storage: 'Storage Management - File systems, databases, and storage resources',
      compute: 'Compute Resources - Virtual machines, containers, and processing power',
      automation: 'Automation & Orchestration - Workflow and task automation',
      reporting: 'Reports & Analytics - Data analysis and reporting tools',
      configuration: 'Configuration Management - Settings and configuration tools',
      ...config.descriptions
    };
  }
  
  /**
   * Validate and normalize a tool before registration
   * @private
   */
  private validateAndNormalizeTool(tool: TaggedTool): void {
    // Validate tool name
    if (!tool.name || typeof tool.name !== 'string' || tool.name.trim() === '') {
      throw new Error(`Invalid tool name: Tool name must be a non-empty string`);
    }

    // Check for duplicates
    if (this.registeredTools.has(tool.name)) {
      console.warn(`[${this.serverName}] Tool '${tool.name}' already registered - overwriting`);
    }

    // Validate tags if present
    if (tool.tags) {
      if (!Array.isArray(tool.tags)) {
        throw new Error(`Invalid tags for tool '${tool.name}': Tags must be an array`);
      }

      // Filter out invalid tags
      const invalidTags = tool.tags.filter(tag =>
        !tag || typeof tag !== 'string' || tag.trim() === ''
      );

      if (invalidTags.length > 0) {
        throw new Error(`Invalid tags for tool '${tool.name}': Tags must be non-empty strings`);
      }

      // Normalize tags (lowercase, trim whitespace)
      tool.tags = tool.tags.map(tag => tag.trim().toLowerCase());
    }
  }

  /**
   * Register a tool with its tags
   */
  registerTool(tool: TaggedTool): void {
    this.validateAndNormalizeTool(tool);
    this.registeredTools.set(tool.name, tool);
    this.invalidateCache();
  }
  
  /**
   * Register multiple tools at once
   */
  registerTools(tools: TaggedTool[]): void {
    for (const tool of tools) {
      // Validate and normalize, but don't invalidate cache individually
      this.validateAndNormalizeTool(tool);
      this.registeredTools.set(tool.name, tool);
    }
    // Invalidate cache once after all tools are registered
    this.invalidateCache();
    // Build cache
    this.ensureCacheValid();
  }
  
  /**
   * Get tools for a specific toolset/tag
   */
  getToolsForToolset(toolsetName: string): Set<string> {
    this.ensureCacheValid();
    return this.toolsetCache.get(toolsetName) || new Set();
  }
  
  /**
   * Get all available toolsets
   */
  getAvailableToolsets(): string[] {
    this.ensureCacheValid();
    return Array.from(this.toolsetCache.keys());
  }
  
  /**
   * Check if a toolset exists
   */
  hasToolset(toolsetName: string): boolean {
    this.ensureCacheValid();
    return this.toolsetCache.has(toolsetName);
  }
  
  /**
   * Get all registered tools
   */
  getAllTools(): Set<string> {
    return new Set(this.registeredTools.keys());
  }
  
  /**
   * Check if a tool exists
   */
  hasTool(toolName: string): boolean {
    return this.registeredTools.has(toolName);
  }
  
  /**
   * Get tool tags
   */
  getToolTags(toolName: string): string[] {
    const tool = this.registeredTools.get(toolName);
    if (!tool) return [];
    
    return tool.tags || [];
  }
  
  /**
   * Generate toolset information for debugging/documentation
   */
  getToolsetInfo() {
    this.ensureCacheValid();
    return Array.from(this.toolsetCache.entries()).map(([name, tools]) => ({
      name,
      toolCount: tools.size,
      tools: Array.from(tools),
      description: this.getToolsetDescription(name)
    }));
  }
  
  /**
   * Get toolsets mapping for middleware integration
   */
  getToolsetsMapping(): Record<string, Set<string>> {
    this.ensureCacheValid();
    const mapping: Record<string, Set<string>> = {};
    for (const [toolsetName, tools] of this.toolsetCache.entries()) {
      mapping[toolsetName] = new Set(tools);
    }
    return mapping;
  }
  
  /**
   * Get description for a toolset based on its name
   */
  private getToolsetDescription(toolsetName: string): string {
    return this.descriptions[toolsetName] || 
           `${toolsetName.charAt(0).toUpperCase() + toolsetName.slice(1)} tools`;
  }
  
  /**
   * Rebuild cache from registered tools' tags
   */
  private rebuildCache(): void {
    this.toolsetCache.clear();

    // Process each registered tool
    for (const [toolName, tool] of this.registeredTools.entries()) {
      const tags = tool.tags || [];

      // Add tool to each of its tags
      for (const tag of tags) {
        if (!this.toolsetCache.has(tag)) {
          this.toolsetCache.set(tag, new Set());
        }
        this.toolsetCache.get(tag)!.add(toolName);
      }
    }
  }
  
  /**
   * Ensure cache is valid (rebuild if needed)
   */
  private ensureCacheValid(): void {
    if (this.toolsetCache.size === 0) {
      this.rebuildCache();
    }
  }
  
  /**
   * Clear cache to force rebuild
   */
  private invalidateCache(): void {
    this.toolsetCache.clear();
  }

  /**
   * Create proxy-based toolsets with configurable return type
   * Generic base method to avoid code duplication 
   * @private
   */
  private createToolsetsProxyBase<T>(
    transformer: (tools: Set<string>) => T
  ): Record<string, T> {
    return new Proxy({} as Record<string, T>, {
      get: (_target, prop: string) => {
        if (typeof prop === 'string') {
          const tools = this.getToolsForToolset(prop);
          return transformer(tools);
        }
        return undefined;
      },
      ownKeys: (_target) => {
        return this.getAvailableToolsets();
      },
      has: (_target, prop: string) => {
        return this.hasToolset(prop);
      }
    });
  }

  /**
   * Create proxy-based toolsets for backward compatibility
   * Returns tools as arrays for easier consumption
   */
  createToolsetsProxy(): Record<string, string[]> {
    return this.createToolsetsProxyBase(tools => Array.from(tools));
  }

  /**
   * Create proxy-based expanded toolsets for middleware
   * Returns tools as Sets for direct use in filtering
   */
  createExpandedToolsetsProxy(): Record<string, Set<string>> {
    return this.createToolsetsProxyBase(tools => tools);
  }
}

/**
 * Factory function to create a configured toolsets manager
 */
export function createTagBasedToolsetsManager(config: ToolsetConfig = {}): TagBasedToolsetsManager {
  return new TagBasedToolsetsManager(config);
}

/**
 * Helper functions for common operations
 */
export function initializeToolsets(manager: TagBasedToolsetsManager, tools: TaggedTool[]): void {
  manager.registerTools(tools);
}

/**
 * Validation helpers
 */
export function isValidToolset(manager: TagBasedToolsetsManager, name: string): boolean {
  return manager.hasToolset(name);
}

export function isValidTool(manager: TagBasedToolsetsManager, name: string): boolean {
  return manager.hasTool(name);
}

export function getToolTags(manager: TagBasedToolsetsManager, toolName: string): string[] {
  return manager.getToolTags(toolName);
}