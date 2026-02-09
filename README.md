# Batfish MCP Container

A Model Context Protocol (MCP) server that makes [Batfish](https://www.batfish.org/) network analysis accessible through AI agents like Claude.

---

## What is Batfish?

**Batfish** is a powerful network validation and analysis framework that can model your entire network infrastructure—routers, switches, firewalls, cloud environments—and answer complex questions about network behavior without touching production systems.

### Why Batfish Matters

- **Pre-deployment Validation**: Test configuration changes before applying them to production
- **Security Analysis**: Identify misconfigurations, ACL gaps, and security vulnerabilities
- **Compliance Checking**: Verify network designs against industry standards (ISA-95, Purdue Model, NIST CSF)
- **Impact Analysis**: Understand how changes will affect network behavior
- **Multi-vendor Support**: Works with Cisco, Juniper, Arista, Palo Alto, AWS, and more

### The Challenge

While Batfish is incredibly powerful, it requires:
- Deep understanding of network analysis concepts
- Knowledge of Batfish's query language and API
- Manual data formatting and loading
- Complex query construction for analysis

This complexity has limited Batfish adoption to network analysis experts.

---

## Why This MCP Container Changes Everything

This container exposes **50+ Batfish tools through the Model Context Protocol (MCP)**, enabling AI agents like Claude to interact with Batfish through natural language.

### What This Enables

**Before (Traditional Batfish):**
```python
# Complex API calls, data formatting, query construction
bf = Session(host="batfish")
bf.init_snapshot("network", name="snapshot1", overwrite=True)
bf.q.reachability().answer()
```

**After (With MCP + AI Agent):**
```
"Analyze my network for devices that can reach the internet"
"Check if my firewall rules allow SSH from the DMZ to production"
"Load my AWS environment and find security group misconfigurations"
```

The AI agent:
1. **Understands intent** - Translates natural language to appropriate Batfish operations
2. **Handles data** - Formats network configs and loads them correctly
3. **Performs analysis** - Executes the right sequence of Batfish tools
4. **Explains results** - Interprets complex output in clear language

This democratizes network analysis—anyone can now leverage Batfish's power through conversation.

---

## What's In This Repository

This repository contains everything needed to deploy the Batfish MCP Container:

- **`batfish/`** - MCP server implementation and 50+ Batfish tools
- **`middleware/`** - Tool filtering and organization middleware
- **`docker-compose.yml`** - Complete two-container stack (Batfish + MCP)
- **`.github/workflows/`** - Automated CI/CD to GitHub Container Registry
- **`docs/`** - Deployment guides, troubleshooting, and contribution guidelines

The container architecture:
```
┌─────────────────────────────┐
│   AI Agent (Claude, etc.)   │
│                             │
└──────────┬──────────────────┘
           │ MCP Protocol
┌──────────▼──────────────────┐
│   Batfish MCP Container     │  ← This repo builds this
│   (50+ Network Tools)       │
└──────────┬──────────────────┘
           │ Batfish API
┌──────────▼──────────────────┐
│  Batfish All-in-One         │
│  (Analysis Engine)          │
└─────────────────────────────┘
```

---

## Table of Contents

### Deploying the Container
[Complete deployment guide](docs/DEPLOYMENT.md) covering:
- Docker Compose setup
- Cloud deployments (AWS ECS, Azure Container Instances, Google Cloud Run)
- Production configuration with authentication
- Docker Swarm orchestration
- Backup and recovery strategies

### Loading Your Data
[Data loading guide](docs/LOADING_DATA.md)

Learn the three methods for loading network configurations into Batfish:
- Incremental loading with staging (best for large networks)
- Base64 ZIP upload (simple one-shot method)
- GitHub integration (most token-efficient method)

### Using the Tools
[Tool usage guide](docs/TOOLS.md) - Coming Soon

Comprehensive guide to available Batfish tools:
- Network analysis tools (topology, routing, reachability)
- AWS security analysis tools
- Compliance and classification tools
- Snapshot management and initialization

### Troubleshooting
[Troubleshooting guide](docs/TROUBLESHOOTING.md) - Coming Soon

Common issues and solutions:
- Container startup problems
- Authentication issues
- Batfish connectivity
- Performance tuning

### Contributing
[Contributing guidelines](docs/CONTRIBUTING.md)

Guidelines for contributing to this project

---

## Quick Start

### Prerequisites
- Docker and Docker Compose
- 4GB+ RAM for Docker

### 1. Build the Container

```bash
git clone https://github.com/presidio-federal/batfish-mcp-container.git
cd batfish-mcp-container
docker build -t batfish-mcp:latest -f batfish/dockerfile .
```

### 2. Start the Services

```bash
docker-compose up -d
```

This starts:
- **batfish** - The Batfish analysis engine
- **batfish-mcp** - The MCP server with tools

### 3. Configure Your AI Agent

Add to Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "batfish": {
      "url": "http://localhost:3009/mcp"
    }
  }
}
```

Restart Claude Desktop.

### 4. Start Analyzing

```
"Show me what networks are currently loaded in Batfish"
"Load my router configs and analyze network segmentation"
"Check my AWS environment for security group misconfigurations"
```

For detailed deployment instructions, see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

---

## Available Tools

The MCP server exposes 50+ tools organized by category:

| Category | Tools | Purpose |
|----------|-------|---------|
| **Initialize** | 10+ tools | Load network configs, AWS snapshots, GitHub repos |
| **Network** | 20+ tools | Topology, routing, reachability, VLANs, ACLs |
| **AWS** | 10+ tools | Security groups, internet exposure, routing |
| **Compliance** | 5+ tools | Device classification, zone compliance (ISA-95, Purdue, NIST) |
| **Management** | 5+ tools | List/delete networks and snapshots |

See [batfish/README.md](batfish/README.md) for complete tool documentation.

---

## Architecture

### Two-Container Design

1. **Batfish Container** (Official batfish/allinone)
   - Network analysis engine
   - Configuration parser
   - Data storage

2. **Batfish MCP Container** (This repository)
   - FastMCP server
   - 50+ Batfish tool wrappers
   - Authentication (optional Azure AD)
   - Tool filtering and organization

### Why MCP?

The [Model Context Protocol](https://modelcontextprotocol.io/) is an open standard for connecting AI agents to external tools and data sources. By implementing Batfish as MCP tools, any MCP-compatible AI agent can use Batfish capabilities.

---

## GitHub Actions CI/CD

This repository includes automated builds:
- Builds on every push to `main` (when container code changes)
- Publishes to GitHub Container Registry (GHCR)
- Multi-platform support (linux/amd64, linux/arm64)
- Semantic versioning with git tags

Images available at:
```
ghcr.io/presidio-federal/batfish-mcp-container:latest
ghcr.io/presidio-federal/batfish-mcp-container:v1.0.0
```

---

## Documentation

- **[Quick Start](docs/QUICKSTART.md)** - Get running in 5 minutes
- **[Deployment Guide](docs/DEPLOYMENT.md)** - Production deployment
- **[Contributing Guide](docs/CONTRIBUTING.md)** - Development setup
- **[Tool Reference](batfish/README.md)** - Complete tool documentation

---

## Support

- Issues: [GitHub Issues](https://github.com/presidio-federal/batfish-mcp-container/issues)
- Discussions: [GitHub Discussions](https://github.com/presidio-federal/batfish-mcp-container/discussions)
- Batfish Docs: [www.batfish.org](https://www.batfish.org/)
- MCP Spec: [modelcontextprotocol.io](https://modelcontextprotocol.io/)

---

## License

MIT License - see [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- [Batfish](https://www.batfish.org/) - The powerful network analysis framework this builds upon
- [FastMCP](https://github.com/jlowin/fastmcp) - The Python MCP server framework
- [Anthropic](https://www.anthropic.com/) - For the Model Context Protocol specification
