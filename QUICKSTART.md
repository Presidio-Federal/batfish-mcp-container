# Quick Start Guide

This guide will help you get up and running with Batfish MCP Container in 5 minutes.

## Prerequisites

- Docker and Docker Compose installed
- 4GB+ RAM available for Docker
- Ports 3009, 9996, and 9997 available

## Step 1: Get the Code

```bash
git clone https://github.com/yourusername/batfish-mcp-container.git
cd batfish-mcp-container
```

## Step 2: Build the Container

```bash
docker build -t batfish-mcp:latest -f batfish/dockerfile .
```

This will take a few minutes the first time.

## Step 3: Start the Services

```bash
docker-compose up -d
```

This starts two containers:
- `batfish` - The Batfish network analysis engine
- `batfish-mcp` - The MCP server interface

## Step 4: Verify It's Running

```bash
# Check container status
docker-compose ps

# View logs
docker-compose logs batfish-mcp

# Should see output like:
# INFO: Uvicorn running on http://0.0.0.0:3009
```

## Step 5: Test the Server

```bash
curl -X POST http://localhost:3009/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/list",
    "params": {}
  }'
```

You should see a JSON response with available MCP tools.

## Next Steps

### Use with Claude Desktop

Add to your Claude Desktop MCP config (`~/Library/Application Support/Claude/claude_desktop_config.json` on Mac):

```json
{
  "mcpServers": {
    "batfish": {
      "url": "http://localhost:3009/mcp"
    }
  }
}
```

### Example: Analyze a Network

```bash
# 1. List networks (should be empty initially)
curl -X POST http://localhost:3009/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
      "name": "management.list_networks",
      "arguments": {}
    }
  }'

# 2. Load a network snapshot (example with router config)
curl -X POST http://localhost:3009/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {
      "name": "initialize.snapshot",
      "arguments": {
        "network": "my-network",
        "snapshot": "baseline",
        "configs": {
          "router1.cfg": "hostname router1\ninterface GigabitEthernet0/0\n ip address 10.0.1.1 255.255.255.0"
        }
      }
    }
  }'
```

## Common Commands

### View Logs
```bash
docker-compose logs -f batfish-mcp
```

### Restart Services
```bash
docker-compose restart
```

### Stop Services
```bash
docker-compose down
```

### Clean Up Everything
```bash
docker-compose down -v  # Warning: deletes data!
```

## Troubleshooting

### Container won't start
```bash
# Check logs
docker-compose logs batfish-mcp

# Check if ports are in use
lsof -i :3009
lsof -i :9996
```

### Connection refused
```bash
# Make sure Batfish is healthy
docker-compose ps batfish

# Check Batfish logs
docker-compose logs batfish
```

### Out of memory
```bash
# Increase Docker memory in Docker Desktop settings
# Recommended: 4GB minimum, 8GB for large networks
```

## What's Next?

- Read the [full README](README.md) for detailed documentation
- Check out [DEPLOYMENT.md](DEPLOYMENT.md) for production setup
- Review [available tools](batfish/README.md) in the Batfish documentation
- See [CONTRIBUTING.md](CONTRIBUTING.md) to contribute

## Getting Help

- [Open an issue](https://github.com/yourusername/batfish-mcp-container/issues)
- [Check discussions](https://github.com/yourusername/batfish-mcp-container/discussions)
- [Batfish documentation](https://www.batfish.org/)
