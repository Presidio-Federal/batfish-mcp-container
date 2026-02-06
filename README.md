# Batfish MCP Container

A FastMCP (Model Context Protocol) server that provides an interface to [Batfish](https://www.batfish.org/) network analysis capabilities. This container acts as a sidecar to the official Batfish all-in-one container, exposing Batfish's powerful network validation and analysis tools through a modern MCP interface.

## What is This?

This project provides:

1. **Batfish MCP Server**: A FastMCP server that wraps Batfish's network analysis capabilities
2. **MCP Tools**: 50+ network analysis tools organized into categories:
   - **Initialization**: Load network configs, AWS snapshots (supports incremental loading)
   - **Management**: List/delete networks and snapshots
   - **Network Analysis**: Topology, reachability, routing, ACLs, VLANs
   - **AWS Analysis**: Security groups, routing, internet exposure, subnet segmentation
   - **Compliance**: Device classification, zone compliance checking (ISA-95, Purdue, NIST CSF)
   - **Testing**: Tagged tests, failure impact analysis

3. **Container Architecture**: Two-container design with Docker Compose orchestration
   - **Batfish Container**: Official Batfish all-in-one container (network analysis engine)
   - **Batfish MCP Container**: FastMCP server that communicates with Batfish

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         Client (MCP)                         │
│                    (Claude, AI Tools, etc.)                  │
└────────────────────────────┬────────────────────────────────┘
                             │ HTTP/MCP Protocol
                             │ Port 3009
┌────────────────────────────▼────────────────────────────────┐
│                    Batfish MCP Container                     │
│              (FastMCP Server + Tool Library)                 │
└────────────────────────────┬────────────────────────────────┘
                             │ Batfish API
                             │ Port 9996
┌────────────────────────────▼────────────────────────────────┐
│                   Batfish All-in-One Container               │
│              (Network Analysis Engine + Storage)             │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Docker and Docker Compose installed
- GitHub account (for pulling from GHCR)

### Option 1: Using Docker Compose (Recommended)

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/batfish-mcp-container.git
   cd batfish-mcp-container
   ```

2. **Configure environment variables:**
   ```bash
   cp .env.example .env
   # Edit .env with your settings (optional, defaults work for local testing)
   ```

3. **Update docker-compose.yml with your GitHub username:**
   ```bash
   # Edit docker-compose.yml and replace 'yourusername' with your GitHub username
   # Or set GITHUB_REPOSITORY environment variable
   export GITHUB_REPOSITORY=yourusername/batfish-mcp-container
   ```

4. **Start the containers:**
   ```bash
   docker-compose up -d
   ```

5. **Verify the containers are running:**
   ```bash
   docker-compose ps
   docker-compose logs batfish-mcp
   ```

6. **Test the MCP server:**
   ```bash
   curl -X POST http://localhost:3009/mcp \
     -H "Content-Type: application/json" \
     -H "Accept: application/json, text/event-stream" \
     -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'
   ```

### Option 2: Using Pre-built Image from GHCR

Pull the latest image:
```bash
docker pull ghcr.io/yourusername/batfish-mcp-container:latest
```

Run with Docker Compose as shown above, or manually:
```bash
# Start Batfish
docker run -d --name batfish \
  -p 9996:9996 -p 9997:9997 \
  -v batfish-data:/data \
  batfish/allinone:latest

# Start Batfish MCP
docker run -d --name batfish-mcp \
  -p 3009:3009 \
  -e BATFISH_HOST=batfish \
  -e DISABLE_JWT_AUTH=true \
  --link batfish:batfish \
  ghcr.io/yourusername/batfish-mcp-container:latest
```

### Option 3: Building Locally

1. **Clone and build:**
   ```bash
   git clone https://github.com/yourusername/batfish-mcp-container.git
   cd batfish-mcp-container
   docker build -t batfish-mcp:latest -f batfish/dockerfile .
   ```

2. **Run with Docker Compose:**
   ```bash
   # Edit docker-compose.yml to use 'batfish-mcp:latest' instead of GHCR image
   docker-compose up -d
   ```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BATFISH_HOST` | `localhost` | Hostname of the Batfish service |
| `BATFISH_PORT` | `9996` | Port of the Batfish service |
| `DISABLE_JWT_AUTH` | `false` | Set to `true` to disable JWT authentication (dev mode) |
| `AZURE_AD_TENANT_ID` | - | Azure AD tenant ID (required if auth enabled) |
| `AZURE_AD_CLIENT_ID` | - | Azure AD client ID (optional for audience validation) |
| `ENABLE_AUTH_LOGGING` | `false` | Enable detailed authentication logging |
| `PORT` | `3009` | HTTP port for the MCP server |
| `HOST` | `0.0.0.0` | Bind address for the server |
| `TRANSPORT` | `http` | Transport type (http or stdio) |

### Authentication Modes

#### Development Mode (Default in Docker Compose)
```bash
DISABLE_JWT_AUTH=true
```
- No JWT token required
- Useful for local testing and development
- **Not recommended for production**

#### Production Mode
```bash
DISABLE_JWT_AUTH=false
AZURE_AD_TENANT_ID=your-tenant-id
AZURE_AD_CLIENT_ID=your-client-id
```
- Requires valid JWT token in `Authorization: Bearer <token>` header
- Validates tokens against Azure AD
- Recommended for production deployments

## Available MCP Tools

The server exposes 50+ tools organized into categories. Here are some highlights:

### Network Analysis
- `network.summary` - Get comprehensive network overview
- `network.segment` - Analyze network segmentation
- `network.topology_connections` - View device connections
- `network.traceroute` - Simulate network paths
- `network.reachability_summary` - Test connectivity between zones

### AWS Analysis
- `aws.reachability` - Test AWS security group rules
- `aws.internet_exposure` - Find internet-exposed resources
- `aws.subnet_segmentation` - Analyze VPC segmentation
- `aws.security_evaluation` - Comprehensive security assessment

### Compliance
- `compliance.check_zone_compliance` - Validate against ISA-95, Purdue, or NIST CSF
- `compliance.auto_classify_zones` - Automatically classify network zones
- `compliance.get_enforcement_points` - Identify security boundaries

### Initialization
- `initialize.snapshot` - Load network device configs
- `initialize.aws_init_snapshot` - Load AWS configuration
- `initialize.aws_add_data_chunk` - Incremental AWS data loading (for large environments)
- `initialize.github_snapshot` - Load configs from GitHub repository

For a complete list of tools, see [batfish/README.md](batfish/README.md).

## Usage Examples

### Example 1: Analyze Network Segmentation

```bash
# 1. Load network configuration
curl -X POST http://localhost:3009/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "initialize.snapshot",
      "arguments": {
        "network": "my-network",
        "snapshot": "baseline",
        "configs": {
          "router1.cfg": "...",
          "switch1.cfg": "..."
        }
      }
    }
  }'

# 2. Analyze segmentation
curl -X POST http://localhost:3009/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
      "name": "network.segment",
      "arguments": {
        "network": "my-network",
        "snapshot": "baseline"
      }
    }
  }'
```

### Example 2: AWS Security Analysis

```bash
# Load AWS snapshot and check for internet exposure
curl -X POST http://localhost:3009/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "aws.internet_exposure",
      "arguments": {
        "network": "aws-prod",
        "snapshot": "current"
      }
    }
  }'
```

## GitHub Actions CI/CD

This repository includes a GitHub Actions workflow that automatically:

1. **Builds** the Docker image on every push to `main`
2. **Pushes** the image to GitHub Container Registry (GHCR)
3. **Tags** images based on:
   - Branch name (e.g., `main`)
   - Git tags (e.g., `v1.0.0`, `v1.0`, `v1`)
   - Git SHA (e.g., `main-abc1234`)
   - `latest` tag for the default branch

### Setting Up GitHub Actions

The workflow is already configured in `.github/workflows/build-and-push.yml`. To use it:

1. **Enable GitHub Actions** in your repository settings
2. **Make your package public** (or configure access):
   - Go to your repository on GitHub
   - Navigate to "Packages" after the first build
   - Make the package public or configure access as needed

3. **Push to trigger a build:**
   ```bash
   git add .
   git commit -m "Initial commit"
   git push origin main
   ```

4. **Create releases with tags:**
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```

The image will be available at:
```
ghcr.io/yourusername/batfish-mcp-container:latest
ghcr.io/yourusername/batfish-mcp-container:v1.0.0
ghcr.io/yourusername/batfish-mcp-container:main
```

## Deployment

### Docker Compose (Production)

For production deployments with authentication:

1. **Create `.env` file:**
   ```bash
   DISABLE_JWT_AUTH=false
   AZURE_AD_TENANT_ID=your-tenant-id
   AZURE_AD_CLIENT_ID=your-client-id
   ENABLE_AUTH_LOGGING=true
   GITHUB_REPOSITORY=yourusername/batfish-mcp-container
   ```

2. **Deploy:**
   ```bash
   docker-compose up -d
   ```

3. **Monitor:**
   ```bash
   docker-compose logs -f batfish-mcp
   ```

### Kubernetes

For Kubernetes deployments, see the example manifests in the `k8s/` directory (coming soon).

## Troubleshooting

### Container won't start

Check logs:
```bash
docker-compose logs batfish-mcp
```

Common issues:
- Batfish container not ready: Wait for healthcheck to pass
- Port conflict: Change port in docker-compose.yml
- Authentication error: Set `DISABLE_JWT_AUTH=true` for testing

### Connection refused errors

Make sure Batfish is running:
```bash
docker-compose ps batfish
curl http://localhost:9996/
```

### Authentication issues

Test without auth:
```bash
docker-compose down
# Edit .env: DISABLE_JWT_AUTH=true
docker-compose up -d
```

## Development

### Local Development Setup

1. **Install Python dependencies:**
   ```bash
   cd batfish
   pip install -r requirements.txt
   ```

2. **Start Batfish container:**
   ```bash
   docker run -d --name batfish -p 9996:9996 -p 9997:9997 batfish/allinone:latest
   ```

3. **Run the server locally:**
   ```bash
   cd batfish
   export BATFISH_HOST=localhost
   export DISABLE_JWT_AUTH=true
   python -m server
   ```

### Building the Container

```bash
docker build -t batfish-mcp:dev -f batfish/dockerfile .
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [Batfish](https://www.batfish.org/) - Network validation and analysis framework
- [FastMCP](https://github.com/jlowin/fastmcp) - Model Context Protocol server framework

## Support

For issues and questions:
- GitHub Issues: [Create an issue](https://github.com/yourusername/batfish-mcp-container/issues)
- Batfish Documentation: [www.batfish.org](https://www.batfish.org/)
- FastMCP Documentation: [FastMCP Docs](https://github.com/jlowin/fastmcp)
