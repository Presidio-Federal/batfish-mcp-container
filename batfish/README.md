# Batfish MCP Server

This server provides a FastMCP interface to Batfish network analysis capabilities.

## Prerequisites

1. Install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

2. Make sure you have a Batfish service running:
   - You can run the standard Batfish all-in-one container using Docker:
     ```bash
     docker run --name batfish -v batfish-data:/data -p 9996:9996 -p 9997:9997 -d batfish/batfish
     ```
   - Or specify a remote Batfish service using environment variables or headers

## Architecture

This solution uses two containers:

1. **Standard Batfish Container**: The official Batfish all-in-one container that provides the core network analysis capabilities.

2. **Batfish MCP Container**: A sidecar container that provides the FastMCP interface to Batfish.

**Security Note**: There is no authentication between the Batfish container and the Batfish MCP container. It is recommended to run them on the same host and allow them to communicate over the Docker network to avoid exposing the Batfish container directly.

## Running the Server

### Option 1: Run Directly

Run the server directly:

```bash
cd src/servers/batfish
python server.py
```

Or from the project root:

```bash
python -m src.servers.batfish.server
```

### Option 2: Docker Container

Build the Batfish MCP container:

```bash
docker build -t batfish-mcp:latest -f src/servers/batfish/Dockerfile .
```

Run the container:

```bash
docker run --rm -it \
  -p 3009:3009 \
  --env-file .env \
  --env BATFISH_HOST=batfish \
  --network batfish-net \
  --env DISABLE_JWT_AUTH=false \
  batfish-mcp:latest
```

## Environment Variables

- `BATFISH_HOST`: Hostname of the Batfish service (default: localhost)
- `BATFISH_PORT`: Port of the Batfish service (default: 9996)
- `TRANSPORT`: Transport type (http or stdio, default: http)
- `PORT`: HTTP port for the server (default: 3009)
- `HOST`: Bind address for the server (default: 0.0.0.0)
- `DISABLE_JWT_AUTH`: Set to "true" to disable JWT authentication (for development)
- `ENABLE_AUTH_LOGGING`: Set to "true" to enable authentication logging

## Request Headers

- `X-BATFISH-HOST`: Override the Batfish host for a specific request
- `X-BATFISH-PORT`: Override the Batfish port for a specific request
- `Authorization`: Bearer token for JWT authentication

## Testing Authentication

The server includes special tools to test authentication and environment variables:

### 1. Environment Check Tool (No Authentication Required)

This tool bypasses authentication to check environment variables:

```bash
curl -X POST http://localhost:3009/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "method": "tools/call",
    "params": {
      "name": "batfish_env_check",
      "arguments": {}
    }
  }'
```

Use this to verify your environment variables are correctly set.

### 2. Authentication Test Tool

```bash
# With development mode enabled (no JWT required)
curl -X POST http://localhost:3009/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "method": "tools/call",
    "params": {
      "name": "batfish_auth_test",
      "arguments": {}
    }
  }'

# With JWT authentication (production mode)
curl -X POST http://localhost:3009/mcp \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "method": "tools/call",
    "params": {
      "name": "batfish_auth_test",
      "arguments": {}
    }
  }'
```

The response will show authentication status and user information.

### Authentication Modes

1. **Development Mode** (`DISABLE_JWT_AUTH=true`):
   - No JWT token required
   - Automatically creates a development user
   - Useful for local testing

2. **Production Mode** (`DISABLE_JWT_AUTH=false` or not set):
   - Requires valid JWT token in Authorization header
   - Validates token against Azure AD
   - Enforces security policies

## Troubleshooting

### Authentication Issues

If you're having authentication problems:

1. Check if development mode is enabled:
   ```bash
   echo $DISABLE_JWT_AUTH
   ```
   If it's set to "true", JWT validation is bypassed.

2. Enable authentication logging:
   ```bash
   export ENABLE_AUTH_LOGGING=true
   ```

3. Check the JWT configuration:
   ```bash
   echo $AZURE_AD_TENANT_ID
   echo $AZURE_AD_CLIENT_ID
   ```

4. Test with the `batfish_auth_test` tool to see detailed authentication info.

### Connection Refused

If you see an error like:
```
ConnectionRefusedError: [Errno 61] Connection refused
```

This means the Batfish service is not running or not accessible. Make sure:
1. Batfish is running (e.g., the Docker container is up)
2. The host and port are correct
3. There are no network issues preventing the connection

### Import Errors

If you see import errors, make sure you're running the script from the correct directory:
```bash
cd src/servers/batfish
python server.py
```

Or use the Python module syntax:
```bash
python -m src.servers.batfish.server
```

## Available Tools

**Note:** Tools are now organized into categories using dot notation (e.g., `management.list_networks`, `aws.reachability`, `network.segment`). This provides better organization and prevents naming conflicts when integrating with other MCP servers.

---

## Management Tools

Core Batfish management operations for networks and snapshots.

### 1. management.list_networks

List all available Batfish networks on the configured server.

**Parameters:**
- None required (host is automatically configured from environment or headers)

**Returns:**
```json
{
  "ok": true,
  "networks": ["network1", "aws-prod", "lab"]
}
```

**Example Usage:**
```python
result = management_list_networks()
# Returns list of all available networks on the Batfish server
```

---

### 2. management.list_snapshots

List all snapshots inside a given network.

**Parameters:**
- `network` (str): Logical network name

**Returns:**
```json
{
  "ok": true,
  "snapshots": ["snapshot1", "snapshot2", "baseline"]
}
```

**Example Usage:**
```python
result = management_list_snapshots(network="aws-prod")
# Returns list of all snapshots in the network
```

---

### 3. management.delete_snapshot

Delete a snapshot within a network.

**Parameters:**
- `network` (str): Logical network name
- `snapshot` (str): Snapshot identifier to delete

**Returns:**
```json
{
  "ok": true,
  "deleted": "snapshot-name"
}
```

**Example Usage:**
```python
result = management_delete_snapshot(
    network="aws-prod",
    snapshot="old-snapshot"
)
```

---

### 4. management.delete_network

Delete an entire network from Batfish.

**Parameters:**
- `network` (str): Logical network name to delete

**Returns:**
```json
{
  "ok": true,
  "deleted": "network-name"
}
```

**Example Usage:**
```python
result = management_delete_network(network="old-network")
```

---

### 5. management.get_snapshot_info

Return metadata about a snapshot including nodes, vendors, warnings, errors, and interfaces.

**Parameters:**
- `network` (str): Logical network name
- `snapshot` (str): Snapshot identifier

**Returns:**
```json
{
  "ok": true,
  "nodes": ["router1", "router2", "switch1"],
  "vendors": ["cisco", "arista"],
  "interfaces": ["router1[GigabitEthernet0/0]", "router2[eth0]"],
  "warnings": [...],
  "errors": [...]
}
```

**Example Usage:**
```python
result = management_get_snapshot_info(
    network="aws-prod",
    snapshot="baseline"
)
```

---

### 6. management.get_parse_status

Return parse warnings and errors for a snapshot.

**Parameters:**
- `network` (str): Logical network name
- `snapshot` (str): Snapshot identifier

**Returns:**
```json
{
  "ok": true,
  "warnings": [
    {
      "File": "router1.cfg",
      "Line": 42,
      "Text": "Unused configuration line",
      "Parser_Context": "..."
    }
  ],
  "errors": [
    {
      "File": "router2.cfg",
      "Status": "FAILED",
      "Error": "Parse error on line 10"
    }
  ]
}
```

**Example Usage:**
```python
result = management_get_parse_status(
    network="aws-prod",
    snapshot="baseline"
)
```

---

## Snapshot Initialization Tools

### 1. batfish_init_snapshot

Initialize a Batfish snapshot with network configuration files (for traditional router/switch configs).

**Parameters:**
- `network` (str): Logical network name
- `snapshot` (str): Snapshot identifier
- `configs` (Dict[str, str]): Dictionary of {filename: configContent}

### 2. batfish_init_aws_snapshot

Initialize a Batfish snapshot with AWS Vendor Model JSON files. Creates the correct directory structure for AWS snapshots: `aws_configs/<region>/aws.json`

**Use this tool when:** You have all AWS data in a single request (small environments).

**For large environments:** Use `batfish_add_aws_data_chunk` + `batfish_finalize_aws_snapshot` instead (see section below).

**Parameters:**
- `snapshot_name` (str): Snapshot identifier
- `region` (str): AWS region (e.g., 'us-east-1')
- `aws_data` (Dict[str, Any]): RAW AWS API data from aws_collect_all tool
  - Contains: Vpcs, Subnets, RouteTables, InternetGateways, NatGateways, SecurityGroups, NetworkAcls, NetworkInterfaces, Reservations
- `network_name` (str, optional): Logical network name (defaults to snapshot_name)

**Returns:**
```json
{
  "ok": true,
  "snapshot": "aws-snapshot-001",
  "network": "aws-network",
  "region": "us-east-1"
}
```

**Example Usage:**
```python
# Using data from aws_collect_all tool
aws_data = {
    "Vpcs": [...],
    "Subnets": [...],
    "RouteTables": [...],
    "SecurityGroups": [...],
    "NetworkAcls": [...],
    "NetworkInterfaces": [...],
    "InternetGateways": [...],
    "NatGateways": [...],
    "Reservations": [...]
}

result = batfish_init_aws_snapshot(
    snapshot_name="aws-prod-snapshot",
    region="us-east-1",
    aws_data=aws_data,
    network_name="aws-prod-network"
)
```

### 2a. batfish_add_aws_data_chunk (NEW - Incremental Snapshots)

Add a chunk of AWS resource data to staging directory for incremental snapshot building.

**Use this tool when:** AWS environment is too large to send in a single request.

**Parameters:**
- `snapshot_name` (str): Snapshot identifier (used as staging key)
- `region` (str): AWS region (e.g., 'us-east-1')
- `resource_type` (str): AWS resource type (Vpcs, Subnets, RouteTables, etc.)
- `data` (List[Dict[str, Any]]): List of AWS resources of this type (raw AWS API format)
- `network_name` (str, optional): Logical network name (defaults to snapshot_name)

**Supported Resource Types:**
- `Vpcs`, `Subnets`, `RouteTables`, `InternetGateways`, `NatGateways`
- `SecurityGroups`, `NetworkAcls`, `NetworkInterfaces`, `Reservations`

**Returns:**
```json
{
  "ok": true,
  "snapshot": "prod-snapshot",
  "region": "us-east-1",
  "resource_type": "Vpcs",
  "resource_count": 5,
  "staging_dir": "/tmp/batfish_aws_staging/production_prod-snapshot_us-east-1",
  "chunks_staged": ["Vpcs"]
}
```

**Example Usage:**
```python
# Add VPCs
result = batfish_add_aws_data_chunk(
    snapshot_name="prod-snapshot",
    region="us-east-1",
    resource_type="Vpcs",
    data=vpc_data,
    network_name="production"
)

# Add Subnets
result = batfish_add_aws_data_chunk(
    snapshot_name="prod-snapshot",
    region="us-east-1",
    resource_type="Subnets",
    data=subnet_data,
    network_name="production"
)

# ... add other resource types ...
```

### 2b. batfish_finalize_aws_snapshot (NEW - Incremental Snapshots)

Consolidate all staged AWS data chunks into a single aws.json and initialize Batfish snapshot.

**Use this tool:** After adding all chunks with `batfish_add_aws_data_chunk`.

**Parameters:**
- `snapshot_name` (str): Snapshot identifier (must match staging key used in chunks)
- `region` (str): AWS region (e.g., 'us-east-1')
- `network_name` (str, optional): Logical network name (defaults to snapshot_name)
- `clear_staging` (bool, optional): Clear staging directory after success (default: True)

**Returns:**
```json
{
  "ok": true,
  "snapshot": "prod-snapshot",
  "network": "production",
  "region": "us-east-1",
  "resources_consolidated": {
    "Vpcs": 5,
    "Subnets": 24,
    "RouteTables": 12,
    "SecurityGroups": 87
  },
  "total_resource_types": 9
}
```

**Example Usage:**
```python
# After adding all chunks
result = batfish_finalize_aws_snapshot(
    snapshot_name="prod-snapshot",
    region="us-east-1",
    network_name="production",
    clear_staging=True
)
```

**See Also:** [Incremental AWS Snapshot Building Guide](tools/INCREMENTAL_AWS_SNAPSHOT_GUIDE.md) for detailed workflow and best practices.

### 3. batfish_list_networks

List available Batfish networks on the configured Batfish server.

**Parameters:**
- None required

**Returns:**
```json
{
  "ok": true,
  "networks": ["network1", "aws-prod", "lab"]
}
```

**Example Usage:**
```python
result = batfish_list_networks()
# Returns list of all available networks on the Batfish server
```

### 4. batfish_list_snapshots

List all snapshots inside a given network.

**Parameters:**
- `network`: Logical network name

**Returns:**
```json
{
  "ok": true,
  "snapshots": ["snapshot1", "snapshot2", "baseline"]
}
```

**Example Usage:**
```python
result = batfish_list_snapshots(network="aws-prod")
# Returns list of all snapshots in the network
```

### 5. batfish_delete_snapshot

Delete a snapshot within a network.

**Parameters:**
- `network`: Logical network name
- `snapshot`: Snapshot identifier to delete

**Returns:**
```json
{
  "ok": true,
  "deleted": "snapshot-name"
}
```

**Example Usage:**
```python
result = batfish_delete_snapshot(
    network="aws-prod",
    snapshot="old-snapshot"
)
```

### 6. batfish_delete_network

Delete an entire network from Batfish.

**Parameters:**
- `network`: Logical network name to delete

**Returns:**
```json
{
  "ok": true,
  "deleted": "network-name"
}
```

**Example Usage:**
```python
result = batfish_delete_network(network="old-network")
```

### 7. batfish_get_snapshot_info

Return metadata about a snapshot including nodes, vendors, warnings, errors, and interfaces.

**Parameters:**
- `network`: Logical network name
- `snapshot`: Snapshot identifier

**Returns:**
```json
{
  "ok": true,
  "nodes": ["router1", "router2", "switch1"],
  "vendors": ["cisco", "arista"],
  "interfaces": ["router1[GigabitEthernet0/0]", "router2[eth0]"],
  "warnings": [...],
  "errors": [...]
}
```

**Example Usage:**
```python
result = batfish_get_snapshot_info(
    network="aws-prod",
    snapshot="baseline"
)
```

### 8. batfish_get_parse_status

Return parse warnings and errors for a snapshot.

**Parameters:**
- `network`: Logical network name
- `snapshot`: Snapshot identifier

**Returns:**
```json
{
  "ok": true,
  "warnings": [
    {
      "File": "router1.cfg",
      "Line": 42,
      "Text": "Unused configuration line",
      "Parser_Context": "..."
    }
  ],
  "errors": [
    {
      "File": "router2.cfg",
      "Status": "FAILED",
      "Error": "Parse error on line 10"
    }
  ]
}
```

**Example Usage:**
```python
result = batfish_get_parse_status(
    network="aws-prod",
    snapshot="baseline"
)
```