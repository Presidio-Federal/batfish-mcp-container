# Deployment Guide

This guide covers various deployment scenarios for the Batfish MCP Container.

## Table of Contents

- [Quick Start](#quick-start)
- [Docker Compose Deployment](#docker-compose-deployment)
- [Production Deployment](#production-deployment)
- [Cloud Deployments](#cloud-deployments)
- [Security Considerations](#security-considerations)
- [Monitoring and Logging](#monitoring-and-logging)

## Quick Start

### Development/Testing (No Authentication)

```bash
# Clone repository
git clone https://github.com/presidio-federal/batfish-mcp-container.git
cd batfish-mcp-container

# Copy environment file
cp .env.example .env

# Update .env with your GitHub username
# GITHUB_REPOSITORY=presidio-federal/batfish-mcp-container

# Start services
docker-compose up -d

# Verify
docker-compose ps
docker-compose logs batfish-mcp
```

## Docker Compose Deployment

### Standard Deployment

The included `docker-compose.yml` provides a complete two-container stack:

```yaml
services:
  batfish:       # Network analysis engine
  batfish-mcp:   # MCP server
```

**Starting:**
```bash
docker-compose up -d
```

**Stopping:**
```bash
docker-compose down
```

**Viewing logs:**
```bash
docker-compose logs -f batfish-mcp
docker-compose logs -f batfish
```

**Restarting a service:**
```bash
docker-compose restart batfish-mcp
```

### Persistent Data

Batfish data is stored in a Docker volume:
```bash
# List volumes
docker volume ls | grep batfish

# Inspect volume
docker volume inspect batfish-mcp-container_batfish-data

# Backup volume
docker run --rm -v batfish-mcp-container_batfish-data:/data -v $(pwd):/backup \
  alpine tar czf /backup/batfish-backup.tar.gz -C /data .

# Restore volume
docker run --rm -v batfish-mcp-container_batfish-data:/data -v $(pwd):/backup \
  alpine sh -c "cd /data && tar xzf /backup/batfish-backup.tar.gz"
```

## Production Deployment

### With Authentication (Azure AD)

1. **Configure environment variables:**

```bash
# .env
DISABLE_JWT_AUTH=false
AZURE_AD_TENANT_ID=your-azure-tenant-id
AZURE_AD_CLIENT_ID=your-azure-client-id
ENABLE_AUTH_LOGGING=true
GITHUB_REPOSITORY=presidio-federal/batfish-mcp-container
```

2. **Deploy:**

```bash
docker-compose up -d
```

3. **Test with JWT token:**

```bash
curl -X POST http://localhost:3009/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'
```

### Using Docker Swarm

1. **Initialize swarm:**

```bash
docker swarm init
```

2. **Create stack file (`docker-stack.yml`):**

```yaml
version: '3.8'

services:
  batfish:
    image: batfish/allinone:latest
    ports:
      - "9997:9997"
      - "9996:9996"
    volumes:
      - batfish-data:/data
    networks:
      - batfish-network
    deploy:
      replicas: 1
      restart_policy:
        condition: on-failure
    healthcheck:
      test: ["CMD-SHELL", "curl -f http://localhost:9996/ || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 5

  batfish-mcp:
    image: ghcr.io/presidio-federal/batfish-mcp-container:latest
    ports:
      - "3009:3009"
    environment:
      - BATFISH_HOST=batfish
      - BATFISH_PORT=9996
      - DISABLE_JWT_AUTH=true
    networks:
      - batfish-network
    deploy:
      replicas: 1
      restart_policy:
        condition: on-failure
    depends_on:
      - batfish

networks:
  batfish-network:
    driver: overlay

volumes:
  batfish-data:
```

3. **Deploy stack:**

```bash
docker stack deploy -c docker-stack.yml batfish-stack
```

4. **Manage stack:**

```bash
# List services
docker stack services batfish-stack

# View logs
docker service logs batfish-stack_batfish-mcp

# Scale MCP service
docker service scale batfish-stack_batfish-mcp=3

# Remove stack
docker stack rm batfish-stack
```

## Cloud Deployments

### AWS ECS/Fargate

1. **Create task definition (JSON):**

See `deployments/aws-ecs-task-definition.json` (create this file based on your needs)

2. **Deploy using AWS CLI:**

```bash
aws ecs register-task-definition --cli-input-json file://task-definition.json
aws ecs create-service --cluster your-cluster --service-name batfish-mcp --task-definition batfish-mcp
```

### Azure Container Instances

```bash
# Create resource group
az group create --name batfish-rg --location eastus

# Create container group
az container create \
  --resource-group batfish-rg \
  --name batfish-containers \
  --image ghcr.io/presidio-federal/batfish-mcp-container:latest \
  --ports 3009 9996 9997 \
  --dns-name-label batfish-mcp-demo \
  --environment-variables \
    BATFISH_HOST=localhost \
    DISABLE_JWT_AUTH=true
```

### Google Cloud Run

```bash
# Deploy Batfish (on Compute Engine or GKE first)
# Then deploy MCP service

gcloud run deploy batfish-mcp \
  --image ghcr.io/presidio-federal/batfish-mcp-container:latest \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars BATFISH_HOST=batfish-host,DISABLE_JWT_AUTH=true
```

## Security Considerations

### Network Security

1. **Use internal networks:**
   - Don't expose Batfish port (9996) to the internet
   - Only expose MCP port (3009) if needed externally

2. **Enable authentication in production:**
   ```bash
   DISABLE_JWT_AUTH=false
   AZURE_AD_TENANT_ID=your-tenant-id
   ```

3. **Use reverse proxy:**
   ```nginx
   # nginx.conf
   server {
       listen 443 ssl;
       server_name batfish.example.com;
       
       ssl_certificate /path/to/cert.pem;
       ssl_certificate_key /path/to/key.pem;
       
       location / {
           proxy_pass http://localhost:3009;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
       }
   }
   ```

### Container Security

1. **Run as non-root user** (already configured in Dockerfile)
2. **Use read-only filesystem where possible**
3. **Limit resource usage:**

```yaml
# docker-compose.yml
services:
  batfish-mcp:
    # ... other config ...
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 4G
        reservations:
          cpus: '1'
          memory: 2G
```

### Secrets Management

Use Docker secrets or external secret management:

```bash
# Create secrets
echo "your-tenant-id" | docker secret create azure_tenant_id -
echo "your-client-id" | docker secret create azure_client_id -

# Use in compose file
services:
  batfish-mcp:
    secrets:
      - azure_tenant_id
      - azure_client_id
    environment:
      - AZURE_AD_TENANT_ID=/run/secrets/azure_tenant_id
      - AZURE_AD_CLIENT_ID=/run/secrets/azure_client_id
```

## Monitoring and Logging

### Health Checks

Both containers include health checks:

```bash
# Check container health
docker inspect --format='{{json .State.Health}}' batfish-mcp | jq
docker inspect --format='{{json .State.Health}}' batfish | jq
```

### Logging

Centralized logging with Docker:

```yaml
# docker-compose.yml
services:
  batfish-mcp:
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
```

Or use a logging driver:

```yaml
services:
  batfish-mcp:
    logging:
      driver: "syslog"
      options:
        syslog-address: "tcp://logs.example.com:514"
```

### Monitoring with Prometheus

Add Prometheus metrics (if implemented):

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'batfish-mcp'
    static_configs:
      - targets: ['localhost:3009']
```

## Troubleshooting

### Common Issues

**Container exits immediately:**
```bash
docker-compose logs batfish-mcp
# Check for import errors or configuration issues
```

**Can't connect to Batfish:**
```bash
# Test Batfish connectivity
docker exec batfish-mcp curl -f http://batfish:9996/
```

**Authentication failures:**
```bash
# Enable auth logging
export ENABLE_AUTH_LOGGING=true
docker-compose up -d
docker-compose logs -f batfish-mcp
```

### Performance Tuning

For large networks, increase Batfish memory:

```yaml
services:
  batfish:
    environment:
      - JAVA_OPTS=-Xmx8g
```

## Backup and Recovery

### Backup Strategy

```bash
#!/bin/bash
# backup.sh

BACKUP_DIR="./backups/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Backup Batfish data
docker run --rm \
  -v batfish-mcp-container_batfish-data:/data \
  -v "$BACKUP_DIR":/backup \
  alpine tar czf /backup/batfish-data.tar.gz -C /data .

echo "Backup completed: $BACKUP_DIR"
```

### Recovery

```bash
#!/bin/bash
# restore.sh

BACKUP_FILE="$1"

docker run --rm \
  -v batfish-mcp-container_batfish-data:/data \
  -v "$(dirname $BACKUP_FILE)":/backup \
  alpine sh -c "cd /data && tar xzf /backup/$(basename $BACKUP_FILE)"

echo "Restore completed"
```

## Upgrading

### Upgrade Process

```bash
# Pull latest images
docker-compose pull

# Backup data
./backup.sh

# Stop services
docker-compose down

# Start with new images
docker-compose up -d

# Verify
docker-compose logs -f batfish-mcp
```

### Rollback

```bash
# Stop current version
docker-compose down

# Use specific version
docker-compose up -d ghcr.io/presidio-federal/batfish-mcp-container:v1.0.0

# Or restore from backup
./restore.sh backups/20260206_120000/batfish-data.tar.gz
```
