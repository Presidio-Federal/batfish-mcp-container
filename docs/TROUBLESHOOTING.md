# Troubleshooting

> **Coming Soon**: This document will provide solutions to common issues when deploying and using the Batfish MCP Container.

## Planned Content

### Container Issues
- Container won't start
- Port conflicts
- Memory/resource constraints
- Health check failures

### Connectivity Issues
- Can't connect to Batfish
- MCP server not responding
- Network timeouts

### Authentication Issues
- JWT validation failures
- Azure AD configuration problems
- Development mode not working

### Performance Issues
- Slow analysis
- Memory exhaustion
- Large snapshot handling

### Data Issues
- Snapshot load failures
- Configuration parse errors
- Missing data in results

---

For immediate help:
- Check logs: `docker-compose logs batfish-mcp`
- Check Batfish health: `curl http://localhost:9996/`
- Enable debug logging: `ENABLE_AUTH_LOGGING=true`
- [Open an issue](https://github.com/presidio-federal/batfish-mcp-container/issues)
