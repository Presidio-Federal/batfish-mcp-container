# Contributing to Batfish MCP Container

Thank you for your interest in contributing! This document provides guidelines and instructions for contributing to this project.

## Getting Started

### Prerequisites

- Docker and Docker Compose
- Python 3.11+
- Git
- GitHub account

### Development Setup

1. **Fork and clone the repository:**
   ```bash
   git clone https://github.com/presidio-federal/batfish-mcp-container.git
   cd batfish-mcp-container
   ```

2. **Install development dependencies:**
   ```bash
   cd batfish
   pip install -r requirements.txt
   pip install pytest black flake8 mypy
   ```

3. **Start Batfish for local testing:**
   ```bash
   docker run -d --name batfish -p 9996:9996 -p 9997:9997 batfish/allinone:latest
   ```

4. **Run the server locally:**
   ```bash
   export BATFISH_HOST=localhost
   export DISABLE_JWT_AUTH=true
   python -m server
   ```

## How to Contribute

### Reporting Bugs

1. Check existing issues to avoid duplicates
2. Use the bug report template
3. Include:
   - Steps to reproduce
   - Expected behavior
   - Actual behavior
   - Environment details (OS, Docker version, etc.)
   - Relevant logs

### Suggesting Features

1. Check existing issues and discussions
2. Use the feature request template
3. Clearly describe:
   - The problem you're trying to solve
   - Your proposed solution
   - Alternative solutions considered
   - Impact on existing functionality

### Pull Requests

1. **Create a feature branch:**
   ```bash
   git checkout -b feature/my-new-feature
   ```

2. **Make your changes:**
   - Follow the code style guidelines
   - Add tests for new functionality
   - Update documentation

3. **Test your changes:**
   ```bash
   # Run tests
   pytest
   
   # Check code style
   black batfish/
   flake8 batfish/
   
   # Type checking
   mypy batfish/
   
   # Test Docker build
   docker build -t batfish-mcp:test -f batfish/dockerfile .
   ```

4. **Commit your changes:**
   ```bash
   git add .
   git commit -m "feat: add new feature description"
   ```
   
   Follow [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat:` New feature
   - `fix:` Bug fix
   - `docs:` Documentation changes
   - `style:` Code style changes (formatting)
   - `refactor:` Code refactoring
   - `test:` Adding or updating tests
   - `chore:` Maintenance tasks

5. **Push and create pull request:**
   ```bash
   git push origin feature/my-new-feature
   ```
   
   Then create a PR on GitHub.

## Code Style Guidelines

### Python

- Follow PEP 8
- Use type hints
- Maximum line length: 100 characters
- Use `black` for formatting
- Document functions with docstrings

Example:
```python
def analyze_network(network: str, snapshot: str) -> Dict[str, Any]:
    """
    Analyze network configuration and return summary.
    
    Args:
        network: The network name
        snapshot: The snapshot identifier
        
    Returns:
        Dictionary containing analysis results
        
    Raises:
        ValueError: If network or snapshot not found
    """
    # Implementation
    pass
```

### Docker

- Use multi-stage builds
- Run as non-root user
- Minimize layer count
- Add health checks
- Document environment variables

## Testing

### Unit Tests

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_tools.py

# Run with coverage
pytest --cov=batfish tests/
```

### Integration Tests

```bash
# Start test environment
docker-compose -f docker-compose.test.yml up -d

# Run integration tests
pytest tests/integration/

# Cleanup
docker-compose -f docker-compose.test.yml down
```

### Testing Docker Build

```bash
# Build
docker build -t batfish-mcp:test -f batfish/dockerfile .

# Run
docker run --rm -p 3009:3009 \
  -e DISABLE_JWT_AUTH=true \
  -e BATFISH_HOST=host.docker.internal \
  batfish-mcp:test

# Test endpoint
curl http://localhost:3009/health
```

## Documentation

### Code Documentation

- Add docstrings to all functions and classes
- Include parameter types and return types
- Document exceptions that can be raised
- Add examples for complex functionality

### User Documentation

When adding features that affect users:
1. Update README.md
2. Update batfish/README.md (tool documentation)
3. Add examples
4. Update DEPLOYMENT.md if needed

### API Documentation

Document new MCP tools:
```python
@mcp.tool(
    name="my_new_tool",
    description="Clear, concise description of what the tool does"
)
def my_new_tool(param1: str, param2: int, ctx: Context = None) -> Dict[str, Any]:
    """
    Detailed description of the tool's functionality.
    
    Args:
        param1: Description of first parameter
        param2: Description of second parameter
        ctx: MCP context (optional)
        
    Returns:
        Dictionary with structure:
        {
            "ok": bool,
            "result": ...,
            "error": str (if ok=False)
        }
    """
    pass
```

## Adding New Tools

### Tool Structure

1. **Create tool file:**
   ```bash
   touch batfish/tools/my_new_tool.py
   ```

2. **Implement tool:**
   ```python
   from typing import Any, Dict
   from pydantic import BaseModel, Field
   
   class MyNewToolInput(BaseModel):
       param1: str = Field(..., description="Parameter description")
       param2: int = Field(default=10, description="Optional parameter")
   
   def my_new_tool_impl(param1: str, param2: int = 10) -> Dict[str, Any]:
       """Tool implementation."""
       try:
           # Implementation here
           return {
               "ok": True,
               "result": "success"
           }
       except Exception as e:
           return {
               "ok": False,
               "error": str(e)
           }
   ```

3. **Register in server.py:**
   ```python
   from .tools.my_new_tool import MyNewToolInput, my_new_tool_impl
   
   @mcp.tool(
       name="category.my_new_tool",
       description="What the tool does"
   )
   def my_new_tool(param1: str, param2: int = 10, ctx: Context = None) -> Dict[str, Any]:
       log_user_access(ctx, "my_new_tool")
       return my_new_tool_impl(param1, param2)
   ```

4. **Add tests:**
   ```python
   def test_my_new_tool():
       result = my_new_tool_impl("test", 5)
       assert result["ok"] is True
       assert "result" in result
   ```

5. **Document in README:**
   Add tool documentation to `batfish/README.md`

## Release Process

Releases are automated via GitHub Actions:

1. **Update version:**
   - Update `__version__` in `batfish/__init__.py`
   - Update changelog

2. **Create tag:**
   ```bash
   git tag -a v1.0.0 -m "Release v1.0.0"
   git push origin v1.0.0
   ```

3. **GitHub Actions will:**
   - Build the Docker image
   - Push to GHCR with version tags
   - Create GitHub release (if configured)

## Community

- Be respectful and inclusive
- Follow the [Code of Conduct](CODE_OF_CONDUCT.md)
- Help others in discussions
- Share knowledge and experiences

## Questions?

- Open a [Discussion](https://github.com/presidio-federal/batfish-mcp-container/discussions)
- Check existing [Issues](https://github.com/presidio-federal/batfish-mcp-container/issues)
- Review the [Documentation](README.md)

Thank you for contributing! 🎉
