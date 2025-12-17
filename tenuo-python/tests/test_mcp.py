import pytest
import tempfile
import os
from tenuo import McpConfig, CompiledMcpConfig, ExtractionResult

# Sample MCP Config YAML
SAMPLE_CONFIG = """
version: "1"
settings:
  trusted_issuers: []
tools:
  filesystem_read:
    description: "Read files from the filesystem"
    constraints:
      path:
        from: body
        path: "path"
        required: true
      max_size:
        from: body
        path: "maxSize"
        type: integer
        default: 1048576
"""

@pytest.fixture
def mcp_config_file():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(SAMPLE_CONFIG)
        path = f.name
    yield path
    os.unlink(path)

def test_load_mcp_config(mcp_config_file):
    """Test loading McpConfig from a file."""
    config = McpConfig.from_file(mcp_config_file)
    assert config is not None
    # We can't easily inspect the inner Rust struct fields from Python unless exposed,
    # but successful load is a good sign.

def test_compile_mcp_config(mcp_config_file):
    """Test compiling McpConfig."""
    config = McpConfig.from_file(mcp_config_file)
    compiled = CompiledMcpConfig.compile(config)
    assert compiled is not None

def test_extract_constraints(mcp_config_file):
    """Test extracting constraints from arguments."""
    config = McpConfig.from_file(mcp_config_file)
    compiled = CompiledMcpConfig.compile(config)
    
    # Valid arguments
    args = {
        "path": "/var/log/syslog",
        "maxSize": 5000
    }
    
    result = compiled.extract_constraints("filesystem_read", args)
    assert isinstance(result, ExtractionResult)
    assert result.tool == "filesystem_read"
    
    # Check extracted constraints
    # Note: result.constraints is a dict-like object (PyDict)
    constraints = dict(result.constraints)
    assert constraints["path"] == "/var/log/syslog"
    assert constraints["max_size"] == 5000

def test_extract_constraints_default_value(mcp_config_file):
    """Test extracting constraints with default values."""
    config = McpConfig.from_file(mcp_config_file)
    compiled = CompiledMcpConfig.compile(config)
    
    # Missing optional arg (maxSize has default)
    args = {
        "path": "/var/log/syslog"
    }
    
    result = compiled.extract_constraints("filesystem_read", args)
    constraints = dict(result.constraints)
    assert constraints["path"] == "/var/log/syslog"
    assert constraints["max_size"] == 1048576  # Default value

def test_extract_constraints_missing_required(mcp_config_file):
    """Test extraction fails when required field is missing."""
    config = McpConfig.from_file(mcp_config_file)
    compiled = CompiledMcpConfig.compile(config)
    
    # Missing required 'path'
    args = {
        "maxSize": 5000
    }
    
    with pytest.raises(Exception) as excinfo:
        compiled.extract_constraints("filesystem_read", args)
    
    # The error message comes from Rust, should mention missing field
    assert "Missing required field" in str(excinfo.value)

def test_extract_constraints_unknown_tool(mcp_config_file):
    """Test extraction fails for unknown tool."""
    config = McpConfig.from_file(mcp_config_file)
    compiled = CompiledMcpConfig.compile(config)
    
    args = {"path": "/foo"}
    
    with pytest.raises(Exception) as excinfo:
        compiled.extract_constraints("unknown_tool", args)
    
    assert "Tool 'unknown_tool' not defined" in str(excinfo.value)

def test_extract_tenuo_metadata(mcp_config_file):
    """Test that _tenuo metadata is extracted and stripped."""
    config = McpConfig.from_file(mcp_config_file)
    compiled = CompiledMcpConfig.compile(config)
    
    # Arguments with embedded warrant/signature
    args = {
        "path": "/var/log/syslog",
        "maxSize": 5000,
        "_tenuo": {
            "warrant": "eyJ0eXAiOiJKV1QiLCJhbGc...",
            "signature": "c2lnbmF0dXJlLi4u"
        }
    }
    
    result = compiled.extract_constraints("filesystem_read", args)
    
    # Check extracted constraints don't include _tenuo
    constraints = dict(result.constraints)
    assert "_tenuo" not in constraints
    assert constraints["path"] == "/var/log/syslog"
    assert constraints["max_size"] == 5000
    
    # Check warrant/signature were extracted
    assert result.warrant_base64 == "eyJ0eXAiOiJKV1QiLCJhbGc..."
    assert result.signature_base64 == "c2lnbmF0dXJlLi4u"
