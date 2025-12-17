import sys
import pytest
import asyncio
import time
from unittest.mock import MagicMock, AsyncMock, patch
from dataclasses import dataclass

# --- Mock Infrastructure Setup ---
mcp_mock = MagicMock()
sys.modules["mcp"] = mcp_mock
sys.modules["mcp.client"] = MagicMock()
sys.modules["mcp.client.stdio"] = MagicMock()
sys.modules["mcp.types"] = MagicMock()

@dataclass
class MockTool:
    name: str
    description: str = ""
    inputSchema: dict = None

mcp_mock.types.Tool = MockTool
mcp_mock.ClientSession = MagicMock()
mcp_mock.StdioServerParameters = MagicMock()

mock_stdio_cm = MagicMock()
mock_stdio_cm.__aenter__.return_value = (MagicMock(), MagicMock())
mock_stdio_cm.__aexit__.return_value = None
mock_stdio_client = MagicMock(return_value=mock_stdio_cm)
sys.modules["mcp.client.stdio"].stdio_client = mock_stdio_client

# Patch sys to allow SecureMCPClient import
with patch.object(sys, "version_info", (3, 11)):
    from tenuo.mcp.client import SecureMCPClient
    import tenuo.mcp.client as client_module
    client_module.MCP_AVAILABLE = True

from tenuo import SigningKey, configure, root_task, Pattern, Warrant, ExpiredError
from tenuo.decorators import set_warrant_context, set_keypair_context

# --- Red Team Scenarios ---

@pytest.mark.asyncio
async def test_scenario_1_shadow_parameter():
    """Scenario 1: Shadow Parameter Attack"""
    print("\n[Red Team] Scenario 1: Shadow Parameter Attack")
    
    # Setup Mock Session
    mock_session = AsyncMock()
    mock_session.initialize = AsyncMock()
    
    # Tool with valid JSON Schema for properties
    # This is what SecureMCPClient.create_protected_tool reads to build 'allowed_keys'
    schema = {
        "type": "object", 
        "properties": {
            "path": {"type": "string"}
        }
    }
    
    # We must mock 'inputSchema' attribute access correctly on the Tool object
    tool_mock = MagicMock()
    tool_mock.configure_mock(name="write_log", description="Write to log")
    # Using configure_mock handles property access better than constructor for attributes
    tool_mock.inputSchema = schema 
    
    mock_session.list_tools.return_value = MagicMock(tools=[tool_mock])
    mock_session.call_tool.return_value = MagicMock(content=[])
    
    cm = MagicMock()
    cm.__aenter__.return_value = mock_session
    cm.__aexit__.return_value = None
    mcp_mock.ClientSession.return_value = cm
    
    # Configure Tenuo
    keypair = SigningKey.generate()
    configure(issuer_key=keypair, dev_mode=True)
    
    async with SecureMCPClient("python", ["server.py"]) as client:
        protected = await client.get_protected_tools()
        write_log = protected["write_log"]
        
        print("   Attacking with shadow parameter 'dangerous_mode=True'...")
        async with root_task(tools=["write_log"], path=Pattern("/logs/*")):
            await write_log(path="/logs/app.txt", dangerous_mode=True)
            
        call_args = mock_session.call_tool.call_args[0]
        received_args = call_args[1]
        
        if "dangerous_mode" in received_args:
            print("   ⚠️  FAILURE: Shadow parameter was PASSED to server (Vulnerability persists).")
            # Fail test if vulnerability exists (now that we expect it fixed)
            assert False, "Shadow Parameter vulnerability detected!"
        else:
            print("   🛡️  PROTECTED: Shadow parameter was stripped (Attack Blocked).")
            # Verify clean args
            assert "path" in received_args
            assert "dangerous_mode" not in received_args

@pytest.mark.asyncio
async def test_scenario_2_time_traveler():
    """Scenario 2: Time Traveler (Expiry Checks)"""
    print("\n[Red Team] Scenario 2: Time Traveler (Expiry Check)")
    
    # Setup Mock Session
    mock_session = AsyncMock()
    mock_session.initialize = AsyncMock()
    mock_session.list_tools.return_value = MagicMock(tools=[
        MockTool("quick_action", "Fast tool", {})
    ])
    
    cm = MagicMock()
    cm.__aenter__.return_value = mock_session
    cm.__aexit__.return_value = None
    mcp_mock.ClientSession.return_value = cm
    
    # Configure Tenuo
    keypair = SigningKey.generate()
    configure(issuer_key=keypair, dev_mode=True)
    
    async with SecureMCPClient("python", ["server.py"]) as client:
        protected = await client.get_protected_tools()
        quick_action = protected["quick_action"]
        
        print("   Minting short-lived warrant (TTL=1s)...")
        short_warrant = Warrant.issue(
            tools="quick_action",
            constraints={},
            ttl_seconds=1,
            keypair=keypair,
            holder=keypair.public_key
        )
        
        print("   Waiting 1.2s for expiry...")
        time.sleep(1.2)
        
        print("   Attempting to use expired warrant...")
        with set_warrant_context(short_warrant), set_keypair_context(keypair):
            with pytest.raises(ExpiredError):
                await quick_action()
                
        print("   🛡️  PROTECTED: Expired warrant was rejected.")

if __name__ == "__main__":
    asyncio.run(test_scenario_1_shadow_parameter())
    asyncio.run(test_scenario_2_time_traveler())
