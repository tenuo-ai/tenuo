import asyncio
import sys
from pathlib import Path

# Add repo root to path so we can run from examples/
sys.path.append(str(Path(__file__).parent.parent))

from tenuo.mcp.client import discover_and_protect

async def main():
    # Assume we are in examples/ or find mcp_server_demo.py
    server_script = Path(__file__).parent / "mcp_server_demo.py"
    if not server_script.exists():
        print(f"Error: {server_script} not found")
        sys.exit(1)

    print(f"Connecting to {server_script}...")
    
    try:
        # Verified Fix: verify discover_and_protect works as a context manager
        async with discover_and_protect("python", [str(server_script)]) as tools:
            print("Tools discovered:", list(tools.keys()))
            
            if "read_file" not in tools:
                print("Error: read_file tool not found")
                return

            print("Attempting to call tool 'read_file'...")
            read_file = tools["read_file"]
            
            # Create a dummy file to read
            target_file = Path("/tmp/repro_test.txt")
            target_file.write_text("success")
            
            try:
                # This call should SUCCEED now because session is alive
                # Note: We need a warrant context or to bypass it for this test
                # Since we didn't configure Tenuo globally, we'll get a ConfigError or similar 
                # unless we disable warrant context or configure Tenuo.
                # However, the original bug was RuntimeError "Not connected".
                # Getting past that to a Tenuo error means the session is alive.
                
                # To make it fully succeed, let's configure Tenuo locally
                from tenuo import configure, SigningKey, root_task_sync, Pattern, Capability
                configure(issuer_key=SigningKey.generate(), dev_mode=True)
                
                with root_task_sync(Capability("read_file", path=Pattern("/tmp/*"))):
                     result = await read_file(path=str(target_file))
                     print(f"SUCCESS: Tool call returned: {result}")
                     
            finally:
                if target_file.exists():
                    target_file.unlink()

        print("Refactored discover_and_protect works correctly as context manager.")

    except Exception as e:
        print(f"FAILURE: Caught unexpected error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())
