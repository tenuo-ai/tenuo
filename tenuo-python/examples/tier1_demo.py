"""
Tier 1 API Demo (The "3-line API")

This example demonstrates the simplified Tier 1 API for protecting tools
and managing authority scopes.
"""

import asyncio
from tenuo import (
    configure,
    root_task,
    scoped_task,
    protect_tools,
    SigningKey,
    ToolSchema,
    register_schema,
    Pattern,
    Capability,
)

# 1. Define your tools (async or sync)
async def read_file(path: str) -> str:
    print(f"  [Tool] Reading file: {path}")
    return "file content"

async def delete_file(path: str) -> str:
    print(f"  [Tool] Deleting file: {path}")
    return "deleted"

# 2. Configure Tenuo (once at startup)
# In production, you would provide trusted_roots.
# In dev, we use dev_mode=True.
issuer_key = SigningKey.generate()
configure(issuer_key=issuer_key, dev_mode=True)

# 3. Protect your tools
# Register schema for critical tools (optional but recommended)
register_schema("delete_file", ToolSchema(
    recommended_constraints=["path"],
    risk_level="critical"
))

# Wrap tools to enforce authorization
tools = [read_file, delete_file]
protect_tools(tools)
protected_read, protected_delete = tools

async def main():
    print("--- Tier 1 API Demo ---")
    
    # 4. Use root_task to define initial scope
    print("\n1. Root Task: Allow reading /data/*")
    async with root_task(Capability("read_file", path=Pattern("/data/*"))):
        # Authorized call
        await protected_read(path="/data/report.txt")
        
        # Unauthorized call (wrong path)
        try:
            print("  [Attempt] Reading /etc/passwd...")
            await protected_read(path="/etc/passwd")
        except Exception as e:
            print(f"  [Blocked] {e}")

    # 5. Scoped Task: Narrowing authority
    print("\n2. Scoped Task: Narrowing to /data/reports/*")
    async with root_task(Capability("read_file", path=Pattern("/data/*"))):
        # Create a narrower scope
        async with scoped_task(Capability("read_file", path=Pattern("/data/reports/*"))):
            # Authorized in narrow scope
            await protected_read(path="/data/reports/q3.pdf")
            
            # Unauthorized in narrow scope (but allowed in parent)
            try:
                print("  [Attempt] Reading /data/other.txt...")
                await protected_read(path="/data/other.txt")
            except Exception as e:
                print(f"  [Blocked] {e}")

    # 6. Critical Tool Protection
    print("\n3. Critical Tool: delete_file")
    try:
        # Try to use critical tool without constraints
        async with root_task(Capability("delete_file")):
            print("  [Attempt] Deleting /data/file.txt...")
            await protected_delete(path="/data/file.txt")
    except Exception as e:
        print(f"  [Blocked] {e}")

if __name__ == "__main__":
    asyncio.run(main())
