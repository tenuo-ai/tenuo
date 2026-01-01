"""
Tier 1 API Demo (The "3-line API")

This example demonstrates the simplified Tier 1 API for protecting tools
and managing authority scopes.
"""

import asyncio
from tenuo import (
    configure,
    mint,
    grant,
    guard,
    SigningKey,
    Pattern,
    Capability,
)
from tenuo.schemas import ToolSchema, register_schema

# 1. Configure Tenuo (once at startup)
issuer_key = SigningKey.generate()
configure(issuer_key=issuer_key, dev_mode=True)

# 2. Register schema for critical tools (optional but recommended)
register_schema("delete_file", ToolSchema(
    recommended_constraints=["path"],
    risk_level="critical"
))

# 3. Define protected tools using @guard
@guard(tool="read_file")
async def read_file(path: str) -> str:
    print(f"  [Tool] Reading file: {path}")
    return "file content"

@guard(tool="delete_file")
async def delete_file(path: str) -> str:
    print(f"  [Tool] Deleting file: {path}")
    return "deleted"

async def main():
    print("--- Tier 1 API Demo ---")

    # 4. Use mint to define initial scope
    print("\n1. Root Task: Allow reading /data/*")
    async with mint(Capability("read_file", path=Pattern("/data/*"))):
        # Authorized call
        await read_file(path="/data/report.txt")

        # Unauthorized call (wrong path)
        try:
            print("  [Attempt] Reading /etc/passwd...")
            await read_file(path="/etc/passwd")
        except Exception as e:
            print(f"  [Blocked] {e}")

    # 5. Scoped Task: Narrowing authority
    print("\n2. Scoped Task: Narrowing to /data/reports/*")
    async with mint(Capability("read_file", path=Pattern("/data/*"))):
        # Create a narrower scope
        async with grant(Capability("read_file", path=Pattern("/data/reports/*"))):
            # Authorized in narrow scope
            await read_file(path="/data/reports/q3.pdf")

            # Unauthorized in narrow scope (but allowed in parent)
            try:
                print("  [Attempt] Reading /data/other.txt...")
                await read_file(path="/data/other.txt")
            except Exception as e:
                print(f"  [Blocked] {e}")

    # 6. Critical Tool Protection
    print("\n3. Critical Tool: delete_file")
    try:
        # Try to use critical tool without constraints
        async with mint(Capability("delete_file")):
            print("  [Attempt] Deleting /data/file.txt...")
            await delete_file(path="/data/file.txt")
    except Exception as e:
        print(f"  [Blocked] {e}")

if __name__ == "__main__":
    asyncio.run(main())
