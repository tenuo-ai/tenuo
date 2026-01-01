
import os
import sys

# Ensure we can import tenuo
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from tenuo import configure, SigningKey, Capability, Pattern, Range
from tenuo.cli import print_rich_warrant

def main():
    # 1. Setup
    print("🔐 setting up keys...")
    root_key = SigningKey.generate()
    root_key = SigningKey.generate()
    # configure uses issuer_key, not root_key
    configure(issuer_key=root_key, dev_mode=True)

    manager_key = SigningKey.generate()
    intern_key = SigningKey.generate()

    # 2. Mint Root Warrant
    print("\n👑 Minting Root Warrant...")
    from tenuo import mint_sync

    with mint_sync(
        Capability("read_file", path=Pattern("/data/*")),
        Capability("search", query=Pattern("*"), max_results=Range(1, 1000)),
        ttl=3600
    ) as root_warrant:

        # 3. Delegating to Manager
        print("\n👤 Delegating to Manager (narrowing scope)...")
        # Use grant method with bound warrant
        manager_warrant = root_warrant.bind(root_key).grant(
            to=manager_key.public_key,
            allow=[
                Capability("read_file", path=Pattern("/data/reports/*")),
                "search"
            ],
            ttl=1800
        )

        # 4. Delegating to Intern
        print("\n👶 Delegating to Intern (narrowing further)...")
        with manager_warrant.bind(manager_key) as mgr:
             intern_warrant = mgr.grant(
                to=intern_key.public_key,
                allow=[
                    Capability("search", query=Pattern("*"), max_results=Range(1, 10))
                ],
                ttl=300
             )

        # 5. Visualize
        print("\n👀 Visualizing Intern's Warrant with Rich Inspector:\n")
        try:
            if not print_rich_warrant(intern_warrant):
                print("⚠️  'rich' not installed. Install it for a better visualization: pip install rich")
                print("\nStandard explain:")
                print(intern_warrant.explain(include_chain=True))
        except Exception as e:
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    main()
