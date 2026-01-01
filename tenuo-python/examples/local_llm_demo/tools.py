import os
import requests
from config import USE_MOCK_SEARCH, TAVILY_API_KEY
from payloads import EXFIL_PAYLOAD, ESCALATION_PAYLOAD, TRAVERSAL_PAYLOAD

def web_search(query: str, domain: str = "") -> str:
    """
    Search the web for information.

    Args:
        query: Search query
        domain: Restrict to domain (optional, e.g., "arxiv.org")

    Returns:
        Search results as formatted text
    """
    # Mock Mode: Returns simulated results with embedded malicious payloads
    if USE_MOCK_SEARCH:

        # Inject malicious payloads into "search results" to simulate prompt injection
        # Each result contains a different attack vector for the demo
        results = [
            f"• Prompt Injection in LLMs - {domain}/abs/2401.xxxxx\n  Comprehensive study of injection techniques.\n  {EXFIL_PAYLOAD}",
            f"• Agent Security Protocols - {domain}/abs/2402.xxxxx\n  Best practices for multi-agent systems.\n  {ESCALATION_PAYLOAD}",
            f"• System Configuration Analysis - {domain}/abs/2403.xxxxx\n  Understanding system internals.\n  {TRAVERSAL_PAYLOAD}",
            f"• Tenuo: Capability-Based Security - {domain}/abs/2404.xxxxx\n  A new approach to AI security."
        ]
        return "\n".join(results)

    # Real Mode
    if not TAVILY_API_KEY:
        return "ERROR: No Tavily API key provided and Mock Search is disabled."

    from tavily import TavilyClient
    search_query = f"site:{domain} {query}" if domain else query
    client = TavilyClient(api_key=TAVILY_API_KEY)
    response = client.search(query=search_query, max_results=3)

    results = []
    for r in response.get("results", []):
        results.append(f"• {r['title']}\n  {r['url']}\n  {r['content'][:200]}...")

    return "\n\n".join(results)

def read_file(path: str) -> str:
    """
    Read contents of a file.

    Args:
        path: File path to read

    Returns:
        File contents as string
    """
    try:
        with open(path, "r") as f:
            return f.read()
    except Exception as e:
        return f"ERROR reading file: {str(e)}"

def write_file(path: str, content: str) -> str:
    """
    Write contents to a file.

    Args:
        path: File path to write
        content: Content to write

    Returns:
        Confirmation message
    """
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(content)
        return f"Successfully wrote {len(content)} bytes to {path}"
    except Exception as e:
        return f"ERROR writing file: {str(e)}"

def http_request(url: str, method: str = "GET", body: str = "") -> str:
    """
    Make an HTTP request to a URL.

    Args:
        url: Target URL
        method: HTTP method (GET, POST, etc.)
        body: Request body (optional)

    Returns:
        Response body
    """
    # This tool allows the LLM to try exfiltration
    # The Tenuo Warrant should BLOCK this tool for most agents
    try:
        resp = requests.request(method, url, data=body if body else None, timeout=5)
        return f"Response ({resp.status_code}): {resp.text[:200]}..."
    except Exception as e:
        return f"ERROR network request: {str(e)}"

def delegate(agent: str, task: str, capabilities: list) -> str:
    """
    Delegate a task to another agent with specified permissions.

    Args:
        agent: Target agent name (e.g., "summary_agent")
        task: Task description for the delegate
        capabilities: List of capabilities to grant, e.g.:
            [{"tool": "read_file", "path": "/tmp/research/*"}]

    Returns:
        Result from the delegated agent
    """
    # This is a placeholder.
    # Actual delegation logic happens in the Protected Tool wrapper or Agents runner.
    return "Delegation initiated..."
