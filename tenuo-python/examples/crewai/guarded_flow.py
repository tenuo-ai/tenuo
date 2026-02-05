"""
GuardedFlow Example
"""
from crewai import Flow, listen, start
from crewai.tools import BaseTool
from tenuo.crewai import guarded_step, Pattern, Wildcard, TenuoCrewAIError

class SearchTool(BaseTool):
    name: str = "web_search"
    description: str = "Search"
    def _run(self, query: str) -> str: return f"Res: {query}"

class EmailTool(BaseTool):
    name: str = "send_email"
    description: str = "Email"
    def _run(self, recipient: str, body: str) -> str: return "Sent"

search_tool = SearchTool()
email_tool = EmailTool()

class ResearchFlow(Flow):

    @start()
    @guarded_step(allow={"web_search": {"query": Wildcard()}}, ttl="5m", strict=True)
    def research(self):
        print("Step 1")
        return search_tool.run(query="AI")

    @listen(research)
    @guarded_step(allow={"send_email": {"recipient": Pattern("*@co.com")}}, ttl="1m")
    def notify(self, result):
        print("Step 2")
        email_tool.run(recipient="boss@co.com", body=f"Res: {result}")
        return "Done"

if __name__ == "__main__":
    try:
        ResearchFlow().kickoff()
        print("Success")
    except TenuoCrewAIError as e:
        print(f"Error: {e}")
