
from typing import Any


class LazySemanticLocator:
    """
    Lazy locator that resolves an AgentQL prompt only when an action is taken.
    This bridges the gap between sync .locator() and async .get_by_prompt().
    """
    def __init__(self, page, prompt: str, agent: Any):
        self._page = page
        self._prompt = prompt
        self._agent = agent

    async def fill(self, value: str, **kwargs):
        self._agent.authorize("fill", {"element": self._prompt})
        element = await self._page.get_by_prompt(self._prompt)
        await element.fill(value, **kwargs)

    async def click(self, **kwargs):
        self._agent.authorize("click", {"element": self._prompt})
        element = await self._page.get_by_prompt(self._prompt)
        await element.click(**kwargs)
