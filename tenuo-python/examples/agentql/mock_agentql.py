"""
Mock AgentQL library for offline demos.
Simulates browser interactions without requiring a real browser or AgentQL API key.
"""
import asyncio

class MockLocator:
    def __init__(self, alias: str):
        self.alias = alias

    async def fill(self, text: str):
        # Simulate network delay
        await asyncio.sleep(0.1)
        pass

class MockPage:
    def __init__(self, url: str):
        self.url = url

    async def click(self, alias: str):
        await asyncio.sleep(0.1)
        pass

    def locator(self, alias: str) -> MockLocator:
        return MockLocator(alias)

class MockSession:
    def __init__(self):
        self.driver = self
        self.url = "about:blank"

    async def goto(self, url: str) -> MockPage:
        await asyncio.sleep(0.2)
        self.url = url
        return MockPage(url)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass

# Fake the module
start_session = MockSession
