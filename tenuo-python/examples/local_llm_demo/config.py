import os
import shutil

# Default configuration
LM_STUDIO_URL = os.getenv("LM_STUDIO_URL", "http://localhost:1234")
LM_STUDIO_MODEL_ID = os.getenv("LM_STUDIO_MODEL_ID")
TAVILY_API_KEY = os.getenv("TAVILY_API_KEY", "")

# Mock Search enabled if no key
USE_MOCK_SEARCH = not TAVILY_API_KEY

# Demo settings
RESEARCH_DIR = "/tmp/tenuo_demo/research"
SUMMARY_DIR = "/tmp/tenuo_demo/summary"

def setup_workspace():
    """Clean and recreate workspace directories."""
    if os.path.exists(RESEARCH_DIR):
        shutil.rmtree(RESEARCH_DIR)
    if os.path.exists(SUMMARY_DIR):
        shutil.rmtree(SUMMARY_DIR)

    os.makedirs(RESEARCH_DIR, exist_ok=True)
    os.makedirs(SUMMARY_DIR, exist_ok=True)
