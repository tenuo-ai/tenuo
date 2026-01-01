"""Configuration for JIT Warrant Demo."""

import os

# LM Studio settings
LM_STUDIO_URL = os.environ.get("LM_STUDIO_URL", "http://localhost:1234")
LM_STUDIO_MODEL_ID = os.environ.get("LM_STUDIO_MODEL_ID", "")

# Demo settings
USE_MOCK_FETCH = True  # Set to False to actually fetch URLs

# Output directory for summaries
OUTPUT_DIR = "/tmp/jit_demo"

def setup_workspace():
    """Create workspace directory."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)

