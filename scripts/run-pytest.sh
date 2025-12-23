#!/bin/bash
# Run pytest from the correct directory to avoid import conflicts
cd "$(dirname "$0")/.."
python -m pytest tenuo-python/tests/ "$@"
