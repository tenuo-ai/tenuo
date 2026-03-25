"""
Unit tests for tenuo-python core logic.

Fast, no framework dependencies, no external I/O.
Every test here should complete in < 100 ms.

Coverage areas:
  - Warrant construction, lifecycle, serialization
  - Capability / constraint evaluation
  - Enforcement engine (_enforcement.py, guards.py)
  - Authorization / allow-list / tier-1 API
  - Approval, delegation diff, chain reconstruction
  - CLI, templates, DX helpers
"""
