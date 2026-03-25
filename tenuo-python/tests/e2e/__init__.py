"""
End-to-end and live integration tests.

These tests require external services or in-process servers.
They are slower (1-10 s each) and may have additional setup requirements.

  test_smoke.py          – import smoke tests for all adapter extras
  test_temporal_e2e.py   – Temporal workflow end-to-end (no live server)
  test_temporal_live.py  – Temporal with an in-process server (opt-in)

Running:
  pytest tests/e2e/                              # all e2e except live
  TEMPORAL_LIVE_TESTS=1 pytest tests/e2e/test_temporal_live.py
"""
