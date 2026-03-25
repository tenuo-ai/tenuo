"""
Example file validation tests.

Ensures every file in the examples/ directory stays in sync with the SDK:
  - syntax is valid Python
  - all `from tenuo import X` names actually exist
  - no deprecated API patterns are used

  test_examples.py           – static analysis of all example files
  test_authorized_workflow.py – runtime execution of the workflow example
"""
