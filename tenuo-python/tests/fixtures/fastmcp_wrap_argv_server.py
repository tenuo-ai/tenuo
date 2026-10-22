"""A FastMCP server that parses its own flags at import time, as some do."""

import argparse

from fastmcp import FastMCP

ARGS = argparse.ArgumentParser().parse_args()  # fails on any flag that isn't its own

mcp = FastMCP("wrap-argv")


def main() -> None:
    mcp.run()
