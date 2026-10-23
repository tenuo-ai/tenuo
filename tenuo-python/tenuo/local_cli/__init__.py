"""Local controller commands, separate from the agent runtime."""


def main(argv=None):
    from .commands import main as run

    return run(argv)
