"""``python -m tenuo_gha [hold|shim|action|doctor|check|init-secrets]`` — default is the HTTP server."""

from __future__ import annotations

import sys


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] in {
        "hold",
        "holder",
        "shim",
        "action",
        "live",
        "stop",
        "doctor",
        "check",
        "init-secrets",
    }:
        mode = sys.argv.pop(1)
        if mode in {"hold", "holder"}:
            from .holder import main as hold
            hold()
            return
        if mode == "shim":
            from .shim import main as shim
            shim()
            return
        if mode == "live":
            from .live import main as live
            live()
            return
        if mode == "doctor":
            from .doctor import main as doctor
            doctor()
            return
        if mode == "check":
            from .check import main as check
            check()
            return
        if mode == "init-secrets":
            from .init_secrets import main as init_secrets
            init_secrets()
            return
        from .action import main as action
        if mode == "stop":
            sys.argv.insert(1, "--stop")
        action()
        return
    from .app import main as serve
    serve()


if __name__ == "__main__":
    main()
