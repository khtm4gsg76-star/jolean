#!/usr/local/bin/python
"""Compatibility launcher for Railway's old literal ${PORT:-8080} command.

Some Railway service Start Command overrides are executed without a shell.
In that case shell expressions arrive at Uvicorn as literal text. This shim
keeps a legacy `uvicorn ... --port ${PORT:-8080}` command working by replacing
only an unexpanded PORT expression with Railway's numeric PORT environment.
Normal numeric ports and all other Uvicorn arguments are passed unchanged.
"""
from __future__ import annotations

import os
import sys


def _is_port_placeholder(value: str) -> bool:
    cleaned = value.strip().strip("'\"")
    return "$PORT" in cleaned or "${PORT" in cleaned


def normalize_args(argv: list[str], environ: dict[str, str] | None = None) -> list[str]:
    env = os.environ if environ is None else environ
    fallback = env.get("PORT", "8080") or "8080"
    try:
        port_value = str(int(fallback))
        port_number = int(port_value)
        if not 1 <= port_number <= 65535:
            raise ValueError
    except (TypeError, ValueError):
        port_value = "8080"

    result = list(argv)
    index = 0
    while index < len(result):
        arg = result[index]
        if arg == "--port" and index + 1 < len(result):
            if _is_port_placeholder(result[index + 1]):
                result[index + 1] = port_value
            index += 2
            continue
        if arg.startswith("--port="):
            value = arg.split("=", 1)[1]
            if _is_port_placeholder(value):
                result[index] = f"--port={port_value}"
        index += 1
    return result


def _drop_to_app_user_if_needed() -> None:
    """Preserve Docker's non-root runtime when a legacy command bypasses ENTRYPOINT."""
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return
    entrypoint = "/usr/local/bin/docker-entrypoint.sh"
    if not os.path.isfile(entrypoint) or os.environ.get("MAZAGI_UVICORN_PRIVDROP") == "1":
        return
    env = os.environ.copy()
    env["MAZAGI_UVICORN_PRIVDROP"] = "1"
    args = [entrypoint, sys.executable, os.path.abspath(__file__), *sys.argv[1:]]
    os.execve(entrypoint, args, env)


def main() -> None:
    _drop_to_app_user_if_needed()
    sys.argv = [sys.argv[0], *normalize_args(sys.argv[1:])]
    from uvicorn.main import main as uvicorn_main

    uvicorn_main()


if __name__ == "__main__":
    main()
