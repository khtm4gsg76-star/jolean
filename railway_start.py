"""Railway-safe launcher for the Mazaji ASGI application.

Reads PORT from the process environment in Python rather than relying on
shell expansion in Procfile / Docker exec-form commands.
"""
from __future__ import annotations

import os
import sys


def resolve_port(value: str | None = None) -> int:
    raw = (os.environ.get("PORT") if value is None else value) or "8080"
    try:
        port = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"Invalid PORT value {raw!r}; Railway PORT must be an integer. "
            "Remove quotes or shell expressions from PORT settings."
        ) from exc
    if not 1 <= port <= 65535:
        raise ValueError(f"PORT must be between 1 and 65535; received {port}.")
    return port


def _preserve_docker_entrypoint() -> None:
    """Re-enter the image's permission-drop script if Railway overrides ENTRYPOINT.

    Railway Start Command overrides for Docker images can bypass the Dockerfile
    ENTRYPOINT. If this launcher is invoked as root inside our image, route it
    through docker-entrypoint.sh once so /data ownership is prepared and the app
    runs as the unprivileged mazagi account.
    """
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        entrypoint = "/usr/local/bin/docker-entrypoint.sh"
        if os.path.isfile(entrypoint):
            args = [entrypoint, sys.executable, os.path.abspath(__file__), *sys.argv[1:]]
            os.execv(entrypoint, args)


def main() -> None:
    _preserve_docker_entrypoint()
    try:
        port = resolve_port()
    except ValueError as exc:
        print(f"[Mazaji launcher] {exc}", file=sys.stderr, flush=True)
        raise SystemExit(1)

    print(
        f"[Mazaji launcher] Starting ASGI application on 0.0.0.0:{port}",
        flush=True,
    )
    import uvicorn

    uvicorn.run(
        "asgi:application",
        host="0.0.0.0",
        port=port,
        proxy_headers=True,
        ws="wsproto",
        timeout_keep_alive=75,
        log_level="info",
    )


if __name__ == "__main__":
    main()
