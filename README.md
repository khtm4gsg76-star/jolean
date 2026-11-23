# Mazaji 2026 — Bot and Website Hosting Manager

This project manages user uploads and runtime processes for Python, Node.js, PHP, and static HTML/CSS/JavaScript projects. See [README_AR.md](README_AR.md) for the full Arabic deployment guide, support matrix, and important security limitations.

The platform can prepare common dependencies and launch supported projects, but it does not automatically repair application logic. Before accepting untrusted public uploads, deploy per-project container isolation and real CPU/RAM limits. The ASGI edge proxies HTTP and WebSocket traffic for public website routes. Raw TCP and arbitrary extra ports are not supported.

Public websites support ZIP and TAR-family uploads (TAR, TAR.GZ/TGZ, TAR.BZ2/TBZ2, TAR.XZ/TXZ), safe extraction, common Python/Node/PHP web stacks, static build outputs, and WebSocket proxying. Optional wildcard site domains are configured with `PUBLIC_SITE_DOMAIN`; wildcard DNS and TLS certificates must be configured with the hosting provider. Arbitrary languages or frameworks that require unavailable runtimes/system services are not automatically supported.


## Railway PORT startup fix (automatic)

No manual Start Command entry is required. `railway.json` selects the Dockerfile and `python railway_start.py` for the base deployment plus the `production` and `pr` environments. The launcher reads Railway's injected `PORT` as an integer.

For a service that still has a stale dashboard override invoking `uvicorn ... --port ${PORT:-8080}` without a shell, the Docker image also installs a compatibility shim at `/usr/local/bin/uvicorn`. It replaces only unexpanded PORT expressions with the numeric environment value. If a legacy command bypasses Docker's entrypoint, the shim re-enters `docker-entrypoint.sh` to prepare `/data` and run as the unprivileged `mazagi` account.

**Important:** Railway must build a new image from this updated source. Restarting an old deployment or redeploying the same old commit does not include the shim. For a GitHub source, replace the repository files with this release and push the update to the branch connected to the `web` service. No manual Start Command or PORT variable change is required.
