# Mazaji 2026 — Bot and Website Hosting Manager

This project manages user uploads and runtime processes for Python, Node.js, PHP, and static HTML/CSS/JavaScript projects. See [README_AR.md](README_AR.md) for the full Arabic deployment guide, support matrix, and important security limitations.

The platform can prepare common dependencies and launch supported projects, but it does not automatically repair application logic. Before accepting untrusted public uploads, deploy per-project container isolation and real CPU/RAM limits. The ASGI edge proxies HTTP and WebSocket traffic for public website routes. Raw TCP and arbitrary extra ports are not supported.

Public websites support ZIP and TAR-family uploads (TAR, TAR.GZ/TGZ, TAR.BZ2/TBZ2, TAR.XZ/TXZ), safe extraction, common Python/Node/PHP web stacks, static build outputs, and WebSocket proxying. Optional wildcard site domains are configured with `PUBLIC_SITE_DOMAIN`; wildcard DNS and TLS certificates must be configured with the hosting provider. Arbitrary languages or frameworks that require unavailable runtimes/system services are not automatically supported.


## Railway PORT startup fix

The project uses `railway_start.py` to read the injected `PORT` environment variable directly in Python. Do not put `${PORT:-8080}` in Railway's Start Command field. The correct command is:

```bash
python railway_start.py
```

If a manual Start Command override exists in **Settings → Deploy → Start Command**, change it to `python railway_start.py` or clear the override so Railway can use `railway.json`/`Procfile`. Save and redeploy. Do not set `PORT` manually; let Railway inject it.


The launcher also detects when a Docker Start Command override bypasses the image entrypoint. In that case it re-enters `docker-entrypoint.sh` so `/data` permissions are prepared and the app runs as the unprivileged `mazagi` user.
