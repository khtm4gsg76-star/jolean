# Mazaji 2026 — Bot and Website Hosting Manager

This project manages user uploads and runtime processes for Python, Node.js, PHP, and static HTML/CSS/JavaScript projects. See [README_AR.md](README_AR.md) for the full Arabic deployment guide, support matrix, and important security limitations.

The platform can prepare common dependencies and launch supported projects, but it does not automatically repair application logic. Before accepting untrusted public uploads, deploy per-project container isolation and real CPU/RAM limits. The ASGI edge proxies HTTP and WebSocket traffic for public website routes. Raw TCP and arbitrary extra ports are not supported.

Public websites support ZIP and TAR-family uploads (TAR, TAR.GZ/TGZ, TAR.BZ2/TBZ2, TAR.XZ/TXZ), safe extraction, common Python/Node/PHP web stacks, static build outputs, and WebSocket proxying. Optional wildcard site domains are configured with `PUBLIC_SITE_DOMAIN`; wildcard DNS and TLS certificates must be configured with the hosting provider. Arbitrary languages or frameworks that require unavailable runtimes/system services are not automatically supported.
