"""ASGI edge for Mazaji: Flask HTTP app plus public-site WebSocket proxying.

Only public-site token URLs are routed to uploaded projects. All ordinary HTTP
requests continue through the existing Flask application via WsgiToAsgi.
"""
from __future__ import annotations

import asyncio
import os
import re
from urllib.parse import quote

import websockets
from asgiref.wsgi import WsgiToAsgi

from app import app as flask_app, db, _server_is_website, _website_path_is_public, _process_is_alive


_TOKEN_ROUTE = re.compile(r"^/public-site/([A-Za-z0-9_-]{32,})/?(.*)$")
_MAX_MESSAGE = 16 * 1024 * 1024


class MazajiASGI:
    def __init__(self, http_app):
        self.http = WsgiToAsgi(http_app)

    async def __call__(self, scope, receive, send):
        if scope.get("type") == "websocket":
            path = scope.get("path", "")
            host_value = ""
            for raw_key, raw_value in scope.get("headers", []):
                if raw_key.lower() == b"host":
                    host_value = raw_value.decode("latin-1").split(":", 1)[0].lower()
                    break
            site_domain = os.environ.get("PUBLIC_SITE_DOMAIN", "").strip().strip(".").lower()
            is_custom_site_host = bool(site_domain and host_value.endswith("." + site_domain))
            if path.startswith("/public-site/") or is_custom_site_host:
                await self._proxy_site_websocket(scope, receive, send)
                return
            await send({"type": "websocket.close", "code": 4404, "reason": "Not found"})
            return
        await self.http(scope, receive, send)

    async def _proxy_site_websocket(self, scope, receive, send):
        # Complete the ASGI opening handshake before opening an upstream socket.
        first = await receive()
        if first.get("type") != "websocket.connect":
            return
        path = scope.get("path", "")
        match = _TOKEN_ROUTE.match(path)
        token = None
        subpath = ""
        srv = None
        if match:
            token, subpath = match.groups()
            srv = next((item for item in db.get("servers", {}).values()
                        if item.get("public_token") and str(item.get("public_token")) == token), None)
        else:
            site_domain = os.environ.get("PUBLIC_SITE_DOMAIN", "").strip().strip(".").lower()
            host_value = ""
            for raw_key, raw_value in scope.get("headers", []):
                if raw_key.lower() == b"host":
                    host_value = raw_value.decode("latin-1").split(":", 1)[0].lower()
                    break
            suffix = "." + site_domain if site_domain else ""
            if suffix and host_value.endswith(suffix):
                token = host_value[:-len(suffix)]
                subpath = path.lstrip("/")
                if token and "." not in token:
                    srv = next((item for item in db.get("servers", {}).values()
                                if item.get("public_host") and str(item.get("public_host")).lower() == token), None)
        if not srv:
            await send({"type": "websocket.close", "code": 4404, "reason": "Invalid site URL"})
            return
        if (not srv or not srv.get("port") or not _server_is_website(srv)
                or srv.get("status") != "Running" or not _process_is_alive(srv)
                or not _website_path_is_public(subpath, srv)):
            await send({"type": "websocket.close", "code": 4404, "reason": "Site unavailable"})
            return

        port = int(srv["port"])
        encoded_path = "/" + quote(subpath or "", safe="/@:+")
        query = scope.get("query_string", b"").decode("latin-1")
        uri = f"ws://127.0.0.1:{port}{encoded_path}" + (f"?{query}" if query else "")

        incoming_headers = {}
        original_host = ""
        for raw_key, raw_value in scope.get("headers", []):
            key = raw_key.decode("latin-1").lower()
            value = raw_value.decode("latin-1")
            if key == "host":
                original_host = value
            if key in {"host", "connection", "upgrade", "origin", "sec-websocket-key", "sec-websocket-version",
                       "sec-websocket-extensions", "sec-websocket-protocol"}:
                continue
            if key == "cookie":
                # Keep app cookies, but never forward Mazaji's dashboard session cookie.
                cookies = []
                for item in value.split(";"):
                    if "=" not in item:
                        continue
                    cookie_name, cookie_value = item.strip().split("=", 1)
                    if cookie_name.strip().lower() != "session":
                        cookies.append(f"{cookie_name.strip()}={cookie_value}")
                if cookies:
                    incoming_headers["Cookie"] = "; ".join(cookies)
                continue
            incoming_headers[raw_key.decode("latin-1")] = value

        headers = [(k, v) for k, v in incoming_headers.items()]
        client = scope.get("client") or ("", 0)
        host_header = original_host
        site_domain = os.environ.get("PUBLIC_SITE_DOMAIN", "").strip().strip(".").lower()
        is_custom_host = bool(site_domain and host_header.split(":", 1)[0].lower().endswith("." + site_domain))
        incoming_headers["X-Forwarded-Prefix"] = "" if is_custom_host else f"/public-site/{srv.get('public_token', '')}"
        incoming_headers["X-Forwarded-Host"] = host_header
        incoming_headers["X-Forwarded-Proto"] = "https" if scope.get("scheme") == "wss" else "http"
        incoming_headers["X-Forwarded-For"] = str(client[0] if client else "")
        headers = [(k, v) for k, v in incoming_headers.items()]
        origin = None
        for raw_key, raw_value in scope.get("headers", []):
            if raw_key.lower() == b"origin":
                origin = raw_value.decode("latin-1")
                break

        accepted = False
        try:
            async with websockets.connect(
                uri,
                origin=origin,
                additional_headers=headers,
                subprotocols=scope.get("subprotocols") or None,
                open_timeout=10,
                ping_interval=20,
                ping_timeout=20,
                close_timeout=3,
                max_size=_MAX_MESSAGE,
                proxy=None,
            ) as upstream:
                await send({"type": "websocket.accept", "subprotocol": upstream.subprotocol})
                accepted = True

                async def client_to_upstream():
                    while True:
                        message = await receive()
                        kind = message.get("type")
                        if kind == "websocket.disconnect":
                            code = message.get("code", 1000) or 1000
                            await upstream.close(code=code)
                            return
                        if kind == "websocket.receive":
                            if message.get("text") is not None:
                                await upstream.send(message["text"])
                            elif message.get("bytes") is not None:
                                await upstream.send(message["bytes"])

                async def upstream_to_client():
                    async for message in upstream:
                        if isinstance(message, bytes):
                            await send({"type": "websocket.send", "bytes": message})
                        else:
                            await send({"type": "websocket.send", "text": message})

                tasks = [asyncio.create_task(client_to_upstream()), asyncio.create_task(upstream_to_client())]
                done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                client_disconnected = tasks[0] in done
                for task in pending:
                    task.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
                for task in done:
                    if not task.cancelled():
                        error = task.exception()
                        if error:
                            raise error
                if not client_disconnected:
                    await send({"type": "websocket.close", "code": upstream.close_code or 1000,
                                "reason": (upstream.close_reason or "")[:100]})
        except Exception:
            if not accepted:
                await send({"type": "websocket.close", "code": 1013, "reason": "Site WebSocket unavailable"})
            else:
                try:
                    await send({"type": "websocket.close", "code": 1011, "reason": "Upstream WebSocket error"})
                except Exception:
                    pass


application = MazajiASGI(flask_app)
