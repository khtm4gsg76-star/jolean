#!/usr/bin/env python3
"""Mazaji static website server with safe file serving and SPA route fallback.

The public document root must never expose repository metadata, credentials,
Python source, local databases, logs, or generated server files.
"""
import argparse
import os
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote, unquote, urlsplit


BLOCKED_DIRS = {
    ".git", ".svn", ".hg", ".venv", "venv", "node_modules", "__pycache__",
    ".idea", ".vscode", "portable_data", ".mazagi-home", ".mazagi-tmp",
}
BLOCKED_NAMES = {
    ".env", "db.json", "credentials.json", "service-account.json", ".htpasswd",
    "id_rsa", "id_ed25519", "out.log", "errors.log", "server.log",
    "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
    "composer.json", "composer.lock", "requirements.txt", "pyproject.toml", "pipfile",
}
BLOCKED_SUFFIXES = (
    ".py", ".pyc", ".pyo", ".log", ".sqlite", ".sqlite3", ".db", ".pem",
    ".key", ".p12", ".pfx", ".bak", ".swp", ".tmp", ".upload_tmp", ".replace_tmp",
    ".php", ".phtml", ".phar", ".inc", ".sh", ".bash", ".ps1", ".bat",
    ".ts", ".tsx", ".jsx",
)


def is_public_path(raw_path: str) -> bool:
    decoded = raw_path or "/"
    for _ in range(3):
        newer = unquote(decoded)
        if newer == decoded:
            break
        decoded = newer
    decoded = decoded.replace("\\", "/")
    parts = [part.casefold() for part in decoded.split("/") if part and part not in (".", "..")]
    if any(part in BLOCKED_DIRS or (part.startswith(".") and part != ".well-known") or part.startswith(".env") for part in parts):
        return False
    if any(part in BLOCKED_NAMES for part in parts):
        return False
    if parts and parts[-1].endswith(BLOCKED_SUFFIXES):
        return False
    return True


class MazajiStaticHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, directory=None, default_page="index.html", **kwargs):
        self.default_page = default_page
        self.site_root = os.path.realpath(directory or os.getcwd())
        super().__init__(*args, directory=self.site_root, **kwargs)

    def translate_path(self, path):
        translated = os.path.realpath(super().translate_path(path))
        try:
            if os.path.commonpath([self.site_root, translated]) == self.site_root:
                return translated
        except ValueError:
            pass
        return os.path.join(self.site_root, ".mazagi-path-not-found")

    def list_directory(self, path):
        self.send_error(403, "Directory listing is disabled")
        return None

    def send_head(self):
        raw_path = urlsplit(self.path).path
        if not is_public_path(raw_path):
            self.send_error(404, "File not found")
            return None
        if raw_path in ("", "/"):
            default_target = os.path.join(self.site_root, self.default_page)
            if os.path.isfile(default_target):
                self.path = "/" + quote(self.default_page, safe="/")
        elif raw_path:
            candidate = self.translate_path(self.path)
            is_missing = not os.path.exists(candidate)
            final_segment = raw_path.rsplit("/", 1)[-1]
            looks_like_asset = "." in final_segment
            accepts_html = "text/html" in self.headers.get("Accept", "")
            if is_missing and not looks_like_asset and (accepts_html or not self.headers.get("Accept")):
                fallback = os.path.join(self.site_root, self.default_page)
                if os.path.isfile(fallback):
                    self.path = "/" + quote(self.default_page, safe="/")

        # Check the real target after resolving symlinks as well as the URL.
        # A harmless-looking /config link must not expose a hidden .env target.
        resolved = self.translate_path(self.path)
        try:
            relative = os.path.relpath(resolved, self.site_root).replace(os.sep, "/")
            if relative != "." and not is_public_path("/" + relative):
                self.send_error(404, "File not found")
                return None
        except (OSError, ValueError):
            self.send_error(404, "File not found")
            return None
        return super().send_head()

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        super().end_headers()


def main():
    parser = argparse.ArgumentParser(description="Mazaji static site server")
    parser.add_argument("port", type=int)
    parser.add_argument("directory")
    parser.add_argument("default_page", nargs="?", default="index.html")
    args = parser.parse_args()
    directory = os.path.realpath(args.directory)
    default_page = os.path.normpath(args.default_page).replace("\\", "/")
    target = os.path.realpath(os.path.join(directory, default_page))
    if (not os.path.isdir(directory) or
            os.path.commonpath([directory, target]) != directory or
            not os.path.isfile(target) or not target.lower().endswith((".html", ".htm"))):
        raise SystemExit("Static site directory/default page is invalid")
    handler = lambda *a, **kw: MazajiStaticHandler(*a, directory=directory, default_page=default_page, **kw)
    server = ThreadingHTTPServer(("0.0.0.0", args.port), handler)
    server.daemon_threads = True
    print(f"Mazaji static site listening on 0.0.0.0:{args.port} from {directory}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
