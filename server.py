#!/usr/bin/env python3
"""Local web server and CORS-free API proxy for PasarGuard Bulk Host Editor."""

from __future__ import annotations

import argparse
import json
import re
import ssl
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

APP_DIR = Path(__file__).resolve().parent
INDEX_PATH = APP_DIR / "index.html"
ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
DEFAULT_ACCEPT = "application/json, text/plain, */*"
HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
}


def validate_proxy_payload(
    payload: dict[str, Any], default_user_agent: str | None = None
) -> tuple[str, str, str, dict[str, str], bytes | None, bool]:
    """Validate and normalize proxy request parameters."""
    raw_base_url = str(payload.get("baseUrl") or "").strip().rstrip("/")
    parsed_base = urllib.parse.urlparse(raw_base_url)
    if parsed_base.scheme not in {"http", "https"} or not parsed_base.netloc:
        raise ValueError("آدرس پنل معتبر نیست (باید با http:// یا https:// شروع شود).")

    clean_base_path = re.sub(r"/dashboard(?:/.*)?$", "", parsed_base.path).rstrip("/")
    base_url = f"{parsed_base.scheme}://{parsed_base.netloc}{clean_base_path}"

    method = str(payload.get("method") or "GET").upper()
    if method not in ALLOWED_METHODS:
        raise ValueError(f"متد HTTP نامعتبر است: {method}")

    path = str(payload.get("path") or "").strip()
    if not path.startswith("/api/"):
        raise ValueError("مسیر API باید با /api/ شروع شود.")

    target_url = f"{base_url}{path}"
    raw_headers = payload.get("headers") or {}
    headers: dict[str, str] = {
        str(k): str(v)
        for k, v in raw_headers.items()
        if str(k).lower() not in HOP_BY_HOP_HEADERS and v is not None
    }
    lower_keys = {k.lower() for k in headers}
    # PasarGuard API keys (pg_key_...) must be sent via X-Api-Key or Authorization: ApiKey, not Bearer.
    for key in list(headers.keys()):
        if key.lower() == "authorization":
            val = headers[key].strip()
            scheme, _, cred = val.partition(" ")
            token_val = cred.strip() if cred else scheme.strip()
            if token_val.startswith("pg_key_"):
                del headers[key]
                headers["X-Api-Key"] = token_val
                lower_keys = {k.lower() for k in headers}
            break
    if "user-agent" not in lower_keys:
        ua = default_user_agent if default_user_agent and not default_user_agent.startswith("Python-urllib") else DEFAULT_USER_AGENT
        headers["User-Agent"] = ua
    if "accept" not in lower_keys:
        headers["Accept"] = DEFAULT_ACCEPT

    body_bytes: bytes | None = None
    body_type = payload.get("bodyType", "json")
    body = payload.get("body")
    if body is not None and method not in {"GET"}:
        if body_type == "form":
            if isinstance(body, dict):
                body_bytes = urllib.parse.urlencode(body).encode("utf-8")
            else:
                body_bytes = str(body).encode("utf-8")
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        else:
            body_bytes = json.dumps(body).encode("utf-8")
            headers.setdefault("Content-Type", "application/json")

    insecure_ssl = bool(payload.get("insecureSsl", False))
    return target_url, method, body_type, headers, body_bytes, insecure_ssl


class _PreserveMethodRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Keep HTTP method and request body on 301/302/307/308 redirects (e.g. HTTP->HTTPS)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        method = req.get_method()
        if code in (301, 302, 307, 308) and method in (ALLOWED_METHODS | {"HEAD"}):
            newurl = newurl.replace(" ", "%20")
            newheaders = dict(req.headers)
            return urllib.request.Request(
                newurl,
                data=req.data,
                method=method,
                headers=newheaders,
                origin_req_host=req.origin_req_host,
                unverifiable=True,
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def forward_request(
    payload: dict[str, Any], timeout: float = 30.0, default_user_agent: str | None = None
) -> tuple[int, dict[str, str], bytes]:
    """Forward a single API request to the PasarGuard panel and return (status, headers, body)."""
    target_url, method, _, headers, body_bytes, insecure_ssl = validate_proxy_payload(
        payload, default_user_agent=default_user_agent
    )
    req = urllib.request.Request(target_url, data=body_bytes, headers=headers, method=method)

    handlers: list[Any] = [_PreserveMethodRedirectHandler()]
    if insecure_ssl:
        handlers.append(urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))
    opener = urllib.request.build_opener(*handlers)

    try:
        with opener.open(req, timeout=timeout) as resp:
            resp_body = resp.read()
            resp_headers = {"Content-Type": resp.headers.get("Content-Type", "application/json")}
            return resp.status, resp_headers, resp_body
    except urllib.error.HTTPError as err:
        err_body = err.read()
        content_type = err.headers.get("Content-Type", "application/json") if err.headers else "application/json"
        return err.code, {"Content-Type": content_type}, err_body
    except urllib.error.URLError as err:
        msg = json.dumps({"detail": f"خطا در اتصال به پنل: {err.reason}"}).encode("utf-8")
        return HTTPStatus.BAD_GATEWAY, {"Content-Type": "application/json; charset=utf-8"}, msg
    except TimeoutError:
        msg = json.dumps({"detail": "اتصال به پنل با تایم‌اوت مواجه شد."}).encode("utf-8")
        return HTTPStatus.GATEWAY_TIMEOUT, {"Content-Type": "application/json; charset=utf-8"}, msg


class BulkHostHandler(BaseHTTPRequestHandler):
    """HTTP handler serving the single-page UI and /proxy endpoint."""

    server_version = "PasarGuardBulkUI/1.0"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        return

    def _send_bytes(self, status: int, content_type: str, data: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _send_json(self, status: int, data: Any) -> None:
        encoded = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self._send_bytes(status, "application/json; charset=utf-8", encoded)

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path in {"/", "/index.html"}:
            if not INDEX_PATH.exists():
                self._send_json(HTTPStatus.NOT_FOUND, {"detail": "index.html not found"})
                return
            self._send_bytes(HTTPStatus.OK, "text/html; charset=utf-8", INDEX_PATH.read_bytes())
            return
        if parsed.path == "/health":
            self._send_json(HTTPStatus.OK, {"status": "ok"})
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"detail": "Not found"})

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/proxy":
            self._send_json(HTTPStatus.NOT_FOUND, {"detail": "Not found"})
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"detail": "Invalid Content-Length"})
            return

        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(HTTPStatus.BAD_REQUEST, {"detail": "Invalid JSON payload"})
            return

        if not isinstance(payload, dict):
            self._send_json(HTTPStatus.BAD_REQUEST, {"detail": "Payload must be a JSON object"})
            return

        try:
            status, headers, body = forward_request(payload, default_user_agent=self.headers.get("User-Agent"))
        except ValueError as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"detail": str(exc)})
            return

        content_type = headers.get("Content-Type", "application/json")
        self._send_bytes(status, content_type, body)


def create_server(host: str = "127.0.0.1", port: int = 8080) -> ThreadingHTTPServer:
    """Create the local HTTP server bound to localhost."""
    return ThreadingHTTPServer((host, port), BulkHostHandler)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="PasarGuard Bulk Host Editor Web UI")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="Port to listen on (default: 8080)")
    parser.add_argument("--no-browser", action="store_true", help="Do not automatically open the browser")
    args = parser.parse_args(argv)

    server = create_server(args.host, args.port)
    url = f"http://{args.host}:{server.server_port}"
    print(f"PasarGuard Bulk Host Editor running at: {url}")
    print("Press Ctrl+C to stop.")

    if not args.no_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
