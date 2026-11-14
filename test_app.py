#!/usr/bin/env python3
"""Automated tests for PasarGuard Bulk Host Editor server and proxy."""

from __future__ import annotations

import json
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from server import create_server, validate_proxy_payload


class MockPasarGuardHandler(BaseHTTPRequestHandler):
    """Minimal mock PasarGuard backend API for end-to-end proxy testing."""

    hosts = [
        {
            "id": 1,
            "remark": "US | IR - US01 - (Miami)",
            "address": ["{TUN1DOMAIN}"],
            "port": None,
            "inbound_tag": "tunsre-us-miami<->fallback-front",
            "sni": ["example.com"],
            "host": [],
            "path": "",
            "is_disabled": False,
            "allowinsecure": False,
            "priority": 0,
        },
        {
            "id": 2,
            "remark": "US | IR - US01 - (Miami) (tun2)",
            "address": ["{TUN2DOMAIN}"],
            "port": None,
            "inbound_tag": "tunsre-us-miami<->fallback-front2",
            "sni": ["example.com"],
            "host": [],
            "path": "",
            "is_disabled": False,
            "allowinsecure": False,
            "priority": 1,
        },
    ]
    next_id = 3

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return

    def _send_json(self, status: int, data) -> None:
        raw = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _reject_urllib_ua(self) -> bool:
        ua = self.headers.get("User-Agent", "")
        if not ua or ua.startswith("Python-urllib"):
            raw = b"error code: 1010"
            self.send_response(HTTPStatus.FORBIDDEN)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return True
        return False

    def _is_authorized(self) -> bool:
        auth = self.headers.get("Authorization", "")
        x_api_key = self.headers.get("X-Api-Key", "")
        if x_api_key == "pg_key_test":
            return True
        if auth == "ApiKey pg_key_test":
            return True
        if auth == "Bearer test-token":
            return True
        return False

    def do_GET(self) -> None:
        if self._reject_urllib_ua():
            return
        if self.path == "/api/admin/token":
            self._send_json(HTTPStatus.METHOD_NOT_ALLOWED, {"detail": "Method Not Allowed"})
            return
        if self.path == "/api/hosts":
            if not self._is_authorized():
                self._send_json(HTTPStatus.UNAUTHORIZED, {"detail": "Could not validate credentials"})
                return
            self._send_json(HTTPStatus.OK, self.hosts)
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"detail": "Not found"})

    def do_POST(self) -> None:
        if self._reject_urllib_ua():
            return
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8")

        if self.path.startswith("/dashboard"):
            self._send_json(HTTPStatus.METHOD_NOT_ALLOWED, {"detail": "Method Not Allowed"})
            return

        if self.path == "/api/redirect-token":
            self.send_response(HTTPStatus.MOVED_PERMANENTLY)
            self.send_header("Location", "/api/admin/token")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if self.path == "/api/admin/token":
            parsed = urllib.parse.parse_qs(raw)
            if parsed.get("username") == ["admin"] and parsed.get("password") == ["secret"]:
                self._send_json(HTTPStatus.OK, {"access_token": "test-token", "token_type": "bearer"})
            else:
                self._send_json(HTTPStatus.UNAUTHORIZED, {"detail": "Invalid credentials"})
            return

        if self.path == "/api/hosts/bulk/delete":
            if self.headers.get("Authorization") != "Bearer test-token":
                self._send_json(HTTPStatus.UNAUTHORIZED, {"detail": "Not authenticated"})
                return
            payload = json.loads(raw)
            ids = set(payload.get("ids", []))
            before = len(self.__class__.hosts)
            self.__class__.hosts = [h for h in self.__class__.hosts if h["id"] not in ids]
            self._send_json(HTTPStatus.OK, {"count": before - len(self.__class__.hosts)})
            return

        self._send_json(HTTPStatus.NOT_FOUND, {"detail": "Not found"})

    def do_PUT(self) -> None:
        if self._reject_urllib_ua():
            return
        if self.path != "/api/hosts":
            self._send_json(HTTPStatus.NOT_FOUND, {"detail": "Not found"})
            return
        if self.headers.get("Authorization") != "Bearer test-token":
            self._send_json(HTTPStatus.UNAUTHORIZED, {"detail": "Not authenticated"})
            return

        length = int(self.headers.get("Content-Length", "0"))
        items = json.loads(self.rfile.read(length).decode("utf-8"))
        for item in items:
            if not item.get("remark"):
                self._send_json(HTTPStatus.UNPROCESSABLE_ENTITY, {"detail": {"remark": "Remark cannot be empty"}})
                return

        by_id = {h["id"]: h for h in self.__class__.hosts}
        for item in items:
            item_id = item.get("id")
            if item_id in by_id:
                by_id[item_id].update(item)
            else:
                new_item = dict(item)
                new_item["id"] = self.__class__.next_id
                self.__class__.next_id += 1
                self.__class__.hosts.append(new_item)
        self._send_json(HTTPStatus.OK, self.__class__.hosts)


class BulkHostEditorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mock_panel = ThreadingHTTPServer(("127.0.0.1", 0), MockPasarGuardHandler)
        cls.panel_url = f"http://127.0.0.1:{cls.mock_panel.server_port}"
        threading.Thread(target=cls.mock_panel.serve_forever, daemon=True).start()

        cls.ui_server = create_server("127.0.0.1", 0)
        cls.ui_url = f"http://127.0.0.1:{cls.ui_server.server_port}"
        threading.Thread(target=cls.ui_server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.ui_server.shutdown()
        cls.ui_server.server_close()
        cls.mock_panel.shutdown()
        cls.mock_panel.server_close()

    def _proxy(self, payload: dict) -> tuple[int, dict | list | str]:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.ui_url}/proxy",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req) as resp:
                raw = resp.read().decode("utf-8")
                try:
                    return resp.status, json.loads(raw)
                except json.JSONDecodeError:
                    return resp.status, raw
        except urllib.error.HTTPError as err:
            raw = err.read().decode("utf-8")
            try:
                return err.code, json.loads(raw)
            except json.JSONDecodeError:
                return err.code, raw

    def test_validate_proxy_payload_rejects_bad_inputs(self) -> None:
        with self.assertRaises(ValueError):
            validate_proxy_payload({"baseUrl": "ftp://bad.local", "path": "/api/hosts"})
        with self.assertRaises(ValueError):
            validate_proxy_payload({"baseUrl": "https://ok.local", "path": "/etc/passwd"})
        with self.assertRaises(ValueError):
            validate_proxy_payload({"baseUrl": "https://ok.local", "method": "TRACE", "path": "/api/hosts"})

    def test_serves_index_html_and_health(self) -> None:
        with urllib.request.urlopen(f"{self.ui_url}/") as resp:
            self.assertEqual(resp.status, 200)
            html = resp.read().decode("utf-8")
            self.assertIn("PasarGuard Bulk Host Editor", html)
            self.assertIn("PUT /api/hosts", html)
        with urllib.request.urlopen(f"{self.ui_url}/health") as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(json.loads(resp.read().decode("utf-8")), {"status": "ok"})

    def test_end_to_end_auth_get_put_clone_and_delete(self) -> None:
        # 1. Authenticate via form-urlencoded proxy
        status, token_res = self._proxy(
            {
                "baseUrl": self.panel_url,
                "method": "POST",
                "path": "/api/admin/token",
                "bodyType": "form",
                "body": {"username": "admin", "password": "secret"},
            }
        )
        self.assertEqual(status, 200)
        token = token_res["access_token"]

        # 2. Fetch hosts
        status, hosts = self._proxy(
            {
                "baseUrl": self.panel_url,
                "method": "GET",
                "path": "/api/hosts",
                "headers": {"Authorization": f"Bearer {token}"},
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(hosts), 2)

        # 3. Bulk update existing + clone new via PUT /api/hosts
        updated_h2 = dict(hosts[1])
        updated_h2["remark"] = updated_h2["remark"].replace("(tun2)", "(Server 2)")
        updated_h2["address"] = ["{TUN1DOMAIN}"]

        clone = dict(updated_h2)
        del clone["id"]
        clone["remark"] = f"{clone['remark']} (tun2)"
        clone["address"] = ["{TUN2DOMAIN}"]
        clone["priority"] = 2

        status, put_res = self._proxy(
            {
                "baseUrl": self.panel_url,
                "method": "PUT",
                "path": "/api/hosts",
                "headers": {"Authorization": f"Bearer {token}"},
                "body": [updated_h2, clone],
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(put_res), 3)
        self.assertEqual(put_res[1]["remark"], "US | IR - US01 - (Miami) (Server 2)")
        self.assertEqual(put_res[2]["remark"], "US | IR - US01 - (Miami) (Server 2) (tun2)")
        self.assertEqual(put_res[2]["address"], ["{TUN2DOMAIN}"])

        # 4. Upstream 422 error passthrough
        bad_clone = dict(clone)
        bad_clone["remark"] = ""
        status, err_res = self._proxy(
            {
                "baseUrl": self.panel_url,
                "method": "PUT",
                "path": "/api/hosts",
                "headers": {"Authorization": f"Bearer {token}"},
                "body": [bad_clone],
            }
        )
        self.assertEqual(status, 422)
        self.assertIn("detail", err_res)

        # 5. Bulk delete the cloned host
        status, del_res = self._proxy(
            {
                "baseUrl": self.panel_url,
                "method": "POST",
                "path": "/api/hosts/bulk/delete",
                "headers": {"Authorization": f"Bearer {token}"},
                "body": {"ids": [put_res[2]["id"]]},
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(del_res["count"], 1)

    def test_post_redirect_preserves_method_and_body(self) -> None:
        status, token_res = self._proxy(
            {
                "baseUrl": self.panel_url,
                "method": "POST",
                "path": "/api/redirect-token",
                "bodyType": "form",
                "body": {"username": "admin", "password": "secret"},
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(token_res["access_token"], "test-token")

    def test_dashboard_url_normalization(self) -> None:
        status, token_res = self._proxy(
            {
                "baseUrl": f"{self.panel_url}/dashboard/hosts",
                "method": "POST",
                "path": "/api/admin/token",
                "bodyType": "form",
                "body": {"username": "admin", "password": "secret"},
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(token_res["access_token"], "test-token")

    def test_pg_api_key_uses_x_api_key_header(self) -> None:
        status, hosts = self._proxy(
            {
                "baseUrl": self.panel_url,
                "method": "GET",
                "path": "/api/hosts",
                "headers": {"Authorization": "Bearer pg_key_test"},
            }
        )
        self.assertEqual(status, 200)
        self.assertIsInstance(hosts, list)

    def test_index_html_has_no_inline_handlers_or_modal_role(self) -> None:
        html = (Path(__file__).resolve().parent / "index.html").read_text(encoding="utf-8")
        self.assertNotIn("onclick=", html)
        self.assertNotIn('role="dialog"', html)
        self.assertNotIn("aria-modal", html)
        self.assertIn("overscroll-behavior: contain", html)
        self.assertIn('id="json-dialog"', html)
        self.assertIn("detectLocalProxy", html)
        self.assertIn("normalizeBaseUrl", html)


if __name__ == "__main__":
    unittest.main(verbosity=2)
