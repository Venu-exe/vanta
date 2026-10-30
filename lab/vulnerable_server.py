#!/usr/bin/env python3
"""A deliberately vulnerable lab server for demonstrating VANTA end-to-end.

DO NOT expose this to a network. It exists so ``make demo`` (or a live viva
demo) produces real findings without touching a third party. Bind it to
127.0.0.1 only and the bundled engagement file already scopes it to loopback.

Run:  python3 lab/vulnerable_server.py --port 8000
"""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse


class VulnerableHandler(BaseHTTPRequestHandler):
    server_version = "nginx/1.18.0"
    sys_version = ""

    # -- helpers ----------------------------------------------------------
    def _send(self, body: str, status: int = 200, cookie: str | None = None) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        # Deliberately no Content-Security-Policy / HSTS / X-Frame-Options.
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("X-Powered-By", "PHP/7.4.3")
        if cookie:
            # Deliberately missing HttpOnly/Secure/SameSite.
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args) -> None:  # keep the demo output clean
        pass

    # -- routes -----------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)

        if parsed.path in ("/", "/index.html"):
            self._send(
                "<html><head><title>VANTA Demo Shop</title></head><body>"
                "<h1>VANTA Demo Shop</h1>"
                "<form method='get' action='/login'>"
                "<input name='username'><input name='password' type='password'>"
                "<input type='submit'></form>"
                "<a href='/search?q=shoes'>Search</a> "
                "<a href='/fetch?url=/products'>Fetch</a> "
                "<a href='/product?id=1'>Product</a>"
                "</body></html>",
                cookie="session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                "eyJzdWIiOiJndWVzdCIsInJvbGUiOiJ1c2VyIn0."
                "c2lnbmF0dXJlLXBsYWNlaG9sZGVy",
            )

        elif parsed.path == "/search":
            q = qs.get("q", [""])[0]
            # Reflected XSS: user input echoed unencoded.
            if "'" in q:
                # SQL error disclosure (error-based SQLi signature).
                self._send(
                    f"<html><body>You have an error in your SQL syntax; "
                    f"check the manual that corresponds to your MySQL server "
                    f"version for the right syntax to use near '{q}'</body></html>"
                )
            else:
                self._send(f"<html><body>Results for: {q}<br>1 product found.</body></html>")

        elif parsed.path == "/fetch":
            # Pretends to fetch a URL server-side (SSRF signal).
            url = qs.get("url", [""])[0]
            self._send(
                f"<html><body>Fetched {url} from 127.0.0.1<br>"
                f"internal-service-status: ok</body></html>"
            )

        elif parsed.path == "/product":
            pid = qs.get("id", ["1"])[0]
            if "'" in pid:
                self._send(
                    "<html><body>PostgreSQL ERROR: unterminated quoted string</body></html>"
                )
            else:
                self._send(f"<html><body>Product {pid}: VANTA Demo Shoe</body></html>")

        elif parsed.path == "/.git/config":
            self._send("[core]\n\trepositoryformatversion = 0\n", status=200)

        else:
            self._send("<html><body>404</body></html>", status=404)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    httpd = HTTPServer((args.host, args.port), VulnerableHandler)
    print(json.dumps({"lab": "vanta-demo", "url": f"http://{args.host}:{args.port}"}))
    print("Press Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
