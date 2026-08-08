#!/usr/bin/env python3
"""Minimal mock MCP upstream for the Wardline demo.

Returns a 200 JSON-RPC result for any POST, so an allowed proxied call
reads as a real success in the demo output rather than a bare status code.
Not an MCP implementation -- just enough to stand in for one upstream.
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            req = json.loads(raw)
        except json.JSONDecodeError:
            req = {}
        tool = (req.get("params") or {}).get("name", "unknown")
        body = json.dumps({
            "jsonrpc": "2.0",
            "id": req.get("id", 1),
            "result": {"tool": tool, "ok": True},
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence per-request logging
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 39300
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
