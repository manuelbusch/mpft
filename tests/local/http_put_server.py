#!/usr/bin/env python3
"""Minimal HTTP server that supports GET and PUT (for integration tests)."""
import os, sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

class Handler(SimpleHTTPRequestHandler):
    def do_PUT(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        path = self.translate_path(self.path)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            if length:
                f.write(self.rfile.read(length))
            else:  # chunked
                while True:
                    line = self.rfile.readline().strip()
                    size = int(line, 16) if line else 0
                    if size == 0:
                        self.rfile.readline()
                        break
                    f.write(self.rfile.read(size)); self.rfile.readline()
        self.send_response(201); self.end_headers()
    def log_message(self, *a): pass

if __name__ == "__main__":
    port, root = int(sys.argv[1]), sys.argv[2]
    os.chdir(root)
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
