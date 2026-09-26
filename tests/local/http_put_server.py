#!/usr/bin/env python3
"""Minimal HTTP server that supports GET and PUT (for integration tests)."""
import os, sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

class Handler(SimpleHTTPRequestHandler):
    def do_PUT(self):
        # Chunked is what the header says, not what a missing or zero
        # Content-Length suggests: an empty file has "Content-Length: 0",
        # and reading chunks from it would wait for the client's timeout.
        chunked = "chunked" in self.headers.get("Transfer-Encoding", "").lower()
        length = int(self.headers.get("Content-Length", 0) or 0)
        path = self.translate_path(self.path)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            if chunked:
                while True:
                    # The size, possibly followed by ";extensions".
                    line = self.rfile.readline().split(b";")[0].strip()
                    size = int(line, 16) if line else 0
                    if size == 0:
                        # Trailers, if any, up to the empty line.
                        while self.rfile.readline().strip():
                            pass
                        break
                    f.write(self.rfile.read(size)); self.rfile.readline()
            elif length:
                f.write(self.rfile.read(length))
        # For the bearer-token test: record what the client authorized with.
        auth = self.headers.get("Authorization")
        if auth:
            with open(path + ".auth", "w") as f:
                f.write(auth)
        self.send_response(201); self.end_headers()
    def log_message(self, *a): pass

if __name__ == "__main__":
    port, root = int(sys.argv[1]), sys.argv[2]
    os.chdir(root)
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
