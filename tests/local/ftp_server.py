#!/usr/bin/env python3
"""pyftpdlib server: plain FTP on port A, explicit FTPS on port B (self-signed cert)."""
import sys, threading
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler, TLS_FTPHandler
from pyftpdlib.servers import ThreadedFTPServer as FTPServer

# Known defect of this server, not of the client: under concurrent connects
# pyftpdlib's ThreadedFTPServer writes the "220 ready" greeting twice on about
# 1.5 % of connections, and the client then reads the second greeting as the
# reply to USER. Reproducible with a plain Python client (connect, read one
# line, send USER, read one line) and independent of TLS; it is not a double
# handle() call, the server logs exactly one session per connection. The test
# URLs therefore carry connect_retries=1.
plain_port, tls_port, root, cert = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4]
auth = DummyAuthorizer(); auth.add_user("ftpuser", "ftppass", root, perm="elradfmwMT")

def run(handler, port):
    handler.authorizer = auth
    handler.passive_ports = range(30000, 30100)
    s = FTPServer(("127.0.0.1", port), handler); s.serve_forever()

TLS_FTPHandler.certfile = cert
threading.Thread(target=run, args=(FTPHandler, plain_port), daemon=True).start()
run(TLS_FTPHandler, tls_port)
