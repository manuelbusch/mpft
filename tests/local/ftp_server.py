#!/usr/bin/env python3
"""pyftpdlib server: plain FTP on port A, explicit FTPS on port B (self-signed cert)."""
import sys, threading
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler, TLS_FTPHandler
from pyftpdlib.servers import ThreadedFTPServer as FTPServer

plain_port, tls_port, root, cert = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4]
auth = DummyAuthorizer(); auth.add_user("ftpuser", "ftppass", root, perm="elradfmwMT")

def run(handler, port):
    handler.authorizer = auth
    handler.passive_ports = range(30000, 30100)
    s = FTPServer(("127.0.0.1", port), handler); s.serve_forever()

TLS_FTPHandler.certfile = cert
threading.Thread(target=run, args=(FTPHandler, plain_port), daemon=True).start()
run(TLS_FTPHandler, tls_port)
