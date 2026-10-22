"""Real HTTP/UDP services used only in disposable overlay test nodes."""
import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == "/bulk":
            chunk, count, delay = b"porthub-private-direct-transfer\n" * 1024, 1024, 0
        elif self.path == "/stream":
            chunk, count, delay = b"porthub-private-stream\n" * 32, 1000, 0.05
        else:
            chunk, count, delay = (socket.gethostname() + " private service\n").encode(), 1, 0
        self.send_response(200)
        self.send_header("Content-Length", str(len(chunk) * count))
        self.end_headers()
        try:
            for _ in range(count):
                self.wfile.write(chunk)
                self.wfile.flush()
                if delay:
                    time.sleep(delay)
        except (BrokenPipeError, ConnectionResetError):
            pass


def udp():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 19090))
    while True:
        payload, address = sock.recvfrom(2048)
        sock.sendto(payload, address)


HTTP_PORT = int(os.environ.get("PORTHUB_LAB_HTTP_PORT", "18080"))
threading.Thread(target=udp, daemon=True).start()
# HTTP_PORT + 1 stays reachable locally so a denied connection proves policy, not a
# missing service.
threading.Thread(target=ThreadingHTTPServer(("0.0.0.0", HTTP_PORT + 1), Handler).serve_forever, daemon=True).start()
ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), Handler).serve_forever()
