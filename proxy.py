"""
Point the scanner at http://192.168.208.1:8080 instead of :8111
Make sure TeamCity runs on port "127.0.0.1:8111:8111" in docker-compose.yml
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import http.client

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 8080
TEAMCITY_HOST = "localhost"
TEAMCITY_PORT = 8111


class ProxyHandler(BaseHTTPRequestHandler):

    def is_blocked(self):
        return (
            self.command == "POST"
            and self.path.endswith("/tokens/RPC2")
            and not self.headers.get("Authorization")
        )

    def forward(self):
        conn = http.client.HTTPConnection(TEAMCITY_HOST, TEAMCITY_PORT, timeout=10)
        body_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(body_len) if body_len else b""
        conn.request(self.command, self.path, body=body, headers=dict(self.headers))
        resp = conn.getresponse()
        self.send_response(resp.status)
        for k, v in resp.getheaders():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(resp.read())

    def handle_any(self):
        if self.is_blocked():
            print(f"[BLOCKED] {self.command} {self.path} from {self.client_address[0]}")
            self.send_response(401)
            self.end_headers()
        else:
            self.forward()

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = handle_any

    def log_message(self, fmt, *args):
        pass  # silence default access log


if __name__ == "__main__":
    print(f"[*] Proxy listening on {LISTEN_PORT}, forwarding to TeamCity on {TEAMCITY_PORT}")
    print(f"[*] Blocking unauthenticated POST .../tokens/RPC2")
    HTTPServer((LISTEN_HOST, LISTEN_PORT), ProxyHandler).serve_forever()