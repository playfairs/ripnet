import base64
import json
import os
import pathlib
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format, *_args):
        pass

    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/echo")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path == "/redirect-loop":
            self.send_response(302)
            self.send_header("Location", "/redirect-loop")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path == "/slow":
            time.sleep(0.2)
        if self.path == "/large":
            self.respond(b"x" * 4096)
            return
        if self.path == "/binary":
            self.respond(b"\xff\x00", "application/octet-stream")
            return
        if self.path == "/status":
            self.respond(b"teapot", status=418)
            return
        self.echo()

    def do_POST(self):
        self.echo()

    def do_PUT(self):
        self.echo()

    def do_PATCH(self):
        self.echo()

    def do_DELETE(self):
        self.echo()

    def do_OPTIONS(self):
        self.echo()

    def do_TRACE(self):
        self.echo()

    def do_PURGE(self):
        self.echo()

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def echo(self):
        size = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(size) if size else b""
        payload = json.dumps(
            {
                "method": self.command,
                "path": self.path,
                "headers": dict(self.headers.items()),
                "body": body.decode("utf-8", "replace"),
            }
        ).encode()
        self.respond(payload, "application/json")

    def respond(self, body, content_type="text/plain", status=200):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)


def run(binary, args, expected=0, timeout=6):
    result = subprocess.run(
        [binary] + args,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    assert result.returncode == expected, (
        args,
        result.returncode,
        result.stdout,
        result.stderr,
    )
    return result


def response(binary, url, *args, expected=0):
    result = run(binary, ["http-request", url, "--json"] + list(args), expected)
    return result, json.loads(result.stdout)


def bulk_response(binary, url, *args, expected=0):
    result = run(binary, ["http-bulk", url, "--json"] + list(args), expected)
    return result, json.loads(result.stdout)


class QuietServer(ThreadingHTTPServer):
    def __init__(self, address, handler):
        super().__init__(address, handler)
        self.request_lock = threading.Lock()
        self.request_count = 0
        self.active_requests = 0
        self.max_active_requests = 0

    def request_started(self):
        with self.request_lock:
            self.request_count += 1
            self.active_requests += 1
            self.max_active_requests = max(
                self.max_active_requests, self.active_requests
            )

    def request_finished(self):
        with self.request_lock:
            self.active_requests -= 1

    def handle_error(self, _request, _client_address):
        pass


class CountingHandler(Handler):
    def parse_request(self):
        parsed = super().parse_request()
        if parsed:
            self.server.request_started()
            self.request_counted = True
        return parsed

    def handle_one_request(self):
        try:
            super().handle_one_request()
        finally:
            if getattr(self, "request_counted", False):
                self.server.request_finished()
                self.request_counted = False


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: http_integration.py RIPNET_BINARY")
    binary = sys.argv[1]
    server = QuietServer(("127.0.0.1", 0), CountingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = "http://127.0.0.1:%d" % server.server_port
    try:
        request_help = run(binary, ["http-request", "--help"])
        assert (
            "--insecure" in request_help.stdout
            and "--allow-trace" in request_help.stdout
        )
        bulk_help = run(binary, ["http-bulk", "--help"])
        assert "--allow-host" in bulk_help.stdout and "--dry-run" in bulk_help.stdout

        security_http = run(
            binary,
            ["security-http", "127.0.0.1", "--port", str(server.server_port), "--json"],
        )
        assert json.loads(security_http.stdout)["status_code"] == 200

        result, data = response(binary, base + "/echo")
        assert data["transport_success"] and data["status_code"] == 200
        assert json.loads(data["body"])["method"] == "GET"

        result, data = response(
            binary,
            base + "/echo",
            "--method",
            "POST",
            "--body",
            "payload",
            "--header",
            "X-Test: present",
            "--query",
            "q=hello world",
            "--bearer",
            "integration-token",
            "--cookie",
            "session=fixture",
        )
        echo = json.loads(data["body"])
        assert echo["method"] == "POST" and echo["body"] == "payload"
        assert "q=hello%20world" in echo["path"]
        assert echo["headers"]["X-Test"] == "present"
        assert echo["headers"]["Authorization"] == "Bearer integration-token"
        assert echo["headers"]["Cookie"] == "session=fixture"

        _, json_echo = response(
            binary,
            base + "/echo",
            "--method",
            "POST",
            "--body",
            '{"enabled":true}',
            "--json-body",
        )
        json_request = json.loads(json_echo["body"])
        assert json_request["headers"]["Content-Type"] == "application/json"
        assert json.loads(json_request["body"]) == {"enabled": True}
        _, form_echo = response(
            binary,
            base + "/echo",
            "--method",
            "POST",
            "--form",
            "name=alice smith",
            "--form",
            "city=New York",
        )
        form_request = json.loads(form_echo["body"])
        assert (
            form_request["headers"]["Content-Type"]
            == "application/x-www-form-urlencoded"
        )
        assert form_request["body"] == "name=alice%20smith&city=New%20York"
        _, invalid_json = response(
            binary,
            base + "/echo",
            "--method",
            "POST",
            "--body",
            "not-json",
            "--json-body",
            expected=1,
        )
        assert "invalid JSON" in invalid_json["error"]

        for method in ("PUT", "PATCH", "DELETE", "OPTIONS", "PURGE"):
            _, data = response(binary, base + "/echo", "--method", method)
            assert json.loads(data["body"])["method"] == method
        _, head = response(binary, base + "/echo", "--method", "HEAD")
        assert head["status_code"] == 200 and head["body_bytes"] == 0

        run(binary, ["http-request", base + "/echo", "--method", "TRACE"], expected=1)
        _, trace = response(
            binary, base + "/echo", "--method", "TRACE", "--allow-trace"
        )
        assert json.loads(trace["body"])["method"] == "TRACE"

        _, basic = response(binary, base + "/echo", "--basic-auth", "alice:secret")
        assert json.loads(basic["body"])["headers"]["Authorization"] == (
            "Basic " + base64.b64encode(b"alice:secret").decode()
        )

        _, redirected = response(binary, base + "/redirect")
        assert redirected["status_code"] == 200
        _, not_followed = response(binary, base + "/redirect", "--no-redirects")
        assert not_followed["status_code"] == 302
        _, redirect_error = response(
            binary, base + "/redirect-loop", "--max-redirects", "1", expected=1
        )
        assert not redirect_error["transport_success"]

        _, teapot = response(binary, base + "/status")
        assert teapot["status_code"] == 418 and teapot["transport_success"]
        _, large_error = response(
            binary, base + "/large", "--max-response", "64", expected=1
        )
        assert "size limit" in large_error["error"]
        _, timeout_error = response(
            binary, base + "/slow", "--timeout", "30", expected=1
        )
        assert not timeout_error["transport_success"]
        refused = socket.socket()
        refused.bind(("127.0.0.1", 0))
        refused_port = refused.getsockname()[1]
        refused.close()
        _, connection_error = response(
            binary, "http://127.0.0.1:%d/" % refused_port, expected=1
        )
        assert not connection_error["transport_success"]
        assert connection_error["total_ms"] == 0
        _, url_error = response(binary, "file:///etc/passwd", expected=1)
        assert not url_error["transport_success"]
        _, binary_data = response(binary, base + "/binary")
        assert binary_data["body_encoding"] == "binary"
        run(binary, ["http-request"], expected=2)

        before_dry_run = server.request_count
        _, plan = bulk_response(
            binary,
            base + "/echo",
            "--allow-host",
            "127.0.0.1",
            "--count",
            "12",
            "--dry-run",
        )
        assert (
            plan["dry_run"] and plan["request_count"] == 12 and plan["completed"] == 0
        )
        assert server.request_count == before_dry_run
        run(
            binary,
            [
                "http-bulk",
                base + "/echo",
                "--allow-host",
                "127.0.0.1",
                "--method",
                "POST",
                "--body",
                "not-json",
                "--json-body",
                "--dry-run",
            ],
            expected=2,
        )
        assert server.request_count == before_dry_run

        before_rejection = server.request_count
        run(
            binary,
            ["http-bulk", base + "/echo", "--allow-host", "example.test"],
            expected=2,
        )
        run(
            binary,
            [
                "http-bulk",
                base + "/echo",
                "--allow-host",
                "127.0.0.1",
                "--count",
                "1001",
            ],
            expected=2,
        )
        run(
            binary,
            [
                "http-bulk",
                base + "/echo",
                "--allow-host",
                "127.0.0.1",
                "--count",
                "121",
                "--max-rps",
                "1",
            ],
            expected=2,
        )
        run(
            binary,
            [
                "http-bulk",
                base + "/echo",
                "--allow-host",
                "127.0.0.1",
                "--concurrency",
                "9",
            ],
            expected=2,
        )
        with tempfile.TemporaryDirectory() as directory:
            large_request_body = pathlib.Path(directory) / "large-body.bin"
            large_request_body.write_bytes(b"z" * (9 * 1024 * 1024))
            before_body_rejection = server.request_count
            run(
                binary,
                [
                    "http-bulk",
                    base + "/echo",
                    "--allow-host",
                    "127.0.0.1",
                    "--count",
                    "2",
                    "--body-file",
                    str(large_request_body),
                ],
                expected=2,
            )
            assert server.request_count == before_body_rejection
        assert server.request_count == before_rejection

        started = time.monotonic()
        _, batch = bulk_response(
            binary,
            base + "/echo",
            "--allow-host",
            "127.0.0.1",
            "--count",
            "3",
            "--concurrency",
            "2",
            "--max-rps",
            "2",
        )
        assert (
            batch["completed"] == 3 and batch["succeeded"] == 3 and batch["failed"] == 0
        )
        assert time.monotonic() - started >= 0.9

        _, scoped_redirect = bulk_response(
            binary, base + "/redirect", "--allow-host", "127.0.0.1", "--count", "1"
        )
        assert scoped_redirect["responses"][0]["status_code"] == 302

        _, concurrent_batch = bulk_response(
            binary,
            base + "/slow",
            "--allow-host",
            "127.0.0.1",
            "--count",
            "4",
            "--concurrency",
            "2",
            "--max-rps",
            "10",
        )
        assert concurrent_batch["completed"] == 4 and server.max_active_requests <= 2
        assert server.max_active_requests > 1
        run(
            binary,
            ["http-stress", "127.0.0.1", "--port", str(server.server_port)],
            expected=1,
        )

        with tempfile.TemporaryDirectory() as directory:
            body_file = pathlib.Path(directory) / "request-body.txt"
            body_file.write_text("from-file")
            _, file_body = response(
                binary, base + "/echo", "--method", "PUT", "--body-file", str(body_file)
            )
            assert json.loads(file_body["body"])["body"] == "from-file"

            output_file = pathlib.Path(directory) / "response.bin"
            run(
                binary,
                [
                    "http-request",
                    base + "/large",
                    "--max-response",
                    "8192",
                    "--save-body",
                    str(output_file),
                ],
            )
            assert output_file.read_bytes() == b"x" * 4096

            key = pathlib.Path(directory) / "key.pem"
            cert = pathlib.Path(directory) / "cert.pem"
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-keyout",
                    str(key),
                    "-out",
                    str(cert),
                    "-days",
                    "1",
                    "-subj",
                    "/CN=localhost",
                ],
                check=True,
                capture_output=True,
            )
            tls_server = QuietServer(("127.0.0.1", 0), Handler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=cert, keyfile=key)
            tls_server.socket = context.wrap_socket(tls_server.socket, server_side=True)
            tls_thread = threading.Thread(target=tls_server.serve_forever, daemon=True)
            tls_thread.start()
            tls_url = "https://localhost:%d/echo" % tls_server.server_port
            try:
                _, tls_error = response(binary, tls_url, expected=1)
                assert not tls_error["transport_success"]
                insecure, tls_data = response(binary, tls_url, "--insecure")
                assert tls_data["transport_success"]
                assert "TLS certificate verification is disabled" in insecure.stderr
            finally:
                tls_server.shutdown()
                tls_server.server_close()

        print("HTTP local integration checks passed")
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
