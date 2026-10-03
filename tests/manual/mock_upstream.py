#!/usr/bin/env python3
"""Mock LLM upstream for exercising the broker's key rotation.

Behaviour is controlled by the model in the request:
  mock-model          -> 200, or 429 on the first call to each key
  always-429-model    -> always 429 (every key exhausted)
  always-500-model    -> always 500
  slow-model          -> 200 after a delay (latency/EWMA paths)

Every request is logged as one JSON line so the test runner can assert on which
credential was used.
"""
import http.server
import json
import socketserver
import sys
import threading
import time

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 11798
LOG = sys.argv[2] if len(sys.argv) > 2 else "mock-upstream.log"
STATE = sys.argv[3] if len(sys.argv) > 3 else "first"

lock = threading.Lock()
seen_per_key = {}
order = []
started = time.time()


def log(entry):
    entry["t"] = round(time.time() - started, 3)
    with lock:
        with open(LOG, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\n")


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _reply(self, status, payload, extra=None):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for name, value in (extra or {}).items():
            self.send_header(name, value)
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        auth = self.headers.get("Authorization") or self.headers.get("x-api-key") or ""
        credential = auth.replace("Bearer ", "")
        try:
            payload = json.loads(raw.decode("utf-8"))
        except Exception:
            payload = {}
        model = payload.get("model", "")
        stream = bool(payload.get("stream"))

        with lock:
            count = seen_per_key.get(credential, 0) + 1
            seen_per_key[credential] = count
            order.append(credential)

        entry = {
            "credential": credential,
            "model": model,
            "path": self.path,
            "key_call": count,
            "body_len": len(raw),
            "body_model": model,
            "stream": stream,
            "host": self.headers.get("Host"),
            "user_agent": self.headers.get("User-Agent"),
        }

        if model == "always-429-model":
            entry["status"] = 429
            log(entry)
            self._reply(429, {"error": {"message": "rate limited", "type": "rate_limit_error"}},
                        {"Retry-After": "1"})
            return

        if model == "always-500-model":
            entry["status"] = 500
            log(entry)
            self._reply(500, {"error": {"message": "upstream broke"}})
            return

        if model == "slow-model":
            time.sleep(2.0)

        # Rotate-on-429 path: only the very first call to the mock is limited,
        # so a single rotation is enough to observe a 200.
        with lock:
            total = len(order)
        if STATE == "first" and model == "mock-model" and total == 1:
            entry["status"] = 429
            log(entry)
            self._reply(429, {"error": {"message": "rate limited", "type": "rate_limit_error"}},
                        {"Retry-After": "1"})
            return

        entry["status"] = 200
        log(entry)

        if stream:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Connection", "close")
            self.end_headers()
            chunks = [
                'data: {"choices":[{"delta":{"content":"he"}}]}\n\n',
                'data: {"choices":[{"delta":{"content":"llo"}}]}\n\n',
                'data: {"choices":[],"usage":{"prompt_tokens":7,"completion_tokens":3}}\n\n',
                "data: [DONE]\n\n",
            ]
            for chunk in chunks:
                data = chunk.encode()
                self.wfile.write(f"{len(data):X}\r\n".encode() + data + b"\r\n")
                self.wfile.flush()
            self.wfile.write(b"0\r\n\r\n")
            return

        self._reply(200, {
            "id": "mock-completion",
            "model": model,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": f"hello from {credential}"},
                         "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 11, "completion_tokens": 22, "total_tokens": 33},
        })

    def do_GET(self):
        log({"method": "GET", "path": self.path})
        self._reply(200, {"ok": True})

    def log_message(self, *args):
        pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    with Server(("127.0.0.1", PORT), Handler) as httpd:
        print(f"mock upstream on 127.0.0.1:{PORT} state={STATE} log={LOG}", flush=True)
        httpd.serve_forever()
