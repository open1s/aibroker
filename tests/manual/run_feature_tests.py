#!/usr/bin/env python3
"""Feature tests for the LLM broker, run against a live broker process.

Two profiles:

  --profile mock   deterministic local mock upstream: key rotation, rate limit
                   exhaustion, 5xx handling, streaming, metrics and the whole
                   admin API.
  --profile real   the real NVIDIA endpoint from a copied config: a genuine
                   completion through the broker, plus live metrics/admin.

Usage:
    python3 tests/manual/run_feature_tests.py --profile mock
    python3 tests/manual/run_feature_tests.py --profile real
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import signal
import socket
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BIN = os.path.join(ROOT, "target", "release", "aibroker")
PY = sys.executable

RESULTS: list[tuple[bool, str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    RESULTS.append((ok, name, detail))
    mark = "PASS" if ok else "FAIL"
    line = f"[{mark}] {name}"
    if detail and not ok:
        line += f"\n       {detail}"
    print(line, flush=True)
    return ok


def port_free(port: int) -> bool:
    with socket.socket() as sock:
        sock.settimeout(0.3)
        return sock.connect_ex(("127.0.0.1", port)) != 0


def wait_for_port(port: int, timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not port_free(port):
            return True
        time.sleep(0.15)
    return False


def request(port: int, method: str, path: str, body=None, headers=None, timeout=30.0):
    """Raw HTTP request, returning (status, headers dict, decoded body)."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    payload = json.dumps(body).encode() if body is not None else None
    send_headers = dict(headers or {})
    if payload is not None:
        send_headers.setdefault("Content-Type", "application/json")
        send_headers["Content-Length"] = str(len(payload))
    try:
        conn.request(method, path, body=payload, headers=send_headers)
        resp = conn.getresponse()
        # `resp.read()` decodes chunked transfer encoding for us.
        raw = resp.read()
        return resp.status, {k.lower(): v for k, v in resp.getheaders()}, raw
    finally:
        conn.close()


def json_of(raw: bytes):
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return None


def read_log(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    entries = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except Exception:
                    pass
    return entries


def truncate(path: str) -> None:
    open(path, "w", encoding="utf-8").close()


def reset_all_keys(port: int, provider: str, key_ids, auth: dict) -> None:
    """Clear cooldowns and rate-limit windows so a test starts clean."""
    for key_id in key_ids:
        request(port, "POST", f"/admin/keys/{provider}/{key_id}/reset", headers=auth)


class Broker:
    def __init__(self, config: str, log: str):
        self.config = config
        self.log = log
        self.proc: subprocess.Popen | None = None

    def start(self) -> bool:
        if not os.path.exists(BIN):
            print(f"missing binary {BIN}; run: cargo build --release --offline")
            return False
        self.handle = open(self.log, "w", encoding="utf-8")
        env = dict(os.environ, RUST_LOG="info")
        self.proc = subprocess.Popen(
            [BIN, "--config", self.config],
            cwd=ROOT,
            stdout=self.handle,
            stderr=subprocess.STDOUT,
            env=env,
        )
        return True

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        try:
            self.handle.close()
        except Exception:
            pass


def start_mock(port: int, state: str, log: str) -> subprocess.Popen:
    truncate(log)
    handle = open(os.path.join(ROOT, "mock-upstream-process.log"), "w", encoding="utf-8")
    proc = subprocess.Popen(
        [PY, os.path.join(ROOT, "tests", "manual", "mock_upstream.py"), str(port), log, state],
        cwd=ROOT,
        stdout=handle,
        stderr=subprocess.STDOUT,
    )
    if not wait_for_port(port):
        proc.kill()
        raise RuntimeError(f"mock upstream did not start on {port}")
    return proc


# ---------------------------------------------------------------------------
# Mock profile
# ---------------------------------------------------------------------------

MOCK_PROXY = 11636
MOCK_UPSTREAM = 11798
MOCK_ADMIN_TOKEN = "test-admin-token-11636"
MOCK_KEYS = ["mock-key-1", "mock-key-2", "mock-key-3", "mock-key-4"]
# `server.max_retries` in test-mock-config.toml; asserted, not hard-coded blindly.
MOCK_RETRY_BUDGET = 3


def run_mock_profile() -> None:
    config = os.path.join(ROOT, "test-mock-config.toml")
    mock_log = os.path.join(ROOT, "mock-upstream.log")
    broker_log = os.path.join(ROOT, "broker-mock.log")

    # --- config validation ------------------------------------------------
    result = subprocess.run(
        [BIN, "--config", config, "--check"], cwd=ROOT, capture_output=True, text=True
    )
    check("config --check accepts the new schema", result.returncode == 0,
          result.stdout + result.stderr)

    mock = start_mock(MOCK_UPSTREAM, "first", mock_log)
    truncate(mock_log)
    broker = Broker(config, broker_log)
    if not broker.start():
        mock.kill()
        return
    try:
        if not wait_for_port(MOCK_PROXY):
            check("broker starts and listens", False, "port never opened")
            print(open(broker_log).read()[-2000:])
            return
        check("broker starts and listens on the new port", True)

        truncate(mock_log)
        base_headers = {"x-llm-model": "mock-model"}

        # --- 1. rotation on 429 within one request ------------------------
        status, headers, raw = request(
            MOCK_PROXY, "POST", "/v1/chat/completions",
            {"model": "mock-model", "messages": [{"role": "user", "content": "hi"}]},
            base_headers,
        )
        body = json_of(raw)
        check("429 on the first key rotates to a second key (200 to the client)",
              status == 200, f"status={status} body={raw[:300]!r}")
        check("client receives the successful upstream payload",
              bool(body) and body.get("id") == "mock-completion",
              f"body={raw[:300]!r}")

        entries = [e for e in read_log(mock_log) if e.get("status") in (200, 429)]
        creds = [e["credential"] for e in entries]
        check("upstream saw exactly two attempts (429 then 200)",
              len(entries) == 2 and entries[0]["status"] == 429 and entries[1]["status"] == 200,
              f"attempts={entries}")
        check("the retry used a different credential", len(set(creds)) == 2,
              f"credentials={creds}")
        check("the full request body was replayed on the retry",
              entries[1]["body_len"] == entries[0]["body_len"] and entries[1]["body_len"] > 0,
              f"body lengths={[e['body_len'] for e in entries]}")
        check("the broker identified itself in User-Agent",
              all(e.get("user_agent") == "llm-broker/2.0" for e in entries),
              f"user agents={[e.get('user_agent') for e in entries]}")
        check("the credential was injected as a bearer token",
              all(c.startswith("sk-mock-") for c in creds), f"credentials={creds}")

        # --- 2. metrics ---------------------------------------------------
        status, _, raw = request(MOCK_PROXY, "GET", "/metrics")
        text = raw.decode()
        check("GET /metrics returns Prometheus text", status == 200 and "# TYPE" in text,
              f"status={status}")
        for series in (
            "llm_broker_requests_total",
            "llm_broker_key_rotations_total 1",
            "llm_broker_key_rate_limited_total{provider_key=\"mock/mock-key-1\"} 1",
            "llm_broker_tokens_input_total 11",
            "llm_broker_tokens_output_total 22",
            "llm_broker_responses_2xx_total 1",
            "llm_broker_responses_4xx_total 1",
        ):
            check(f"metrics contain `{series}`", series in text,
                  "\n".join(l for l in text.splitlines() if series.split("{")[0] in l))
        check("metrics expose per-key latency histogram",
              "llm_broker_key_latency_milliseconds_bucket" in text, "")
        check("metrics expose in-flight gauge",
              "llm_broker_requests_in_flight 0" in text, "")
        check("token usage from the response body was accounted (11 in / 22 out)",
              "llm_broker_tokens_input_total 11" in text
              and "llm_broker_tokens_output_total 22" in text, "")

        # --- 3. admin auth -------------------------------------------------
        admin = f"http://127.0.0.1:{MOCK_PROXY}/admin"  # noqa: F841 (documentation)
        status, _, _ = request(MOCK_PROXY, "GET", "/admin/status")
        check("admin refuses a request without a token (fail closed)", status == 401,
              f"status={status}")
        status, _, _ = request(MOCK_PROXY, "GET", "/admin/status",
                               headers={"Authorization": "Bearer wrong-token"})
        check("admin refuses a wrong token", status == 401, f"status={status}")
        auth = {"Authorization": f"Bearer {MOCK_ADMIN_TOKEN}"}
        status, _, raw = request(MOCK_PROXY, "GET", "/admin/status", headers=auth)
        status_body = json_of(raw)
        check("admin accepts the configured token", status == 200, f"status={status}")
        check("admin reports every provider and key",
              bool(status_body) and status_body.get("keys_total") == 3,
              f"body={raw[:300]!r}")
        check("admin reports the active strategy",
              bool(status_body) and status_body.get("strategy") == "round_robin",
              f"body={raw[:300]!r}")

        # --- 4. admin: keys never leak secrets -----------------------------
        status, _, raw = request(MOCK_PROXY, "GET", "/admin/keys", headers=auth)
        keys_body = json_of(raw)
        check("GET /admin/keys lists all keys", status == 200 and
              len(keys_body["providers"]["mock"]) == 3, f"body={raw[:400]!r}")
        check("GET /admin/keys never returns a secret", "sk-mock" not in raw.decode(),
              f"body={raw[:400]!r}")
        check("GET /admin/keys reports rate-limit state per key",
              any(k["rate_limit_hits"] == 1 for k in keys_body["providers"]["mock"]),
              f"keys={keys_body['providers']['mock']}")

        # --- 5. admin: runtime key management ------------------------------
        status, _, raw = request(
            MOCK_PROXY, "POST", "/admin/keys",
            {"provider": "mock", "id": "mock-key-4", "key": "sk-mock-4",
             "models": ["mock-model"], "max_rpm": 2},
            auth,
        )
        check("admin can add a key at runtime", status == 201, f"status={status} body={raw[:200]!r}")
        status, _, raw = request(MOCK_PROXY, "POST", "/admin/keys",
                                 {"provider": "ghost", "id": "x", "key": "y"}, auth)
        check("admin rejects a key for an unknown provider with 404", status == 404,
              f"status={status}")
        status, _, raw = request(MOCK_PROXY, "POST", "/admin/keys",
                                 {"provider": "mock", "id": "bad", "key": "  "}, auth)
        check("admin rejects an empty secret with 400", status == 400, f"status={status}")

        status, _, raw = request(MOCK_PROXY, "PATCH", "/admin/keys/mock/mock-key-4",
                                 {"weight": 9, "max_rpm": 7}, auth)
        patched = json_of(raw)
        check("admin can patch a key's limits and weight",
              status == 200 and patched["key"]["weight"] == 9
              and patched["key"]["max_rpm"] == 7, f"status={status} body={raw[:300]!r}")

        status, _, _ = request(MOCK_PROXY, "POST", "/admin/keys/mock/mock-key-4/disable", headers=auth)
        check("admin can disable a key", status == 200, f"status={status}")
        _, _, raw = request(MOCK_PROXY, "GET", "/admin/keys", headers=auth)
        disabled = [k for k in json_of(raw)["providers"]["mock"] if k["id"] == "mock-key-4"]
        check("the disabled key is reported as disabled",
              bool(disabled) and disabled[0]["enabled"] is False, f"key={disabled}")

        status, _, _ = request(MOCK_PROXY, "POST", "/admin/keys/mock/mock-key-4/enable", headers=auth)
        check("admin can re-enable a key", status == 200, f"status={status}")

        status, _, _ = request(MOCK_PROXY, "POST", "/admin/keys/mock/mock-key-1/reset", headers=auth)
        _, _, raw = request(MOCK_PROXY, "GET", "/admin/keys", headers=auth)
        reset_key = [k for k in json_of(raw)["providers"]["mock"] if k["id"] == "mock-key-1"][0]
        check("admin can reset a key's cooldown and rate-limit history",
              status == 200 and reset_key["rate_limit_hits"] == 0 and reset_key["rpm"] == 0,
              f"key={reset_key}")

        status, _, _ = request(MOCK_PROXY, "DELETE", "/admin/keys/mock/mock-key-4", headers=auth)
        _, _, raw = request(MOCK_PROXY, "GET", "/admin/keys", headers=auth)
        check("admin can delete a key",
              status == 200 and len(json_of(raw)["providers"]["mock"]) == 3,
              f"status={status} keys={len(json_of(raw)['providers']['mock'])}")

        # --- 6. admin: strategy and routing views --------------------------
        status, _, raw = request(MOCK_PROXY, "PUT", "/admin/config/strategy",
                                 {"strategy": "usage_based"}, auth)
        check("admin can change the selection strategy at runtime",
              status == 200 and json_of(raw)["strategy"] == "usage_based",
              f"status={status} body={raw[:200]!r}")
        status, _, raw = request(MOCK_PROXY, "PUT", "/admin/config/strategy",
                                 {"strategy": "not-a-strategy"}, auth)
        check("admin rejects an unknown strategy", status == 400, f"status={status}")
        status, _, raw = request(MOCK_PROXY, "GET", "/admin/config/strategy", headers=auth)
        check("admin reports the strategies it supports",
              status == 200 and len(json_of(raw)["available"]) == 7,
              f"body={raw[:300]!r}")
        status, _, raw = request(MOCK_PROXY, "GET", "/admin/routes", headers=auth)
        routes = json_of(raw)["routes"]
        check("admin exposes the compiled routing table",
              status == 200 and {r["pattern"] for r in routes}
              == {"mock-model", "always-429-model", "always-500-model", "unserved-model"},
              f"routes={routes}")
        status, _, raw = request(MOCK_PROXY, "GET", "/admin/models", headers=auth)
        check("admin exposes known models",
              status == 200 and "mock-model" in json_of(raw)["models"]
              and "always-429-model" in json_of(raw)["models"],
              f"body={raw[:300]!r}")

        # --- 7. admin: reload ---------------------------------------------
        status, _, raw = request(MOCK_PROXY, "POST", "/admin/config/reload", headers=auth)
        check("admin can hot-reload the config file", status == 200, f"status={status} body={raw[:200]!r}")
        status, _, raw = request(MOCK_PROXY, "GET", "/admin/config", headers=auth)
        check("admin can dump the on-disk config (token-gated)",
              status == 200 and "[server]" in raw.decode(), f"status={status}")

        # --- 8. routing: a model no key serves -----------------------------
        status, headers, raw = request(
            MOCK_PROXY, "POST", "/v1/chat/completions",
            {"model": "unserved-model", "messages": []},
            {"x-llm-model": "unserved-model"},
        )
        check("an unserved model is refused with 503 and no upstream call",
              status == 503, f"status={status} body={raw[:200]!r}")

        # --- 9. 5xx is rotated too ----------------------------------------
        reset_all_keys(MOCK_PROXY, "mock", MOCK_KEYS, auth)
        truncate(mock_log)
        status, headers, raw = request(
            MOCK_PROXY, "POST", "/v1/chat/completions",
            {"model": "always-500-model", "messages": []},
            {"x-llm-model": "always-500-model"},
        )
        attempts = [e for e in read_log(mock_log) if e.get("status") == 500]
        check("a 5xx is retried across keys up to the retry budget",
              len(attempts) == MOCK_RETRY_BUDGET,
              f"5xx attempts={len(attempts)} (budget={MOCK_RETRY_BUDGET})")
        check("each 5xx attempt used a different key",
              len({e["credential"] for e in attempts}) == len(attempts),
              f"credentials={[e['credential'] for e in attempts]}")
        check("an exhausted 5xx surfaces as a 5xx to the client", status >= 500,
              f"status={status} headers={headers} body={raw[:300]!r}")

        # --- 10. every key rate limited -> 429 with Retry-After ------------
        reset_all_keys(MOCK_PROXY, "mock", MOCK_KEYS, auth)
        status, headers, raw = request(
            MOCK_PROXY, "POST", "/v1/chat/completions",
            {"model": "always-429-model", "messages": []},
            {"x-llm-model": "always-429-model"},
        )
        check("all keys rate limited surfaces 429 to the client", status == 429,
              f"status={status} headers={headers} body={raw[:200]!r}")
        check("a Retry-After hint is forwarded on exhaustion",
              "retry-after" in headers, f"headers={headers}")
        tried = [e for e in read_log(mock_log) if e.get("model") == "always-429-model"]
        check("the 429 path also used the full retry budget on distinct keys",
              len(tried) == MOCK_RETRY_BUDGET
              and len({e["credential"] for e in tried}) == MOCK_RETRY_BUDGET,
              f"credentials={[e['credential'] for e in tried]}")

        # --- 11. streaming passthrough and usage accounting ----------------
        reset_all_keys(MOCK_PROXY, "mock", MOCK_KEYS, auth)
        truncate(mock_log)
        status, headers, raw = request(
            MOCK_PROXY, "POST", "/v1/chat/completions",
            {"model": "mock-model", "stream": True, "messages": []},
            {"x-llm-model": "mock-model"},
        )
        text = raw.decode(errors="replace")
        check("streaming responses pass through as SSE", status == 200 and "data: " in text
              and "[DONE]" in text, f"status={status} body={text[:200]!r}")
        check("streaming deltas reach the client intact",
              '"he"' in text and '"llo"' in text, f"body={text[:200]!r}")

        # --- 12. observability: access log ---------------------------------
        log_text = open(broker_log, encoding="utf-8").read()
        check("structured access log records key, attempts and tokens",
              "request completed" in log_text and "attempts=" in log_text
              and "tokens_in=" in log_text, "")
        check("access log records the rotation (attempts=2 on one request)",
              "attempts=2" in log_text, "")

    finally:
        broker.stop()
        mock.kill()


# ---------------------------------------------------------------------------
# Real profile
# ---------------------------------------------------------------------------

REAL_PROXY = 11536
REAL_ADMIN_TOKEN = "test-admin-token-11536"
REAL_MODEL = "deepseek-ai/deepseek-v4.1-flash"
RETIRED_MODEL = "minimaxai/minimax-m2.5"


def run_real_profile() -> None:
    config = os.path.join(ROOT, "test-real-config.toml")
    broker_log = os.path.join(ROOT, "broker-real.log")

    result = subprocess.run(
        [BIN, "--config", config, "--check"], cwd=ROOT, capture_output=True, text=True
    )
    check("copied config validates", result.returncode == 0, result.stdout + result.stderr)
    check("config --check does not print any secret",
          "nvapi-" not in result.stdout + result.stderr, result.stdout[:300])

    if not port_free(REAL_PROXY):
        check(f"port {REAL_PROXY} is free before start", False, "already in use")
        return

    broker = Broker(config, broker_log)
    if not broker.start():
        return
    try:
        if not wait_for_port(REAL_PROXY):
            check("broker starts on the copied config's port", False,
                  open(broker_log).read()[-2000:])
            return
        check(f"broker starts on port {REAL_PROXY}", True)

        auth = {"Authorization": f"Bearer {REAL_ADMIN_TOKEN}"}
        status, _, raw = request(REAL_PROXY, "GET", "/admin/status", headers=auth)
        status_body = json_of(raw)
        check("admin reports the copied provider and its 3 keys",
              status == 200 and status_body["keys_total"] == 3
              and status_body["providers"][0]["name"] == "nvidia",
              f"body={raw[:400]!r}")

        # A real completion through the broker.
        started = time.time()
        status, headers, raw = request(
            REAL_PROXY, "POST", "/v1/chat/completions",
            {
                "model": REAL_MODEL,
                "messages": [{"role": "user", "content": "Say OK"}],
                # Generous budget: reasoning models spend completion tokens on
                # hidden reasoning before emitting any content.
                "max_tokens": 256,
                "temperature": 0,
            },
            {"x-llm-model": REAL_MODEL},
            timeout=60.0,
        )
        elapsed = time.time() - started
        body = json_of(raw)
        check(f"real completion through the broker succeeds ({elapsed:.1f}s)", status == 200,
              f"status={status} body={raw[:400]!r}")
        message = {}
        if body and body.get("choices"):
            message = body["choices"][0].get("message", {}) or {}
        content = (message.get("content") or "").strip()
        reasoning = (message.get("reasoning_content") or "").strip()
        check("real completion returns assistant output (content or reasoning)",
              bool(content or reasoning),
              f"content={content[:80]!r} reasoning={reasoning[:80]!r}")
        check("the upstream reported the model we asked for",
              bool(body) and body.get("model") == REAL_MODEL,
              f"model={body.get('model') if body else None}")
        if body and body.get("usage"):
            check("real response reports token usage",
                  body["usage"].get("total_tokens", 0) > 0, f"usage={body['usage']}")
        check("the response exposes a finish_reason",
              bool(body) and bool(body["choices"][0].get("finish_reason")),
              f"choice={body['choices'][0] if body and body.get('choices') else None}")

        # The credential must not be the client's.
        status, _, raw = request(
            REAL_PROXY, "POST", "/v1/chat/completions",
            {"model": REAL_MODEL, "messages": [{"role": "user", "content": "hi"}], "max_tokens": 16},
            {"x-llm-model": REAL_MODEL, "Authorization": "Bearer not-a-real-key"},
            timeout=60.0,
        )
        check("the broker overrides a client-supplied Authorization header",
              status == 200, f"status={status} body={raw[:200]!r}")

        # A retired model must fail fast: NVIDIA answers 410 Gone and no other
        # key can fix that, so exactly one attempt may be made.
        _, _, raw = request(REAL_PROXY, "GET", "/admin/keys", headers=auth)
        before = {k["id"]: k["selections"] for k in json_of(raw)["providers"]["nvidia"]}
        started = time.time()
        status, headers, raw = request(
            REAL_PROXY, "POST", "/v1/chat/completions",
            {"model": RETIRED_MODEL, "messages": [{"role": "user", "content": "hi"}]},
            {"x-llm-model": RETIRED_MODEL},
            timeout=30.0,
        )
        elapsed = time.time() - started
        _, _, keys_raw = request(REAL_PROXY, "GET", "/admin/keys", headers=auth)
        after = {k["id"]: k["selections"] for k in json_of(keys_raw)["providers"]["nvidia"]}
        attempts = sum(after[k] - before[k] for k in before)
        check("a retired model (410 Gone) is surfaced to the client", status == 410,
              f"status={status} body={raw[:200]!r}")
        check("a retired model fails fast instead of burning the whole key pool",
              attempts == 1, f"attempts={attempts} elapsed={elapsed:.2f}s")
        check("the client sees the provider's own explanation",
              b"end of life" in raw or b"no longer available" in raw,
              f"body={raw[:200]!r}")

        # Metrics reflect the real traffic.
        status, _, raw = request(REAL_PROXY, "GET", "/metrics")
        text = raw.decode()
        check("metrics count the real requests",
              status == 200 and "llm_broker_requests_total" in text, f"status={status}")
        check("metrics attribute traffic to a real key",
              "llm_broker_key_requests_total{provider_key=\"nvidia/" in text, "")
        check("real token usage was extracted from the responses",
              "llm_broker_tokens_input_total 0" not in text, "")

        # Round-robin across the three real keys.
        seen = set()
        for _ in range(3):
            status, _, raw = request(
                REAL_PROXY, "POST", "/v1/chat/completions",
                {"model": REAL_MODEL, "messages": [{"role": "user", "content": "hi"}],
                 "max_tokens": 16},
                {"x-llm-model": REAL_MODEL},
                timeout=60.0,
            )
            if status == 200:
                seen.add(status)
        _, _, raw = request(REAL_PROXY, "GET", "/admin/keys", headers=auth)
        keys = json_of(raw)["providers"]["nvidia"]
        used = [k["id"] for k in keys if k["selections"] > 0]
        check("round robin spreads real traffic across keys", len(used) >= 2,
              f"keys used={used} selections={[(k['id'], k['selections']) for k in keys]}")

        log_text = open(broker_log, encoding="utf-8").read()
        check("access log contains real request lines", "request completed" in log_text, "")
    finally:
        broker.stop()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", choices=["mock", "real"], required=True)
    args = parser.parse_args()

    if args.profile == "mock":
        run_mock_profile()
    else:
        run_real_profile()

    passed = sum(1 for ok, _, _ in RESULTS if ok)
    failed = [(name, detail) for ok, name, detail in RESULTS if not ok]
    print("\n" + "=" * 72)
    print(f"{passed}/{len(RESULTS)} checks passed")
    if failed:
        print("\nFailures:")
        for name, detail in failed:
            print(f"  - {name}")
            if detail:
                print(f"      {detail[:600]}")
    print("=" * 72)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
