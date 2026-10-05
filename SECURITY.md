# Security model

What this broker protects, what it does not, and how to check each claim
yourself. Every property below was verified against a running broker; the
commands are the ones used, so they can be re-run after a change.

## What it protects

| Threat | Control |
|---|---|
| Another local process spends your API keys | Client tokens (`[[clients]]`); the proxy refuses an unauthenticated request |
| A client reaches a model or provider it should not | Per-client model/provider allow-lists, enforced before the body is forwarded |
| One client exhausts the pool | Per-client RPM, TPM and concurrency budgets |
| A secret inside a prompt leaks to a provider | `[content_guard]` patterns, optionally refusing the request; the verdict may be decided per client and per rule by a Rego `content_rule` |
| A secret inside a prompt leaks to the *log* | `[dump] redact`, applied to every dumped body and header |
| Credentials leak through the control plane | `/admin/config` and `--dump-config` redact; client tokens are never in admin output |
| A burst of rate limits becomes an outage | Cooldown escalation resets after sustained success, so one bad minute is not permanent |

## What it does not protect

Stated plainly, because a security document that only lists wins is misleading:

- **A compromise of the user account.** Anything that can read the config file,
  the token files, or this process's memory can read the keys. File modes
  (`0600`) and `file:` secrets narrow the window; they do not close it.
- **Prompt content in general.** The guard matches the patterns you configure.
  It has no notion of what "sensitive" means beyond those regexes.
- **A provider misusing what it receives.** Once a request is forwarded, the
  provider has it.
- **Anything the client sends to a provider directly**, bypassing the broker.

## Verifying it

Substitute your port and tokens. `$CLIENT` is a client token, `$ADMIN` the admin
token.

### Authentication

```bash
# No credential, an empty one, and a truncated one are all refused.
for h in "" "Authorization: Bearer " "Authorization: Bearer ${CLIENT:0:20}"; do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST localhost:11536/v1/chat/completions \
    -H 'Content-Type: application/json' ${h:+-H "$h"} \
    -d '{"model":"<model>","messages":[]}'
done            # expect 401 401 401
```

### Scoping

```bash
# A model outside the client's allow-list is refused, and never forwarded.
curl -s -o /dev/null -w "%{http_code}\n" -X POST localhost:11536/v1/chat/completions \
  -H "Authorization: Bearer $CLIENT" -H 'x-llm-model: gpt-4o' \
  -d '{"model":"gpt-4o","messages":[]}'                       # expect 403
```

### The control plane is separate

```bash
# A client token is not an admin token, and vice versa.
curl -s -o /dev/null -w "%{http_code}\n" -u "x:$CLIENT" localhost:11536/admin   # 401
curl -s -o /dev/null -w "%{http_code}\n" \
  -H "Authorization: Bearer $ADMIN" -X POST localhost:11536/v1/chat/completions \
  -d '{"model":"<model>","messages":[]}'                                        # 401
```

### No secret in any admin output

```bash
for ep in /admin /admin/status /admin/security /admin/keys /admin/config; do
  curl -s -u "x:$ADMIN" "localhost:11536$ep" | grep -q "$CLIENT" && echo "LEAK $ep"
done
```

`/admin/config` reports `env:` and `file:` references verbatim — they are not the
secret, and knowing which reference is configured is the point of the dump.

### The dashboard can refresh itself, and only read

A browser will not attach HTTP credentials to a page's own `fetch`, so the
dashboard is served a per-process, read-only token to send back. It is not the
admin token, and it is accepted for safe methods only:

```bash
# The token is in the page's own payload; the point is that it cannot write.
REFRESH=$(curl -s -u "x:$ADMIN" localhost:11536/admin \
  | python3 -c "import sys,re,json;print(json.loads(re.search(r'<script id="data"[^>]*>(.*?)</script>',sys.stdin.read(),re.S).group(1))['refresh_token'])")

curl -s -o /dev/null -w "%{http_code}\n" -H "X-Admin-Token: $REFRESH" localhost:11536/admin/status   # 200
curl -s -o /dev/null -w "%{http_code}\n" -X POST -H "X-Admin-Token: $REFRESH" \
  localhost:11536/admin/config/reload                                                               # 401
```

It is regenerated when the broker restarts, so a dashboard left open in a tab
stops refreshing rather than keeping access forever.

### The content guard

```bash
# A prompt containing a matched pattern is reported and (in `report` mode) served.
curl -s -o /dev/null -w "%{http_code}\n" -X POST localhost:11536/v1/chat/completions \
  -H "Authorization: Bearer $CLIENT" -H 'x-llm-model: <model>' \
  -d '{"model":"<model>","messages":[{"role":"user","content":"key AKIAIOSFODNN7EXAMPLE"}]}'

grep -c 'request content matched' broker.log     # the finding, naming the rule
grep -c 'AKIAIOSFODNN7EXAMPLE'    broker.log     # 0: the dump redacted it
```

With `action = "deny"` the status is 403 **and** the provider must not see the
body. Assert on the upstream, not the status: an earlier version returned 403
while the body was still forwarded, and only checking the provider caught it.

The same holds when a Rego `content_rule` decides the verdict, which is what
makes the decision per client rather than per pattern:

```bash
# config says report; the policy refuses this rule for this client
grep -c 'content policy failed' broker.log      # 0 when the policy answered
grep -c 'policy = ' broker.log                  # the policy's own reason
```

A policy that cannot answer (a rule that is undefined for this finding) refuses,
and so does one that fails to evaluate. Both are covered end-to-end: the tests
assert the upstream received no secret, not merely that the status was 403.

### Cooldowns recover

```bash
curl -s -u "x:$ADMIN" localhost:11536/admin/keys | grep -o '"cooldown_secs":[^,]*'
```

After a burst that trips several keys, the values should be one initial step
(60 s by default), not multiples of it — a level above 1 after a single burst
means the ramp is not resetting.

## Operating notes

- **Start the guard in `report`.** Watch `llm_broker_content_findings_total`
  against real traffic before switching to `deny`; a false positive that refuses
  a legitimate prompt is a broken tool.
- **Keep the guard patterns and the `[dump] redact` list in step.** They are two
  independent lists, and a shape that is detected but not redacted still lands in
  the log.
- **A `file:` secret (mode `0600`) is better than a literal**, which is readable
  by anything that can read the config and is echoed by `ps` if passed as an
  argument.
- **Alert on `llm_broker_client_denials_total{reason="unknown_credential"}`** — a
  spike is someone probing the port. Any `policy_error` means the policy is
  broken and traffic is being refused.
