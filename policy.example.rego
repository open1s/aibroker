# Example egress policy for LLM Broker.
#
# Copy this next to your config, point `[policy] files = [...]` at it, and edit.
# The broker asks one question per request:
#
#     data.llm.authz.allow      -- may this request leave the machine?
#
# and optionally:
#
#     data.llm.authz.reason     -- why not, in words for the caller
#
# Everything the policy can see arrives as `input`:
#
#   input.auth.ok                 bool    caller passed client authentication
#   input.auth.scheme             string  "none" | "bearer" | "api-key"
#
#   input.client.name             string? configured client name, absent when
#                                         no [[clients]] are defined
#   input.client.enabled          bool
#   input.client.allowed_models   [string] the patterns from the config
#   input.client.allowed_providers [string]
#   input.client.model_allowed    bool    broker's verdict for this model
#   input.client.provider_allowed bool    broker's verdict for this route
#
#   input.request.model           string? from `x-llm-model` or the URL path;
#                                         null when no early signal was present
#   input.request.path            string
#   input.request.method          string
#   input.request.stream          bool
#   input.request.estimated_tokens number
#
#   input.route.providers         [string] providers this request would use
#   input.route.matched           string? the route pattern that matched
#
#   input.budget.allowed          bool    rate/concurrency budget verdict
#
# `model_allowed` and `provider_allowed` are computed by the broker rather than
# in Rego on purpose: OPA's `glob.match` uses `.` as its delimiter and so would
# not match `gpt-*` against `gpt-4o`, and one implementation means the policy and
# the broker cannot disagree about what a pattern means. Use the precomputed
# booleans for ordinary allow-lists, and write your own predicates for anything
# else. `glob.match` and `regex.match` are both available if you want them.
#
# A policy error is a refusal. Traffic is never forwarded because the policy
# engine failed to evaluate.

package llm.authz

import rego.v1

# Start closed and open only the paths you intend.
default allow := false

# ---------------------------------------------------------------------------
# 1. The single-user case: no clients configured, so there is nobody to
#    authenticate and the proxy behaves as it did before this feature existed.
# ---------------------------------------------------------------------------
allow if {
	not is_string(input.client.name)
}

# ---------------------------------------------------------------------------
# 2. An authenticated client, within its configured allow-lists and budget.
#    This is the behaviour of the built-in default policy.
# ---------------------------------------------------------------------------
allow if {
	is_string(input.client.name)
	input.client.enabled
	input.auth.ok
	input.budget.allowed
	input.client.model_allowed
	input.client.provider_allowed
}

# ---------------------------------------------------------------------------
# 3. A worked example: keep large contexts away from a third-party provider.
#
#    Uncomment this INSTEAD of rule 2 if a long prompt must be treated as more
#    sensitive -- it stays on the self-hosted provider, or is refused.
#
# allow if {
# 	is_string(input.client.name)
# 	input.auth.ok
# 	input.budget.allowed
# 	input.client.model_allowed
# 	input.request.estimated_tokens <= 4000
# 	input.route.providers[_] == "on-prem"
# }
#
# reason := "prompts over 4000 tokens must stay on-prem" if {
# 	is_string(input.client.name)
# 	input.request.estimated_tokens > 4000
# }

# ---------------------------------------------------------------------------
# 4. A worked example: no streaming for one particular client, because a
#    streamed answer cannot be inspected before it forms.
#
# allow if {
# 	input.client.name != "untrusted-batch"
# }
#
# Some clients may only use named models, by regex, regardless of their
# configured allow-list:
#
# allow if {
# 	input.client.name == "ci"
# 	regex.match(`^gpt-4o(-mini)?$`, input.request.model)
# }

# ---------------------------------------------------------------------------
# Reasons. `deny_reason` is optional; without it the broker derives a reason
# from the first rule that failed.
# ---------------------------------------------------------------------------
reason := "this client is disabled" if {
	is_string(input.client.name)
	not input.client.enabled
}

reason := "client budget exhausted" if {
	is_string(input.client.name)
	not input.budget.allowed
}

reason := "this client may not use that model" if {
	is_string(input.client.name)
	not input.client.model_allowed
}

reason := "this client may not use that provider" if {
	is_string(input.client.name)
	not input.client.provider_allowed
}
