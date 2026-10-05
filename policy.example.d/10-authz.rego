# Example egress policy, split across a directory.
#
# Point `[policy] rules_dir = "policy.example.d"` at this directory instead of
# listing `files = [...]`. Every `*.rego` beneath it is loaded in sorted order of
# its relative path, and regorus merges modules by *package* -- so this file and
# any other may both contribute to `package llm.authz`.
#
# Why a directory: a policy grows. `10-authz.rego` answers "may this leave the
# machine", `20-content.rego` answers "what about what is inside it", and each
# can be reviewed and diffed on its own by someone who does not write Rust.
#
# `policy.example.rego` is the single-file equivalent and documents every
# `input.*` field available to the admission decision below.

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
# Reasons. Optional; without them the broker derives a reason from the first
# client rule that failed.
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
