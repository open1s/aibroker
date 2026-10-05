# What to do about a content finding.
#
# The broker scans the request body for the patterns in `[content_guard]` before
# it forwards anything, then asks this rule what to do:
#
#     data.llm.content.action    -- "report" or "deny"
#     data.llm.content.reason    -- optional, in words for the refusal
#
# THE MATCHED TEXT IS NOT AVAILABLE HERE, on purpose. `input` carries the *name*
# of the rule that matched, the field it was found in, and the request -- never
# the value. Passing the match in would turn this engine into a second copy of
# the secret it is judging, and its input is retained for the life of the query.
#
#   input.rule                 string   rule name from [content_guard]
#   input.field                string   which field matched, e.g. "messages"
#   input.configured           string   the action the config asked for
#   input.client.name          string?  configured client name
#   input.client.authenticated bool
#   input.request.model        string?
#   input.request.path         string
#
# `action` must be defined for *every* finding. A Rego `default` is the usual way
# to guarantee that, but a `default` must be a constant -- it cannot read
# `input`. The rule below therefore uses a catch-all body instead, which is the
# equivalent and still leaves the rule defined. If `action` comes out undefined
# for a real finding, the broker treats that as a refusal: a policy that cannot
# answer must not let the body through.
#
# A mistake in this file fails at startup. Regorus compiles lazily, so a bad rule
# in this package is invisible to the `data.llm.authz.allow` query the broker
# evaluates first; the broker evaluates this rule once with a probe input at
# startup specifically to surface it.

package llm.content

import rego.v1

# ---------------------------------------------------------------------------
# The configured `[content_guard] action` is the baseline unless a rule below
# overrides it. This keeps the policy *additive*: switching it on does not
# silently change the verdict for every pattern already in the config.
# ---------------------------------------------------------------------------
action := input.configured if {
	not overridden
}

overridden if {
	input.rule == "openai-key"
}

overridden if {
	input.rule == "aws-access-key"
}

overridden if {
	input.rule == "email-address"
}

# ---------------------------------------------------------------------------
# A provider credential must never be sent in a prompt, whoever sent it.
# ---------------------------------------------------------------------------
action := "deny" if {
	input.rule == "openai-key"
}

action := "deny" if {
	input.rule == "aws-access-key"
}

# ---------------------------------------------------------------------------
# A worked example of the thing a single global config action cannot express: an
# exception for one client. The support triage tool exists to discuss customer
# identifiers, so an email address in *its* prompts is expected -- reported, not
# refused. Every other client is refused.
#
# This is the reason to put the verdict in Rego at all: "who is asking" is part
# of "is this allowed", and the config has no way to say so.
# ---------------------------------------------------------------------------
action := "report" if {
	input.client.name == "support-triage"
	input.rule == "email-address"
}

action := "deny" if {
	input.rule == "email-address"
	not input.client.name == "support-triage"
}

# ---------------------------------------------------------------------------
# Reasons, for the refusal the caller sees.
# ---------------------------------------------------------------------------
reason := "a provider credential must not be sent in a prompt" if {
	input.rule == "openai-key"
}

reason := "an AWS access key must not be sent in a prompt" if {
	input.rule == "aws-access-key"
}

reason := "customer identifiers may only be sent by the support triage client" if {
	input.rule == "email-address"
	not input.client.name == "support-triage"
}
