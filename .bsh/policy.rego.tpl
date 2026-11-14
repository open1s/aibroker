# =============================================================================
# Workspace tool policy - TEMPLATE (not enforced)
#
# bsh reads .bsh/policy.rego, NOT this file. Copy this file to
# .bsh/policy.rego (same folder, drop the .tpl suffix) to make it this
# workspace's policy. Every read, write, egress and spawn then asks this module
# as well as the baseline, the session tier and the preset modules.
#
# A workspace policy can only NARROW: every module must allow, so nothing here
# can widen a refusal another module already made. The verdict below therefore
# ALLOWS by default; the worked examples refuse only when switched on.
#
# If this file does not parse, or its verdict is undefined for a question, the
# host applies its failure asymmetry: writes and egress are DENIED and a read
# that resolves inside the workspace is allowed. A broken policy never opens
# the door.
#
# The input document, one question at a time:
#   input.session         the turn's session id
#   input.preset          the agent preset id in effect ("" when none)
#   input.tool            the tool asking: read_file, write_file, bash,
#                         browser_open, mcp, run_in_background, subagent, ...
#   input.action          "read" | "write" | "egress" | "spawn" | "capability"
#   input.target.kind     "path" | "host"
#   input.target.path     absolute path (kind == "path")
#   input.target.host     hostname as written (kind == "host")
#   input.target.ip       the resolved address the decision is made on
#   input.target.port     destination port, or null when the caller had none
#   input.workspace_root  the absolute workspace root
#
# The data document, installed once per build:
#   data.workspace_root / data.workspace_prefix   the root, and "root/" for a
#                                                 single startswith containment
#   data.permission                               effective mode: "read-only",
#                                                 "workspace-write" or
#                                                 "danger-full-access"
#   data.preset / data.preset_permission          preset in force, its ceiling
#   data.sandbox_enabled                          the settings master switch:
#                                                 true = the switch is on, false
#                                                 = it is off for every preset.
#   data.sandbox_confined                         the RESOLVED answer: true only
#                                                 while heel actually confines
#                                                 this turn. False with the switch
#                                                 off AND at full access (where
#                                                 the permission releases the
#                                                 shell, unless a preset forces
#                                                 heel). A policy that REQUIRES
#                                                 confinement reads THIS key; the
#                                                 spawn question is still asked,
#                                                 so it can refuse (example 5).
#   data.egress_unrestricted                      true when the workspace has NO
#                                                 .bsh/egress-allowlist file
#   data.egress_allowlist / data.egress_hosts / data.egress_ports
#                                                 the workspace allowlist rules
#   data.preset_egress_allowlist / _hosts / _ports
#                                                 the preset's own egress rules
#
# Rule ids: a "# rule: <id>" comment is reported with a refusal; the verdict's
# "rule" field repeats the id. A denial's "reason" is shown to the reader, so
# write it for a person. The Policy pane lists this module and its rule ids.
# =============================================================================

package policy.workspace

# -----------------------------------------------------------------------------
# The switch. The worked examples are compiled but inert while this is false,
# so copying this template changes nothing. Set it to true after editing the
# lists below.
# -----------------------------------------------------------------------------
examples := false

# -----------------------------------------------------------------------------
# The verdict. The first matching branch decides; the last branch allows.
# -----------------------------------------------------------------------------

# rule: workspace-deny-path
verdict := {"allow": false, "rule": "workspace-deny-path", "reason": "the path is on this workspace's deny list"} if {
    examples
    denied_path(input.target)
# rule: workspace-deny-egress-port
} else := {"allow": false, "rule": "workspace-deny-egress-port", "reason": "the destination port is not on this workspace's list"} if {
    examples
    denied_port(input)
# rule: workspace-deny-host
} else := {"allow": false, "rule": "workspace-deny-host", "reason": "the destination is on this workspace's deny list"} if {
    examples
    denied_host(input)
# rule: workspace-deny-tool
} else := {"allow": false, "rule": "workspace-deny-tool", "reason": "this workspace does not offer this tool"} if {
    examples
    denied_tool(input)
# rule: workspace-require-sandbox
} else := {"allow": false, "rule": "workspace-require-sandbox", "reason": "this workspace requires the sandbox; turn it back on to run commands"} if {
    examples
    denied_unconfined_spawn(input)
# rule: workspace-allow
} else := {"allow": true, "rule": "workspace-allow"}

# -----------------------------------------------------------------------------
# 1. Paths this workspace refuses.
#
# deny_paths holds absolute prefixes: the directory itself and everything under
# it. The trailing slash is required.
#
# deny_segments holds names that are refused wherever they appear, so ".env"
# also refuses "config/.env".
# -----------------------------------------------------------------------------
deny_paths := [
    # "/absolute/path/to/your-secrets/",
]

deny_segments := [
    # ".env",
    # "id_rsa",
]

denied_path(target) if {
    target.kind == "path"
    some prefix in deny_paths
    startswith(concat("", [target.path, "/"]), prefix)
}

# The appended slash makes a file with that exact name match as a segment.
denied_path(target) if {
    target.kind == "path"
    some segment in deny_segments
    contains(concat("", [target.path, "/"]), concat("", ["/", segment, "/"]))
}

# -----------------------------------------------------------------------------
# 2. Destination ports (egress only).
#
# Flip enforce_egress_ports to true to use the list. An empty list with the
# switch on refuses EVERY port, and a request whose port the caller could not
# state is refused too: a port list never admits an unknown port.
# -----------------------------------------------------------------------------
enforce_egress_ports := false

allowed_egress_ports := [
    # 443,
]

denied_port(input) if {
    enforce_egress_ports
    input.action == "egress"
    not port_allowed(input.target.port)
}

port_allowed(port) if {
    some allowed in allowed_egress_ports
    port == allowed
}

# -----------------------------------------------------------------------------
# 3. Destination hosts (egress only).
#
# The allowlist file is the normal door. This is the other direction: refuse a
# destination the allowlist would otherwise permit. Matching the HOSTNAME is
# the weaker door (a DNS rebind keeps the name); the allowlist matches the
# resolved address for exactly that reason. Suffixes start with "." and match
# any name ending in them.
# -----------------------------------------------------------------------------
deny_hosts := [
    # "telemetry.example.com",
]

deny_host_suffixes := [
    # ".ads.example.com",
]

denied_host(input) if {
    input.action == "egress"
    some host in deny_hosts
    input.target.host == host
}

denied_host(input) if {
    input.action == "egress"
    some suffix in deny_host_suffixes
    endswith(input.target.host, suffix)
}

# -----------------------------------------------------------------------------
# 4. Tools this workspace does not offer.
#
# The tool name refuses both the registration question ("capability", asked for
# the gated tools bash, run_in_background, job_output, job_kill and subagent)
# and every call-time action, so a tool named here cannot slip in through a
# turn that was built before this policy was saved.
# -----------------------------------------------------------------------------
deny_tools := [
    # "browser_open",
    # "mcp",
]

denied_tool(input) if {
    some tool in deny_tools
    input.tool == tool
}

# -----------------------------------------------------------------------------
# 5. Require the sandbox for shell spawns.
#
# data.sandbox_confined is the RESOLVED answer: true only while heel actually
# confines this turn. It is the key to require, because the master switch alone
# is not enough - at full access the permission releases the shell with the
# switch still on, and a preset's `sandbox = "heel"` confines a full-access
# session, which this key follows. The spawn question is asked even for an
# unconfined shell, so a workspace that REQUIRES confinement can refuse it
# here: the call fails before a process exists. Set require_sandbox to true to
# make confinement a floor rather than a release. The interactive terminal is
# a separate seam with its own .bsh/terminal-policy.rego gate.
# -----------------------------------------------------------------------------
require_sandbox := false

denied_unconfined_spawn(input) if {
    require_sandbox
    not data.sandbox_confined
    input.action == "spawn"
}
