# =============================================================================
# Interactive terminal policy - TEMPLATE (not enforced)
#
# bsh reads .bsh/terminal-policy.rego, NOT this file. Copy this file to
# .bsh/terminal-policy.rego (same folder, drop the .tpl suffix) to make it this
# workspace's terminal policy. The pane also writes this same policy body to
# that name when it first opens in a workspace that has none, so the file the
# pane drops and the file a reader copies carry the same rules.
#
# The file is TRI-STATE:
#
#   no file at all        every gate is OPEN. That is the documented default,
#                         and the shipped policy module is the only one that
#                         applies: nothing is refused.
#   a file that parses    decides. It can only NARROW, because the shipped
#                         allow-all baseline stays underneath it.
#   a file that does      closes BOTH gates - start and input. An
#   NOT parse             unusable rule must never widen the gate it was meant
#                         to narrow: on the first load the pane reports the
#                         refusal and spawns nothing. A broken RELOAD keeps the
#                         LAST GOOD policy in force and records the parse error
#                         in the audit ring and the status line; deleting the
#                         file restores the allow-all default.
#
# This gate is the INTERACTIVE PANE's: the shell it spawns and the line a
# reader submits. It is NOT the workspace tool
# policy - .bsh/policy.rego, whose template is policy.rego.tpl beside this file,
# gates TOOL CALLS (read, write, egress, spawn, capability). The two are
# separate seams answering different questions, and neither widens the other.
#
# The body below documents the exact input and answer shapes and carries two
# worked examples behind one switch.
# =============================================================================

package terminal

# The terminal gate asks this policy at two points, each with its own input
# document. Every field is always present; 'deny' is bsh's own escape hatch and
# is always false, so a policy may ignore it.
#
#   start   {"action": "start",  "command": <shell path>, "shell": <shell path>,
#            "cwd": <workspace>, "deny": false}
#           Asked before any process exists. 'command' and 'shell' are the same
#           path. A refused start spawns NOTHING: it is the only door that
#           guarantees no process runs.
#
#   input   {"action": "input",  "command": <the submitted line, exactly>,
#            "cwd": <workspace>, "deny": false}
#           Asked on Enter, before the submitting carriage return is written.
#           'cwd' is the directory the terminal STARTED in, so a 'cd' the shell
#           made is invisible here.
#
# There used to be a third point, 'output', asked per chunk read from the PTY.
# The pane's terminal is now libghostty, which reads the PTY itself and draws
# the bytes directly, so no chunk passes through bsh and no output rule is ever
# consulted. Rules that mention action "output" are accepted and ignored.
#
# Answer with a BOOLEAN, or with an OBJECT to explain a refusal:
#
#   {"allow": true}
#   {"allow": false, "reason": "<shown in the pane's status line>"}
#
# An object that omits 'allow' reads as false. Telling the points apart is one
# test on the action: input.action == "start" / "input".
#
# The default is open. Narrow it by naming what to refuse below.
default allow := true

# -----------------------------------------------------------------------------
# The switch. Every worked example is guarded by it AND reads a list that starts
# EMPTY, so flipping it to true on its own changes NOTHING: name what to refuse
# in the list first, then flip. Flipping it back to false disables every example
# at once without deleting it.
# -----------------------------------------------------------------------------
examples := false

# -----------------------------------------------------------------------------
# 1. Refuse a destructive input line.
#
# A line containing one of these substrings is refused and never submitted: no
# carriage return reaches the shell, and Ctrl-U clears what it echoed.
# -----------------------------------------------------------------------------
denied_commands := [
    # "rm -rf",
    # "mkfs",
    # "dd of=/dev/",
]

denied_command(command) if {
    some needle in denied_commands
    contains(command, needle)
}

decision := {"allow": false, "reason": "this command is on the workspace's destructive list"} if {
    examples
    input.action == "input"
    denied_command(input.command)
}

# -----------------------------------------------------------------------------
# 2. Refuse to start one shell.
#
# The start gate is the hard boundary: a refusal leaves the pane with no process
# at all. 'shell' is the shell's path, and it is the same value as 'command'.
# -----------------------------------------------------------------------------
deny_shells := [
    # "/bin/bash",
]

denied_shell(shell) if {
    some refused in deny_shells
    shell == refused
}

decision := {"allow": false, "reason": "this shell is not used in this workspace"} if {
    examples
    input.action == "start"
    denied_shell(input.shell)
}
