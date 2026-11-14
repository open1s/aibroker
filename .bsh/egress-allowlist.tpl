# =============================================================================
# Egress allowlist - TEMPLATE (not enforced)
#
# bsh reads .bsh/egress-allowlist, NOT this file. Copy this file to
# .bsh/egress-allowlist (same folder, drop the .tpl suffix) to make it this
# workspace's allowlist. The rules below are the same copy the Policy pane's
# "Create starter allowlist" writes, so the two cannot describe different
# shapes.
#
# The file is TRI-STATE: no file at all leaves the network UNRESTRICTED; a file
# that exists and declares no rule DENIES ALL egress; rules narrow the reach to
# what they name. Every rule example below is commented out, so copying this
# template AS IS is the deliberate deny-all floor - uncomment a rule to open it.
# =============================================================================

# Egress allowlist for this workspace.
#
# CREATING THIS FILE OPTS INTO CONTROL.
#
# With NO file at all the workspace is UNRESTRICTED: the network works out of
# the box. A file that EXISTS and declares no rule - only comments and blank
# lines, like this starter - DENIES ALL EGRESS. That is deliberate: the file is
# the workspace's network floor, and an empty one is a lockdown, not an
# absence. Delete the file to restore the unrestricted default, or uncomment a
# rule to allow a destination.
#
# This file can only NARROW what the baseline and the preset allow; a preset
# may narrow it further and can never add a destination this file does not
# name.
#
# One rule per line; blank lines and '#' comments are ignored. A line is one of
# three shapes, decided by what it can be:
#
#   port     443              a bare integer: a destination PORT. No port lines
#                             means any port; one or more means only those.
#   address  203.0.113.7      an address or a CIDR range: the STRONG door,
#            10.0.0.0/8       decided on the resolved IP, so a DNS rebind
#                             cannot ride it.
#   hostname api.example.com  anything else: a HOSTNAME, the WEAKER door -
#            *.crates.io      the name is what the policy saw, so a rebind
#                             survives it. A leading '*.' matches any subdomain.
#
# Every line below is a COMMENTED example, so this file declares no rule and
# egress is denied until you deliberately uncomment one.
#
# WORKED EXAMPLE - allow one IPv4 address on the HTTPS port. Uncomment both
# lines to make the HTTPS URL of 203.0.113.7 reachable and nothing else:
# 203.0.113.7
# 443
#
# Example: allow a service by name (the weaker door).
# api.example.com
# *.crates.io
#
# DENY ALL: what this file already does. Leave no uncommented rule. There is no
# deny-all keyword - a present file with no rule IS the deny.
#
# ALLOW ALL: there is no wildcard-hostname spelling for any host: a hostname
# rule matches an exact name or a leading '*.' suffix, so '*' matches no host.
# The nearest real equivalent is an address rule covering every address; the
# parser accepts it and it is the honest allow-all:
# 0.0.0.0/0
# ::/0
