# admin policy — BREAK-GLASS ONLY
# This policy grants full Vault access. It must only be assigned to
# time-limited tokens created during declared incidents.
#
# Usage: scripts/break-glass.sh
# Token TTL: 1 hour maximum
# All access is logged to Vault audit device
#
# Post-incident: revoke token immediately, rotate all accessed secrets,
# write incident report referencing audit log entries.
# See: docs/break-glass.md

path "*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}
