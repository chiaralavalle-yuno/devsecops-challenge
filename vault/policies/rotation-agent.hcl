# rotation-agent policy — elevated but scoped access
# The rotation agent needs read+write to all pagos secrets for rotation.
# It does NOT have sudo/sys capabilities — it cannot manage Vault itself.

# Full CRUD on all Pagos secrets
path "secret/data/pagos/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Read and manage metadata (version history for rollback)
path "secret/metadata/pagos/*" {
  capabilities = ["read", "list", "delete"]
}

# Undelete secret versions (needed for rollback)
path "secret/undelete/pagos/*" {
  capabilities = ["update"]
}

# Destroy specific versions (cleanup after successful rotation)
path "secret/destroy/pagos/*" {
  capabilities = ["update"]
}

# Allow token self-renewal
path "auth/token/renew-self" {
  capabilities = ["update"]
}

# Allow token lookup
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
