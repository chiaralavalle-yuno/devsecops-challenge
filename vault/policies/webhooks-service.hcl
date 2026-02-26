# webhooks-service policy — least-privilege access
# This service only needs to read webhook secrets for payment providers.
# It cannot read API keys, database credentials, or cross-provider secrets.

# Read webhook secret for any configured payment provider
# The + wildcard matches exactly ONE segment (e.g., bancosur, walletpro)
path "secret/data/pagos/providers/+/webhook_secret" {
  capabilities = ["read"]
}

# Read metadata for version info
path "secret/metadata/pagos/providers/+/webhook_secret" {
  capabilities = ["read", "list"]
}

# Allow token self-renewal
path "auth/token/renew-self" {
  capabilities = ["update"]
}

# Allow token lookup
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
