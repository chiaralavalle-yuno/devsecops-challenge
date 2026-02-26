# payments-api policy — least-privilege access
# This service only needs to read BancoSur credentials.
# It cannot read WalletPro secrets, database credentials, or any other path.

# Read BancoSur API key and webhook secret
path "secret/data/pagos/providers/bancosur/*" {
  capabilities = ["read"]
}

# Read metadata (required for version info, not secret values)
path "secret/metadata/pagos/providers/bancosur/*" {
  capabilities = ["read", "list"]
}

# Allow token self-renewal
path "auth/token/renew-self" {
  capabilities = ["update"]
}

# Allow token lookup (for AppRole validation)
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
