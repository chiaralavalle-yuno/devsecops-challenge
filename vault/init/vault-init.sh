#!/bin/sh
# vault-init.sh — Seeds Vault with dummy secrets, policies, AppRoles, and audit device
# Called automatically by docker-compose via the vault-init service.
# Safe to re-run (checks if already initialized).
set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:-http://vault:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-root}"
ENV_FILE="${ENV_FILE:-/workspace/.env}"

export VAULT_ADDR VAULT_TOKEN

echo "==> Waiting for Vault to be ready..."
until vault status &>/dev/null; do
  sleep 1
  echo "    Vault not ready yet, retrying..."
done
echo "    Vault is ready."

# ============================================================
# 1. Enable KV v2 secrets engine
# ============================================================
echo ""
echo "==> Enabling KV v2 secrets engine at secret/..."
if vault secrets list | grep -q "^secret/"; then
  echo "    KV v2 already enabled."
else
  vault secrets enable -version=2 -path=secret kv
  echo "    KV v2 enabled."
fi

# ============================================================
# 2. Enable audit logging
# ============================================================
echo ""
echo "==> Enabling audit file device..."
if vault audit list 2>/dev/null | grep -q "file/"; then
  echo "    Audit device already enabled."
else
  vault audit enable file file_path=/vault/logs/audit.log
  echo "    Audit device enabled → /vault/logs/audit.log"
fi

# ============================================================
# 3. Write secrets — api_keys fetched live from mock-provider
# ============================================================
echo ""
echo "==> Fetching initial keys from mock-provider..."

MOCK_PROVIDER_URL="${MOCK_PROVIDER_URL:-http://mock-provider:5003}"

BANCOSUR_API_KEY=$(wget -qO- "${MOCK_PROVIDER_URL}/bancosur/current-key" \
  | sed 's/.*"api_key":"\([^"]*\)".*/\1/')
echo "    BancoSur api_key: ${BANCOSUR_API_KEY}"

BANCOSUR_WEBHOOK_SECRET=$(wget -qO- "${MOCK_PROVIDER_URL}/bancosur/current-webhook-secret" \
  | sed 's/.*"webhook_secret":"\([^"]*\)".*/\1/')
echo "    BancoSur webhook_secret: ${BANCOSUR_WEBHOOK_SECRET}"

WALLETPRO_API_KEY=$(wget -qO- "${MOCK_PROVIDER_URL}/walletpro/current-key" \
  | sed 's/.*"api_key":"\([^"]*\)".*/\1/')
echo "    WalletPro api_key: ${WALLETPRO_API_KEY}"

WALLETPRO_WEBHOOK_SECRET=$(wget -qO- "${MOCK_PROVIDER_URL}/walletpro/current-webhook-secret" \
  | sed 's/.*"webhook_secret":"\([^"]*\)".*/\1/')
echo "    WalletPro webhook_secret: ${WALLETPRO_WEBHOOK_SECRET}"

echo ""
echo "==> Writing secrets to Vault..."

# BancoSur — use real values from mock-provider
vault kv put secret/pagos/providers/bancosur/api_key \
  api_key="${BANCOSUR_API_KEY}"

vault kv put secret/pagos/providers/bancosur/webhook_secret \
  webhook_secret="${BANCOSUR_WEBHOOK_SECRET}"

# WalletPro — use real values from mock-provider
vault kv put secret/pagos/providers/walletpro/api_key \
  api_key="${WALLETPRO_API_KEY}"

vault kv put secret/pagos/providers/walletpro/webhook_secret \
  webhook_secret="${WALLETPRO_WEBHOOK_SECRET}"

# Database (stored but not rotated — see README)
vault kv put secret/pagos/database/transactions_url \
  url="postgres://pagos_app:dummy_password_replace_me@db:5432/transactions"

vault kv put secret/pagos/database/admin_password \
  password="dummy_admin_password_replace_me_$(openssl rand -hex 8)"

# IAM (for rotation agent)
vault kv put secret/pagos/aws/iam_access_key \
  access_key_id="AKIAIOSFODNN7EXAMPLE" \
  secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

echo "    All secrets written."

# ============================================================
# 4. Write policies
# ============================================================
echo ""
echo "==> Writing Vault policies..."

vault policy write payments-api /vault/policies/payments-api.hcl
vault policy write webhooks-service /vault/policies/webhooks-service.hcl
vault policy write rotation-agent /vault/policies/rotation-agent.hcl
vault policy write admin /vault/policies/admin.hcl

echo "    Policies written."

# ============================================================
# 5. Enable AppRole auth
# ============================================================
echo ""
echo "==> Enabling AppRole authentication..."
if vault auth list | grep -q "approle/"; then
  echo "    AppRole already enabled."
else
  vault auth enable approle
  echo "    AppRole enabled."
fi

# ============================================================
# 6. Create AppRoles and bind policies
# ============================================================
echo ""
echo "==> Creating AppRoles..."

create_approle() {
  local name="$1"
  local policy="$2"
  local token_ttl="${3:-1h}"

  vault write "auth/approle/role/${name}" \
    token_policies="${policy}" \
    token_ttl="${token_ttl}" \
    token_max_ttl="4h" \
    secret_id_ttl="0" \
    bind_secret_id=true
  echo "    Created AppRole: ${name} (policy: ${policy})"
}

create_approle "payments-api"     "payments-api"
create_approle "webhooks-service" "webhooks-service"
create_approle "rotation-agent"   "rotation-agent"

# ============================================================
# 7. Fetch AppRole credentials and write to .env
# ============================================================
echo ""
echo "==> Fetching AppRole credentials..."

get_role_id() {
  vault read -field=role_id "auth/approle/role/${1}/role-id"
}

get_secret_id() {
  vault write -force -field=secret_id "auth/approle/role/${1}/secret-id"
}

ROLE_ID_PAYMENTS=$(get_role_id "payments-api")
SECRET_ID_PAYMENTS=$(get_secret_id "payments-api")

ROLE_ID_WEBHOOKS=$(get_role_id "webhooks-service")
SECRET_ID_WEBHOOKS=$(get_secret_id "webhooks-service")

ROLE_ID_ROTATION=$(get_role_id "rotation-agent")
SECRET_ID_ROTATION=$(get_secret_id "rotation-agent")

echo ""
echo "==> Writing AppRole credentials to ${ENV_FILE}..."

# Append to .env (create if not exists, skip if already present)
write_env_var() {
  local key="$1"
  local value="$2"
  if [ -f "$ENV_FILE" ] && grep -q "^${key}=" "$ENV_FILE"; then
    # Update existing line
    sed -i "s|^${key}=.*|${key}=${value}|" "$ENV_FILE"
  else
    echo "${key}=${value}" >> "$ENV_FILE"
  fi
}

write_env_var "VAULT_ADDR" "${VAULT_ADDR}"
write_env_var "VAULT_ROLE_ID_PAYMENTS_API" "${ROLE_ID_PAYMENTS}"
write_env_var "VAULT_SECRET_ID_PAYMENTS_API" "${SECRET_ID_PAYMENTS}"
write_env_var "VAULT_ROLE_ID_WEBHOOKS_SERVICE" "${ROLE_ID_WEBHOOKS}"
write_env_var "VAULT_SECRET_ID_WEBHOOKS_SERVICE" "${SECRET_ID_WEBHOOKS}"
write_env_var "VAULT_ROLE_ID_ROTATION_AGENT" "${ROLE_ID_ROTATION}"
write_env_var "VAULT_SECRET_ID_ROTATION_AGENT" "${SECRET_ID_ROTATION}"

echo ""
echo "==> Vault initialization complete!"
echo ""
echo "    Secrets stored at:"
echo "      secret/pagos/providers/bancosur/api_key"
echo "      secret/pagos/providers/bancosur/webhook_secret"
echo "      secret/pagos/providers/walletpro/api_key"
echo "      secret/pagos/providers/walletpro/webhook_secret"
echo "      secret/pagos/database/transactions_url"
echo "      secret/pagos/database/admin_password"
echo "      secret/pagos/aws/iam_access_key"
echo ""
echo "    AppRole credentials written to: ${ENV_FILE}"
echo "    Audit device: /vault/logs/audit.log"
echo ""
echo "    Test least-privilege (should get 403):"
echo "      vault login -method=approle role_id=\$VAULT_ROLE_ID_WEBHOOKS_SERVICE secret_id=\$VAULT_SECRET_ID_WEBHOOKS_SERVICE"
echo "      vault kv get secret/pagos/providers/bancosur/api_key  # should fail"
