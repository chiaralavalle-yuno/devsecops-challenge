# Pagos Credential Rotation Runbook

## Overview

This runbook covers three rotation scenarios:
1. **Scheduled rotation** — quarterly, automated via GitHub Actions cron
2. **On-demand rotation** — triggered via GitHub Actions `workflow_dispatch` with approval
3. **Emergency rotation** — via break-glass when normal tooling is unavailable

---

## Quick Reference

```bash
# Rotate BancoSur (Vault backend, local demo)
python rotation/rotate.py --provider bancosur --backend vault

# Rotate WalletPro (AWS backend, production)
python rotation/rotate.py --provider walletpro --backend aws

# Rotate all providers
python rotation/rotate.py --provider all --backend vault

# Test rollback (force failure)
python rotation/rotate.py --provider bancosur --backend vault --force-fail

# Check rotation status
python rotation/dashboard.py --backend vault
```

---

## Scenario 1: Scheduled Rotation (GitHub Actions)

The `rotate-secrets.yml` workflow runs automatically on the quarterly cron schedule.

**To trigger manually via GitHub UI:**
1. Go to: `Actions → Rotate Secrets → Run workflow`
2. Select provider and backend
3. A required reviewer from the `secrets-rotation` environment must approve
4. The workflow runs, writes events to `audit/audit.log`, and uploads it as an artifact

**What happens automatically:**
1. Pre-flight: validates current key is still accepted by provider
2. Generates new key via `POST /bancosur/rotate-key` (mock-provider)
3. Stores new key in Vault/AWS (old key becomes `AWSPREVIOUS`)
4. Sends `POST /reload-credentials` to each affected service
5. 60-second dual-credential window: both old and new keys valid
6. Health check loop: polls service `/health` for 30 seconds
7. On success: calls `POST /bancosur/revoke-previous` to end dual window
8. On failure: restores previous version + reloads services + audit event

---

## Scenario 2: On-Demand Emergency Rotation (Secret Compromised)

**If a secret was exposed (e.g., found in a git commit, logs, or support ticket):**

### Step 1: Contain

```bash
# Rotate the compromised key IMMEDIATELY
python rotation/rotate.py --provider bancosur --backend vault
```

This starts the 60-second dual-credential window. Existing connections using the old key will complete normally; new requests use the new key.

### Step 2: Verify

```bash
# Check service health after rotation
curl http://localhost:5001/health  # payments-api
curl http://localhost:5002/health  # webhooks-service

# Check audit log
tail -20 audit/audit.log | python3 -m json.tool
```

### Step 3: Revoke Old Key Immediately (Skip Dual Window)

If the key is confirmed compromised, don't wait for the 60-second window:

```bash
# Revoke old key at provider immediately
curl -X POST http://localhost:5003/bancosur/revoke-previous
```

### Step 4: Purge from Git History

If the key was committed to git:

```bash
# Remove from git history (requires git-filter-repo)
pip install git-filter-repo
git filter-repo --path-glob '*.env' --invert-paths --force

# Force push (coordinate with team first)
git push --force-with-lease origin main
```

**Also:**
- Rotate GitHub Actions secrets if they were compromised
- Check if the key appears in any CI/CD logs
- Notify the payment provider's security team

---

## Scenario 3: Break-Glass Emergency Access

Use when the rotation agent cannot run (Vault sealed, network partition, etc.).

```bash
./scripts/break-glass.sh
```

See `docs/break-glass.md` for the full procedure.

---

## Rollback Procedure

If a rotation causes service failures and the automated rollback doesn't recover:

### Manual Rollback (Vault)

```bash
# List versions
export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=root
vault kv metadata get secret/pagos/providers/bancosur/api_key

# Get previous version (replace N with current version - 1)
vault kv get -version=N secret/pagos/providers/bancosur/api_key

# Write previous version as new current
PREV_KEY=$(vault kv get -version=N -field=api_key secret/pagos/providers/bancosur/api_key)
vault kv put secret/pagos/providers/bancosur/api_key api_key="$PREV_KEY"

# Reload services
curl -X POST http://localhost:5001/reload-credentials
```

### Manual Rollback (AWS)

```bash
# List versions
aws secretsmanager list-secret-version-ids \
  --secret-id pagos/providers/bancosur/api_key

# Promote AWSPREVIOUS to AWSCURRENT
aws secretsmanager update-secret-version-stage \
  --secret-id pagos/providers/bancosur/api_key \
  --version-stage AWSCURRENT \
  --move-to-version-id <PREVIOUS_VERSION_ID> \
  --remove-from-version-id <CURRENT_VERSION_ID>
```

---

## Credential Inventory

| Secret | Path | Rotation Owner | Last Rotated |
|--------|------|---------------|-------------|
| BancoSur API Key | `pagos/providers/bancosur/api_key` | rotation-agent | see dashboard |
| BancoSur Webhook Secret | `pagos/providers/bancosur/webhook_secret` | rotation-agent | see dashboard |
| WalletPro API Key | `pagos/providers/walletpro/api_key` | rotation-agent | see dashboard |
| WalletPro Webhook Secret | `pagos/providers/walletpro/webhook_secret` | rotation-agent | see dashboard |
| DB Transactions URL | `pagos/database/transactions_url` | DBA team | manual |
| DB Admin Password | `pagos/database/admin_password` | DBA team | manual |
| IAM Access Key | `pagos/aws/iam_access_key` | rotation-agent | see dashboard |

**DB credentials note:** Database credential rotation is out of scope for this implementation. In production, Pagos would use:
- **Vault dynamic secrets**: generates a temporary DB user with 1h TTL — developers never see a password
- **RDS IAM authentication**: no password at all — IAM token grants DB access
- **Least privilege**: application role connects via service-specific DB user (not admin)

---

## If a Key Leak Is Already in Production History

1. Rotate the key immediately (above)
2. Assume the key is compromised — notify the payment provider
3. Check provider audit logs for unauthorized use
4. Run `git filter-repo` to purge history
5. Force-push and invalidate GitHub's cache: `git push --force-with-lease`
6. Notify your security team and open an incident ticket
7. Review pre-commit hook installation: `./scripts/install-hooks.sh`

---

## Post-Rotation Verification

```bash
# 1. Health checks
curl http://localhost:5001/health   # { "status": "ok" }
curl http://localhost:5002/health   # { "status": "ok" }

# 2. Test payment processing
curl -X POST http://localhost:5001/payment -H 'Content-Type: application/json' \
  -d '{"amount": 100.00}'

# 3. Test webhook validation
CURRENT_SECRET=$(docker exec pagos-vault vault kv get -field=webhook_secret \
  secret/pagos/providers/walletpro/webhook_secret)
PAYLOAD='{"type":"payment.completed","amount":100}'
SIG=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$CURRENT_SECRET" | awk '{print $2}')
curl -X POST http://localhost:5002/webhook \
  -H "X-WalletPro-Signature: sha256=$SIG" \
  -H 'Content-Type: application/json' \
  -d "$PAYLOAD"

# 4. Verify audit log
tail -5 audit/audit.log | jq .
```
