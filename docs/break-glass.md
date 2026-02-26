# Break-Glass Emergency Access Procedure

## When to Use

Break-glass access is for **declared security incidents only** — specifically when:
1. Normal rotation tooling is down and a secret must be immediately rotated
2. A key is confirmed compromised and the rotation agent cannot reach Vault
3. A service is locked out due to a misconfigured policy

**Do NOT use break-glass for:**
- Routine administration
- Testing or debugging in non-production
- Any non-incident situation

---

## Step-by-Step Process

### 1. Declare an Incident

Before running break-glass, open an incident ticket in your tracking system (Jira, PagerDuty, etc.) and note the ticket number.

### 2. Run the Break-Glass Script

```bash
./scripts/break-glass.sh
```

The script will:
- Prompt for your name, incident ticket, and reason
- Log the activation to `audit/audit.log` **before** creating the token
- Create a Vault token with `admin` policy, TTL = 1 hour
- Send a Slack alert (if `SLACK_WEBHOOK_URL` is configured)
- Print the token to stdout

### 3. Use the Token

```bash
export VAULT_TOKEN=<token-from-script>
export VAULT_ADDR=http://localhost:8200  # or production URL

# Verify your access
vault token lookup

# Perform emergency operation (example: rotate a key manually)
vault kv put secret/pagos/providers/bancosur/api_key \
  api_key="bsur_$(openssl rand -hex 16)"
```

### 4. Revoke the Token When Done

**This is mandatory.** Do not let the token expire naturally unless you cannot revoke it.

```bash
vault token revoke "$VAULT_TOKEN"
```

Verify revocation:
```bash
vault token lookup  # Should return "permission denied"
```

---

## Post-Incident Requirements

These steps are required within 24 hours of incident resolution:

### A. Rotate All Accessed Secrets

Check `audit/audit.log` for `secret_read` events during the break-glass window:

```bash
# Find all secrets accessed between break-glass activation and token revocation
grep '"actor":"<your-operator-id>"' audit/audit.log | \
  jq -r '.resource' | sort -u
```

Rotate each identified secret:
```bash
python rotation/rotate.py --provider bancosur --backend vault
python rotation/rotate.py --provider walletpro --backend vault
```

### B. Write an Incident Report

The report must include:
1. Timeline: detection → escalation → break-glass activation → resolution
2. Secrets accessed (from audit log)
3. Root cause analysis
4. Preventive measures to avoid recurrence
5. Reference to audit log entries (timestamp range)

File the report under your incident management system.

### C. Verify Audit Trail Integrity

```bash
# Count break-glass events in the log
grep '"action":"break_glass_activated"' audit/audit.log | wc -l

# Verify the audit event was written before the token was used
grep '"action":"break_glass_'  audit/audit.log | jq -r '.timestamp'
```

---

## Security Properties

| Property | Implementation |
|----------|---------------|
| Authorization | Token requires `admin` policy (not default) |
| Time limit | 1h TTL — token automatically expires |
| Audit trail | Event written to `audit/audit.log` BEFORE token creation |
| Notification | Slack alert to security channel (if configured) |
| Traceability | Token display name includes incident ticket number |
| Revocability | Token can be revoked immediately via `vault token revoke` |

---

## Vault Token Details

The token created by `break-glass.sh` has:
- **Policy**: `admin` (full Vault access — see `vault/policies/admin.hcl`)
- **TTL**: 1 hour (non-renewable by default)
- **Display name**: `break-glass-<incident-ticket>`
- **Metadata**: operator name + incident ticket

In AWS Secrets Manager (production): use AWS STS `assume-role` with `pagos-rotation-agent` role and a short session duration instead of Vault break-glass.

---

## Production Improvements

This demo uses Vault's dev mode. In production:
1. Use Vault Enterprise namespaces for additional isolation
2. Configure control groups (MFA required for break-glass token creation)
3. Integrate with PagerDuty for automatic incident correlation
4. Ship `audit/audit.log` to your SIEM in real-time via Filebeat/Fluentd
