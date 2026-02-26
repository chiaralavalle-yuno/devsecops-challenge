# Pagos DevSecOps Challenge — Secrets Management Pipeline

A production-grade secrets management pipeline built for a Latin American fintech (Pagos) that experienced a credential leak incident. This repository implements the full pipeline: prevention, storage, rotation, and audit.

**The incident**: A developer accidentally pushed API keys, webhook secrets, and DB credentials in a config file. This pipeline ensures it can never happen again.

---

## What This Implements

| Layer | Tool | What it does |
|-------|------|-------------|
| **Prevention** | Gitleaks + pre-commit | Blocks secrets before they reach git |
| **Prevention** | TruffleHog (CI) | Defense-in-depth scan on every PR diff |
| **Storage** | AWS Secrets Manager | Primary backend — KMS encryption, IAM RBAC, CloudTrail audit |
| **Storage** | HashiCorp Vault | Local demo backend — same patterns, runs without AWS |
| **Access Control** | Vault AppRole / IAM roles | Least-privilege per service — each service reads only what it needs |
| **Rotation** | Python orchestrator | Zero-downtime rotation with dual-credential window and auto-rollback |
| **Rotation** | GitHub Actions | On-demand (with approval gate) + quarterly automated cron |
| **Audit** | Centralized JSON log | Every secret access and rotation event, SIEM-forwardable |
| **Observability** | Rich dashboard | Secret ages + rotation status at a glance |
| **Anomaly Detection** | audit log parser | Detects new paths, rate spikes, unknown actors |

---

## Quick Start (Local Demo — No AWS Required)

### Prerequisites

- Docker and Docker Compose
- Python 3.12+
- `pre-commit` (`pip install pre-commit` or `brew install pre-commit`)
- `gitleaks` (optional locally — pre-commit downloads it automatically)

### 1. Clone and set up hooks

```bash
git clone <this-repo>
cd devsecops-challenge
./scripts/install-hooks.sh
```

### 2. Start Vault and mock provider

```bash
docker compose up -d vault mock-provider
```

### 3. Initialize Vault (seeds secrets, policies, AppRoles)

```bash
docker compose run --rm vault-init
# This writes AppRole credentials to .env (gitignored)
```

### 4. Start all services

```bash
source .env  # Load AppRole credentials
docker compose up -d payments-api webhooks-service
```

### 5. Verify all services are healthy

```bash
curl http://localhost:5001/health   # payments-api: { "status": "ok" }
curl http://localhost:5002/health   # webhooks-service: { "status": "ok" }
curl http://localhost:5003/health   # mock-provider: { "status": "ok" }
```

---

## Verification Checklist

### 1. Pre-commit blocks a secret

```bash
./scripts/demo-blocked-commit.sh
```

Expected: commit is blocked by gitleaks with an actionable remediation message.

### 2. Least-privilege enforcement

```bash
# Try to read bancosur/api_key using the webhooks-service token (should get 403)
source .env
python3 - <<'EOF'
import hvac, os
client = hvac.Client(url="http://localhost:8200")
client.auth.approle.login(
    role_id=os.environ["VAULT_ROLE_ID_WEBHOOKS_SERVICE"],
    secret_id=os.environ["VAULT_SECRET_ID_WEBHOOKS_SERVICE"]
)
try:
    result = client.secrets.kv.v2.read_secret_version(
        path="pagos/providers/bancosur/api_key", mount_point="secret"
    )
    print("ERROR: Should have been denied!")
except Exception as e:
    print(f"✓ DENIED (as expected): {e}")
EOF
```

### 3. Zero-downtime rotation

```bash
source .env
pip install -r rotation/requirements.txt
python rotation/rotate.py --provider bancosur --backend vault
# Output: rotation_started → key_rotated → reload → health_check → rotation_complete
```

### 4. Auto-rollback on failure

```bash
python rotation/rotate.py --provider walletpro --backend vault --force-fail
# Output: rotation started → forced failure → ROLLBACK → service recovered → exit 1
```

### 5. Audit log

```bash
cat audit/audit.log | python3 -m json.tool --no-ensure-ascii | head -60
# Or view sample events (always committed):
cat audit/sample-audit.log
```

### 6. Dashboard

```bash
source .env
python rotation/dashboard.py --backend vault
```

### 7. Anomaly detection

```bash
# Run against sample log (includes a break-glass event and a rotation failure)
python rotation/anomaly_detect.py --log audit/sample-audit.log --summary
```

### 8. CI scan test (requires GitHub push)

Push a branch with a fake key pattern in a non-allowlisted file:
```
AKIA_FAKE_KEY_EXAMPLE123  # This triggers gitleaks
```
Expected: GitHub Actions fails with a PR comment containing remediation steps.

---

## Repository Structure

```
devsecops-challenge/
├── .gitignore                          # .env, vault/data/, audit/audit.log, etc.
├── .env.example                        # Template — copy to .env, never commit .env
├── .gitleaks.toml                      # Custom rules: bsur_, wpro_, postgres://, AWS keys
├── .pre-commit-config.yaml             # Gitleaks + secrets-reminder + hygiene hooks
├── .trufflehogignore                   # False-positive suppressions for TruffleHog
├── docker-compose.yml                  # Vault + mock-provider + payments-api + webhooks-service
│
├── vault/                              # LOCAL DEMO BACKEND
│   ├── config/vault.hcl                # Vault server config (file storage, dev mode)
│   ├── policies/                       # Least-privilege HCL policies per service
│   │   ├── payments-api.hcl            # read-only: bancosur/* only
│   │   ├── webhooks-service.hcl        # read-only: +/webhook_secret only
│   │   ├── rotation-agent.hcl          # read+write: all pagos/*
│   │   └── admin.hcl                   # BREAK-GLASS ONLY: sudo on *
│   └── init/vault-init.sh              # Seeds Vault + writes AppRole creds to .env
│
├── aws/                                # PRIMARY PRODUCTION BACKEND
│   ├── secrets-definitions.json        # All credential definitions (dummy values)
│   ├── iam-policies/                   # Strict ARN-based IAM policies per service
│   │   ├── payments-api-policy.json
│   │   ├── webhooks-service-policy.json
│   │   └── rotation-agent-policy.json
│   ├── setup-aws.py                    # Seeds Secrets Manager + creates IAM roles
│   └── oidc-setup.md                   # GitHub Actions OIDC → AWS (step-by-step)
│
├── services/
│   ├── mock-provider/                  # Simulates BancoSur + WalletPro APIs
│   │   └── app.py                      # Key rotation, dual-window, HMAC validation
│   ├── payments-api/                   # Fetches BancoSur key, /health validates it
│   │   └── app.py                      # SecretsClient + CredentialCache (dual-key)
│   └── webhooks-service/               # Validates WalletPro HMAC signatures
│       └── app.py                      # Same dual-credential pattern
│
├── rotation/
│   ├── backends/
│   │   ├── __init__.py                 # SecretsBackend ABC
│   │   ├── aws_backend.py              # boto3: GetSecretValue, rollback via stage promotion
│   │   └── vault_backend.py            # hvac: KV v2 read/write/version rollback
│   ├── providers/
│   │   ├── __init__.py                 # PaymentProvider ABC
│   │   ├── bancosur.py                 # mock-provider /rotate-key, /validate, /revoke-previous
│   │   └── walletpro.py                # Same for WalletPro
│   ├── rotate.py                       # Main orchestrator (7-step rotation with rollback)
│   ├── dashboard.py                    # Rich CLI table: secret ages + rotation status
│   └── anomaly_detect.py               # Audit log parser: rate spikes, unknown actors
│
├── audit/
│   ├── audit_schema.json               # JSON Schema for audit events (SIEM-forwardable)
│   └── sample-audit.log                # Committed example with all event types
│
├── scripts/
│   ├── install-hooks.sh                # One-time pre-commit setup
│   ├── demo-blocked-commit.sh          # Shows gitleaks blocking a commit
│   ├── secrets-reminder.sh             # Remediation message shown on hook failure
│   └── break-glass.sh                  # Emergency admin token (1h TTL, logged)
│
├── .github/workflows/
│   ├── secrets-scan.yml                # Gitleaks + TruffleHog on every push + PR
│   └── rotate-secrets.yml              # workflow_dispatch + quarterly cron
│
└── docs/
    ├── threat-model.md                 # STRIDE analysis for all credential types
    ├── pci-dss-mapping.md              # PCI-DSS v4.0 control mapping
    ├── rotation-runbook.md             # Scheduled, on-demand, and emergency rotation
    └── break-glass.md                  # Emergency access procedure + post-incident steps
```

---

## Architecture

### Secrets Backend Abstraction

The `SecretsBackend` ABC makes all rotation logic backend-agnostic:

```python
class SecretsBackend(ABC):
    def get_secret(self, path: str) -> dict: ...
    def put_secret(self, path: str, data: dict) -> None: ...
    def get_previous_version(self, path: str) -> dict | None: ...
    def rollback_secret(self, path: str) -> None: ...
    def write_audit_event(self, event: dict) -> None: ...
```

Switch between backends with `--backend vault` or `--backend aws`. Services select their backend via the `SECRETS_BACKEND` environment variable.

### Zero-Downtime Rotation Pattern

```
                   t=0       t=30s      t=60s
                    │         │          │
                    ▼         ▼          ▼
Old key valid: ████████████████████████████░░░
New key valid:         ████████████████████████████
                         ↑ dual window ↑
```

1. `POST /rotate-key` → mock-provider generates new key, keeps old for 60s
2. New key stored in Vault/AWS
3. `POST /reload-credentials` → service swaps keys in-memory (keeps old as `previous`)
4. In-flight requests using old key complete normally (within 60s)
5. Health check passes → `POST /revoke-previous` ends the window
6. Health check fails → rollback to previous version, service reloads old key

This mirrors real provider behavior (e.g., Stripe's key rotation).

### Least-Privilege Access Control

```
payments-api   → read: bancosur/api_key only
webhooks-service → read: */webhook_secret only (not api_key, not cross-provider)
rotation-agent → read+write: all pagos/* (for rotation)
admin          → all: BREAK-GLASS ONLY, 1h TTL
```

Test the enforcement:
```bash
# webhooks-service AppRole cannot read bancosur/api_key
vault login -method=approle \
  role_id=$VAULT_ROLE_ID_WEBHOOKS_SERVICE \
  secret_id=$VAULT_SECRET_ID_WEBHOOKS_SERVICE
vault kv get secret/pagos/providers/bancosur/api_key  # → 403
```

---

## Key Design Decisions

### 1. AWS Secrets Manager as Primary Backend

Native KMS encryption, CloudTrail audit trail, IAM-native RBAC, and built-in versioning — all PCI-DSS Req 3/8/10 features without extra infrastructure.

CloudTrail captures every `GetSecretValue` call automatically. No application-level audit code required for the AWS backend (the rotation script additionally writes structured JSON for cross-backend SIEM normalization).

### 2. Vault as Local Demo Backend

Enables evaluators without AWS access to run the full demo. The `SecretsBackend` abstraction makes switching transparent — same rotation logic, same audit schema, same service patterns.

**Local demo uses the Vault dev-mode root token for simplicity.** Docker Compose interpolates `.env` at startup before `vault-init` runs, so AppRole credentials generated at runtime can't be injected that way. Services receive `VAULT_TOKEN=root` directly as a compose environment variable. Production uses AppRole with credentials injected via Kubernetes secrets or ECS task role — `_get_from_vault` falls back to AppRole auth when `VAULT_ROLE_ID_*` is set and `VAULT_TOKEN` is absent.

### 3. Production: Kubernetes + External Secrets Operator

In production, Pagos would use [External Secrets Operator](https://external-secrets.io/):
- ESO pulls from AWS Secrets Manager (or Vault) and injects as Kubernetes Secrets
- Services read from projected volumes — no SDK calls at runtime
- Eliminates the startup latency from direct API calls
- Automatic refresh interval replaces the `POST /reload-credentials` pattern

### 4. OIDC Instead of Static Keys in CI

The rotation workflow uses Vault with `VAULT_TOKEN` as a GitHub Secret for the demo. The production AWS pattern (OIDC → IAM role assume) is fully documented in `aws/oidc-setup.md` but not executed in the demo.

Pattern: GitHub Actions assumes scoped IAM role via OIDC — no exportable static keys, 15-minute token TTL, scoped to specific repository + branch.

### 5. Dual-Scanner Strategy

Gitleaks (primary) uses custom pattern rules (`bsur_`, `wpro_`, postgres URL, AWS key). TruffleHog (secondary, CI only) provides entropy-based defense-in-depth.

Trade-off: TruffleHog without `--only-verified` catches more secrets but generates false positives on high-entropy config strings. `.trufflehogignore` mitigates this. Gitleaks with custom rules provides the authoritative verdict.

Allowlists in `.gitleaks.toml` reduce false positives in example files. The trade-off: allowlists require discipline to not use allowed patterns (`bsur_fake_`, `dummy_`) for real secrets.

### 6. Rotation: 100% Simulated

All provider API calls go to `mock-provider`. The README (this file) documents what production calls would look like. The `BancoSurProvider` and `WalletProProvider` classes show the API shape — replace the `MOCK_PROVIDER_URL` with the real endpoint to go to production.

### 7. DB Credentials: Out of Scope (Intentionally)

DB credential rotation requires coordination with the running database. In production, Pagos would use:
- **Vault dynamic secrets**: generates a temporary DB user with 1h TTL — the application role is never given a static password
- **RDS IAM authentication**: no password at all — IAM token grants DB access
- **Least privilege**: each service connects via a service-specific DB role (not admin)

---

## AWS Setup (Production / Real Testing)

```bash
# Install dependencies
pip install boto3

# Configure AWS credentials (SSO preferred)
aws sso login --profile admin-won-dev

# Create secrets + IAM policies + roles
python aws/setup-aws.py --profile admin-won-dev

# Run rotation against AWS
python rotation/rotate.py --provider bancosur --backend aws --profile admin-won-dev

# Set up OIDC for GitHub Actions (see aws/oidc-setup.md)
```

---

## Audit Log Format

Every event is written as a JSON line conforming to `audit/audit_schema.json`:

```json
{
  "timestamp": "2025-11-15T14:30:00.000Z",
  "action": "rotation_complete",
  "actor": "rotation-agent",
  "resource": "pagos/providers/bancosur",
  "backend": "vault",
  "result": "success",
  "metadata": {
    "new_key_prefix": "bsur_c3d4...",
    "path": "pagos/providers/bancosur/api_key"
  }
}
```

**Action types**: `secret_read`, `secret_write`, `rotation_started`, `rotation_complete`, `rotation_failed_rollback`, `break_glass_activated`

**SIEM forwarding**: Ship `audit/audit.log` via Filebeat or Fluentd. For AWS backend, CloudTrail events can also be streamed to the same SIEM via EventBridge → Kinesis.

---

## GitHub Actions Setup

### secrets-scan.yml

Runs automatically on every push and PR. No configuration needed.

To see it in action: push a branch with `AKIA_FAKE_KEY_EXAMPLE123` in a Python file → gitleaks fails → PR comment with remediation steps is posted.

### rotate-secrets.yml

**Required setup** (Settings → Environments → Create `secrets-rotation`):
1. Add required reviewers (security team members)
2. Restrict to `main` branch only
3. Add environment secrets: `VAULT_ADDR`, `VAULT_TOKEN`
4. Add environment secrets: `VAULT_ROLE_ID_ROTATION_AGENT`, `VAULT_SECRET_ID_ROTATION_AGENT`

**Quarterly automated rotation**: The cron `0 2 1 */3 *` runs on the 1st of January, April, July, and October at 02:00 UTC. The environment approval gate applies here too — a reviewer must approve before the rotation runs.

---

## PCI-DSS Compliance Summary

| Requirement | Control | Status |
|-------------|---------|--------|
| Req 3 — Encryption at rest | AWS KMS / Vault Transit | ✓ |
| Req 4 — Encryption in transit | TLS everywhere | ✓ |
| Req 6.4 — Security testing in SDLC | Gitleaks + TruffleHog in CI | ✓ |
| Req 7 — Least-privilege access | AppRole per service, deny by default | ✓ |
| Req 8 — Unique IDs per service | Dedicated AppRole + IAM role per service | ✓ |
| Req 10 — Audit logging | Centralized JSON log + CloudTrail + Vault audit device | ✓ |
| Req 12.3 — Risk-based policy | Quarterly rotation + threat model | ✓ |

Full mapping: [docs/pci-dss-mapping.md](docs/pci-dss-mapping.md)

---

## Documentation

- [Threat Model](docs/threat-model.md) — STRIDE analysis
- [PCI-DSS Mapping](docs/pci-dss-mapping.md) — Req 3, 4, 6, 7, 8, 10, 12
- [Rotation Runbook](docs/rotation-runbook.md) — Scheduled, on-demand, emergency
- [Break-Glass Procedure](docs/break-glass.md) — Emergency access + post-incident steps
- [AWS OIDC Setup](aws/oidc-setup.md) — GitHub Actions → AWS without static keys
