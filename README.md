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

## Engineering Notes

### Design Decisions

**Root token for local demo instead of AppRole at runtime**

Docker Compose interpolates `.env` at startup — before `vault-init` runs. This means AppRole credentials generated dynamically can never be injected via `.env` into service containers in the same `docker compose up`. Rather than add a two-phase startup (compose up, wait, export, compose restart), services receive `VAULT_TOKEN=root` directly in the compose environment. The AppRole path is still fully implemented: `_get_from_vault` checks for `VAULT_TOKEN` first, falls back to `VAULT_ROLE_ID_*` / `VAULT_SECRET_ID_*` when present. Production deploys use AppRole or IAM-based auth injected via Kubernetes secrets or ECS task roles — not via `.env`.

**curl instead of the vault CLI in break-glass.sh**

The Vault CLI is not available in the typical operator environment (and bundling it creates a dependency). All Vault operations in `break-glass.sh` use `curl` against the HTTP API — the same API the CLI wraps. This makes the script portable: it runs wherever `curl` is available, with no PATH or binary version concerns.

**Mock-provider as the source of truth for key state**

Rather than generating random keys in `vault-init.sh` and also in `mock-provider`, `vault-init` fetches the current keys from mock-provider via HTTP at initialization time. This ensures Vault and mock-provider always agree on what the valid credentials are. The alternative (having Vault be the source of truth and push values into mock-provider) would require mock-provider to expose a write API, which would undermine the simulation of an external third-party provider.

**File-based audit log in addition to backend-native audit**

For the AWS backend, CloudTrail captures every `GetSecretValue` call automatically. For the Vault backend, the audit device writes every API call. The rotation script additionally writes to `audit/audit.log` in a normalized JSON format. This extra write serves two purposes: it provides a unified, backend-agnostic event stream (useful for cross-backend SIEM normalization), and it gives evaluators a concrete file to inspect without needing to access CloudTrail or Vault audit logs.

---

### Challenges & How They Were Solved

**Vault dev mode discards all state on restart**

Vault's dev mode (`-dev`) starts with an in-memory store. Every `docker compose restart` wipes all secrets and policies. The `vault-init` service re-seeds everything on each startup, which means the startup sequence must be strictly ordered: mock-provider must be healthy before vault-init runs (so it can fetch current keys), and services must wait for vault-init to complete before they try to fetch credentials. The `depends_on` with `condition: service_completed_successfully` and `condition: service_healthy` enforce this ordering without shell sleeps.

**Vault dev mode ignores the config file**

The `vault.hcl` config file (TLS, storage backend, telemetry) is correct for a production-style startup but is ignored in dev mode. An earlier version of `docker-compose.yml` mounted `./vault/config:/vault/config:ro`, which caused a read-only filesystem error because the dev-mode container also tries to write to `/vault/config`. Removing the mount resolved the conflict. The config file is kept in the repository as the reference for production configuration.

**Gitleaks `detect` vs `protect --staged`**

The pre-commit hook initially invoked gitleaks without subcommand, which defaults to `detect` and scans the full git history on every commit. This is slow and produces false positives for secrets that were already cleaned up. The correct subcommand for pre-commit is `protect --staged`, which scans only the currently staged diff. Changing the hook args from `["--config=.gitleaks.toml"]` to `["protect", "--staged", "--config=.gitleaks.toml"]` fixed this.

**demo-blocked-commit.sh triggering its own gitleaks scan**

`demo-blocked-commit.sh` creates a temporary file containing a fake `bsur_` key to demonstrate that the pre-commit hook blocks it. When gitleaks was pointed at `protect --staged`, it correctly staged and caught the key — but it also caught the key inside `demo-blocked-commit.sh` itself when that file was first committed. The fix was to add `scripts/demo-blocked-commit.sh` to the global allowlist paths in `.gitleaks.toml`, so gitleaks skips the script file itself while still catching any real secrets staged in other files.

**Webhook secret vs API key confusion in mock-provider**

Initially, `mock-provider` stored only an API key per provider. The webhooks-service validates HMAC-SHA256 signatures using a separate shared webhook secret — a different credential from the API key. The HMAC validation endpoint was accidentally using `state["current_key"]` (the API key) instead of a dedicated `webhook_secret`. This caused every webhook signature validation to fail. The fix added a separate `webhook_secret` field to each provider's state, exposed `/current-webhook-secret` endpoints so `vault-init` can fetch and sync them, and corrected the HMAC function to use the right field.

---

### AI-Assisted False Positive Analysis

`scripts/ai_false_positive.py` adds a third decision layer between Gitleaks blocking a commit and a developer manually reviewing the finding.

**Three-tier decision logic:**

1. **Immediate PASS** (deterministic): the finding is in a known-safe path (`tests/`, `fixtures/`, `docs/`) *and* the value starts with a known-safe prefix (`fake_`, `test_`, `example_`, `mock_`, `dummy_`). No API call needed.

2. **Immediate FAIL** (deterministic): the finding is in a production code path (`src/`, `services/`, `rotation/`). No leniency — these paths should never contain credential values.

3. **Ambiguous** (AI-assisted): anything that doesn't match rule 1 or 2 is sent to `claude-sonnet-4-20250514` with the file path, matched pattern, and surrounding context. The model returns a structured verdict with confidence and reasoning.

**Why not call the AI for everything?** Latency. A pre-commit hook that adds 2–3 seconds to common cases (test fixtures with `fake_` prefixes) will be disabled by developers. The deterministic fast paths cover ~90% of real-world findings, keeping the AI call for genuinely ambiguous cases.

**Caching**: verdicts are cached in `/tmp/pagos_fp_cache.json` keyed by `(path, pattern, value_prefix)`. The same finding in the same file doesn't trigger a second API call within a session.

**Audit trail**: every verdict (including AI reasoning) is appended to `audit/audit.log` with `action: "false_positive_analysis"`. This gives security reviewers visibility into what the AI decided and why, enabling periodic calibration of the deterministic rules.

**Exit codes**: 0 = false positive (commit can proceed after developer confirms), 1 = real secret detected (commit must be blocked). The script is designed to be called by a wrapper hook, not to replace gitleaks — gitleaks still makes the authoritative blocking decision.

---

### What Would Be Different in Production

**OIDC instead of `VAULT_TOKEN` in CI**

The demo stores `VAULT_TOKEN` as a GitHub Actions secret. In production, GitHub Actions would use OIDC to assume a scoped IAM role (no exportable static key, 15-minute token TTL, scoped to specific repository + branch). The setup is documented in `aws/oidc-setup.md` and the workflow is OIDC-ready (`permissions: id-token: write`) — activating it requires creating the OIDC provider in AWS and adding the role ARN as a GitHub variable.

**Raft storage instead of dev-mode file storage**

Vault dev mode and single-node file storage are both single points of failure. Production uses Raft integrated storage (3- or 5-node cluster) with auto-unseal via AWS KMS or Azure Key Vault. This eliminates the manual unseal requirement and provides HA with automatic leader election.

**Kubernetes + External Secrets Operator instead of direct SDK calls**

Services calling `hvac` or `boto3` at startup create a tight coupling between application code and the secrets backend. In production, [External Secrets Operator](https://external-secrets.io/) runs in the cluster, pulls secrets from AWS Secrets Manager (or Vault), and injects them as Kubernetes `Secret` objects. Services read from projected volumes — no SDK, no startup latency, automatic refresh on rotation.

**Real Slack alerting instead of log-only**

`break-glass.sh` and the rotation workflow format Slack webhook payloads and log them to `audit/audit.log`. Setting `SLACK_WEBHOOK_URL` as an environment variable enables real posting. In production, this would be a dedicated `#pagos-security-alerts` channel with on-call PagerDuty integration — break-glass activation and rotation failures would page the on-call engineer.

**TruffleHog with `--only-verified` for lower false-positive rate**

The CI workflow runs TruffleHog without `--only-verified` to catch unverified high-entropy strings. In production with established baseline `.trufflehogignore` rules, enabling `--only-verified` would reduce noise by only alerting on credentials that TruffleHog can actively verify against provider APIs (Stripe, GitHub, AWS, etc.). The trade-off: you miss secrets for providers TruffleHog doesn't have verifiers for. Running both modes (verified + unverified) in separate jobs with different failure thresholds is the production pattern.

**Vault dynamic secrets for database credentials**

The demo stores static DB connection strings. In production, the application would request a dynamic DB credential from Vault on startup — Vault creates a temporary PostgreSQL/MySQL role with a 1-hour TTL and returns the credentials. The role is automatically revoked when the lease expires. The application never holds a static password; the credential lifecycle is managed entirely by Vault.

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
