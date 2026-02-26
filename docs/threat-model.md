# Pagos Threat Model

## Context

Pagos is a Latin American fintech processing payments via BancoSur and WalletPro APIs.
The incident that prompted this project: a developer accidentally pushed a config file
containing live API keys, webhook secrets, and database credentials.

**STRIDE threat model for the secrets management pipeline.**

---

## Assets

| Asset | Classification | Owner |
|-------|---------------|-------|
| BancoSur API key | PCI-DSS CHD-adjacent | payments-api |
| WalletPro API key | PCI-DSS CHD-adjacent | payments-api |
| WalletPro webhook secret | Sensitive | webhooks-service |
| DB credentials | Highly sensitive | DBA only |
| Vault root token | Critical | Platform team |
| IAM rotation role | Critical | Platform team |
| Audit log | Sensitive (integrity) | Security team |

---

## Threats

### S — Spoofing

| Threat | Mitigation |
|--------|-----------|
| Attacker claims to be `payments-api` and reads BancoSur key | AppRole bind_secret_id prevents token creation without valid secret_id; each service has unique role |
| Forged webhook from attacker claims to be WalletPro | HMAC-SHA256 validation — requires knowledge of webhook_secret stored in Vault |
| Attacker reuses expired AppRole secret_id | AppRoles configured with `secret_id_ttl=0` (non-expiring) but bound; production should use short-lived secret_ids with push protection |

### T — Tampering

| Threat | Mitigation |
|--------|-----------|
| Attacker modifies secrets in transit | TLS in all paths (Vault, AWS Secrets Manager, HTTPS APIs); KMS encryption at rest |
| Attacker rotates a key to a known value | Vault policy restricts `create/update` to `rotation-agent` only; services are read-only |
| Audit log tampered to cover tracks | Vault audit device writes independently of application; CloudTrail logs are immutable; SIEM forwarding creates a secondary copy |
| Attacker replaces rotation script in CI | GitHub branch protection + required reviewers on `main`; OIDC means no long-lived key to steal |

### R — Repudiation

| Threat | Mitigation |
|--------|-----------|
| Operator denies performing break-glass access | `break_glass_activated` event written BEFORE token creation; Vault audit device independently logs the token creation |
| Service denies reading a secret | Vault audit device captures every `GetSecretValue`; CloudTrail captures every AWS Secrets Manager `GetSecretValue` |

### I — Information Disclosure

| Threat | Mitigation |
|--------|-----------|
| Developer commits secret to git | Gitleaks pre-commit hook + CI scan; `.gitignore` patterns for `.env`; custom rules for `bsur_` and `wpro_` prefixes |
| Secret leaked in CI logs | Services fetch secrets at runtime from Vault/AWS — no secrets in workflow files or logs |
| `webhooks-service` reads `bancosur/api_key` | Vault policy `webhooks-service.hcl` allows only `pagos/providers/+/webhook_secret` — 403 on cross-provider read |
| Secret leaked in Docker image layers | Services receive credentials via environment (from Vault AppRole, not baked in); images contain no secrets |

### D — Denial of Service

| Threat | Mitigation |
|--------|-----------|
| Vault unavailable during service startup | Retry loop with exponential backoff (5 attempts); services degrade gracefully (503) rather than crash |
| Rotation fails mid-way, leaves invalid key active | Rollback on health check failure restores previous version; dual-credential window means in-flight requests complete |
| Attacker exhausts Vault rate limits | Credential caching in service memory reduces Vault calls; rate limits configurable per AppRole |

### E — Elevation of Privilege

| Threat | Mitigation |
|--------|-----------|
| Compromised `payments-api` tries to write secrets | Vault policy: `payments-api` has `read` only — `create/update` returns 403 |
| `rotation-agent` tries to access Vault sys/ | Policy does not grant `sys/*` capabilities; agent cannot unseal, create policies, or manage auth methods |
| Break-glass token used beyond incident scope | 1h TTL hard limit; post-incident token revocation required; audit log shows all access |
| Attacker gains persistent access via Vault token | Tokens tied to AppRoles with TTL; no static tokens committed to git; VAULT_TOKEN is an ephemeral GitHub Secret |

---

## Trust Boundaries

```
Internet
  │
  ├── WalletPro → [HMAC validation] → webhooks-service → [AppRole] → Vault
  │
  └── BancoSur ← [API key] ← payments-api → [AppRole] → Vault
                                                │
                                         rotation-agent
                                                │
                                    [admin policy, 1h TTL]
                                         break-glass
```

---

## Residual Risks

| Risk | Acceptance Rationale |
|------|---------------------|
| Mock-provider state is in-memory | Demo only — production uses real provider APIs with their own state management |
| DB credentials not rotated | Vault dynamic secrets / RDS IAM auth is the production solution; out of scope for this implementation |
| Vault dev mode in Docker Compose | Dev mode with `root` token — acceptable for local demo; production uses production Vault cluster with Raft HA and auto-unseal |
| `payments-api` and `webhooks-service` share the same Vault instance | Isolation at the policy level; network-level isolation (separate Vault namespaces) is a production improvement |
