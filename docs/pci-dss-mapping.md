# PCI-DSS v4.0 Compliance Mapping

This document maps Pagos DevSecOps controls to PCI-DSS v4.0 requirements.

---

## Requirement 3 — Protect Stored Account Data

| Sub-requirement | Control | Implementation |
|----------------|---------|----------------|
| 3.5.1 — Encryption of stored data | KMS encryption at rest | AWS Secrets Manager uses AWS KMS (AES-256) for all stored secrets. Vault uses the Transit secrets engine or file-backed storage with OS-level encryption |
| 3.5.1.3 — Cryptographic key management | Key rotation | AWS KMS automatically rotates CMKs annually; Vault Transit engine supports key rotation |
| 3.6 — Cryptographic key protection | Least-privilege key access | IAM policies restrict KMS `Decrypt` to `kms:ViaService secretsmanager.*.amazonaws.com` — keys cannot be used outside Secrets Manager |

---

## Requirement 4 — Protect Cardholder Data in Transit

| Sub-requirement | Control | Implementation |
|----------------|---------|----------------|
| 4.2.1 — TLS for data in transit | TLS everywhere | All Vault and AWS API calls use TLS; mock-provider simulates HTTPS in production; webhook validation over HTTPS |
| 4.2.1.1 — Certificate validation | TLS certificate validation | hvac and boto3 validate TLS certificates by default; no `verify=False` in production code |

---

## Requirement 6 — Develop and Maintain Secure Systems

| Sub-requirement | Control | Implementation |
|----------------|---------|----------------|
| 6.3.2 — Inventory of bespoke software | Repository structure | All custom code is in this repository; `secrets-definitions.json` documents all credentials |
| 6.3.3 — Security patches | Pinned dependencies | `requirements.txt` files pin all versions; Dependabot can be configured for automated updates |
| 6.4.1 — Security testing in CI/CD | Secrets scanning | Gitleaks + TruffleHog scan every PR and push; pre-commit hook prevents secrets reaching CI |
| 6.4.2 — Detect and remove secrets | Pre-commit + CI scan | See `.pre-commit-config.yaml` and `.github/workflows/secrets-scan.yml`; custom rules for `bsur_` and `wpro_` prefixes |

---

## Requirement 7 — Restrict Access to System Components

| Sub-requirement | Control | Implementation |
|----------------|---------|----------------|
| 7.2 — Access control model | Least privilege | Each service has a dedicated AppRole with the minimum required Vault policy; `payments-api` cannot read `walletpro` secrets |
| 7.2.4 — Review user accounts | Audit log | `audit/audit.log` + Vault audit device log every secret access for review |
| 7.3.1 — Deny by default | Vault policies | Vault policies are deny-by-default; only explicitly granted paths are accessible |

---

## Requirement 8 — Identify Users and Authenticate

| Sub-requirement | Control | Implementation |
|----------------|---------|----------------|
| 8.2.1 — Unique IDs per user | AppRole per service | `payments-api`, `webhooks-service`, `rotation-agent` each have a unique AppRole with unique role_id |
| 8.2.2 — No shared credentials | No shared secrets | No service shares credentials; CI uses its own `VAULT_TOKEN` GitHub Secret; break-glass creates per-incident tokens |
| 8.3.1 — MFA for admin access | Break-glass prompt | `break-glass.sh` requires operator name + incident ticket (process control); production would add Vault control groups for MFA |
| 8.6 — Service account management | AppRole binding | Each service account is bound to specific policies; `bind_secret_id=true` prevents token creation without the secret_id |

---

## Requirement 10 — Log and Monitor All Access

| Sub-requirement | Control | Implementation |
|----------------|---------|----------------|
| 10.2.1 — Audit logs for all access | Centralized audit log | `audit/audit.log` receives events from rotation script, services, and mock-provider; Vault audit device and CloudTrail capture API-level events |
| 10.2.1.1 — Log individual user access | Actor field | Every audit event includes `actor` field (service name or human operator ID) |
| 10.2.1.2 — Log admin actions | Break-glass events | `break_glass_activated` and `break_glass_token_issued` events include operator, incident ticket, and reason |
| 10.2.1.3 — Log access to audit logs | Vault audit device | Vault's own audit device logs audit log access; AWS CloudTrail logs S3 access if audit logs are shipped there |
| 10.3.1 — Protect audit logs | Append-only | Vault audit device is append-only; CloudTrail logs are immutable; SIEM integration creates read-only copy |
| 10.5.1 — Retain audit logs 12 months | Retention policy | GitHub Actions artifacts retained 90 days (configurable to 1 year); CloudWatch Logs retention configured to 1 year; note in README |
| 10.6.1 — Synchronize clocks | UTC timestamps | All services use `datetime.now(timezone.utc)` — no local time zones in audit events |

---

## Requirement 12 — Support Information Security with Organizational Policies

| Sub-requirement | Control | Implementation |
|----------------|---------|----------------|
| 12.3.2 — Targeted risk analysis | Threat model | See `docs/threat-model.md` for STRIDE analysis covering all credential types |
| 12.3.3 — Cryptographic review | Annual rotation | Quarterly rotation schedule implemented in `rotate-secrets.yml` cron; rotation runbook documents the process |
| 12.10.1 — Incident response plan | Break-glass procedure | `docs/break-glass.md` documents the full incident response process; `scripts/break-glass.sh` provides tooling |

---

## Gaps and Production Improvements

| Gap | Production Resolution |
|-----|--------------------|
| DB credentials not rotated | Vault dynamic secrets (generates temp DB user with 1h TTL) or RDS IAM authentication |
| Mock provider instead of real APIs | Real BancoSur/WalletPro API calls with proper error handling and retry logic |
| Vault dev mode (no HA, no auto-unseal) | Production Vault cluster with Raft HA storage, AWS KMS auto-unseal, and TLS |
| CloudWatch audit retention | Configure 1-year CloudWatch Logs retention + S3 archival for 3-year compliance retention |
| MFA for break-glass | Vault Enterprise control groups require multi-party approval before admin token creation |
