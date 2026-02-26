#!/usr/bin/env bash
# secrets-reminder.sh — prints a remediation guide when gitleaks blocks a commit
# This hook always exits 0 (it's informational only); gitleaks itself blocks the commit.
set -euo pipefail

# Only print if gitleaks found something (check its exit code in the pre-commit framework)
cat <<'REMINDER'

╔══════════════════════════════════════════════════════════════════╗
║           PAGOS SECURITY: Possible Secret Detected              ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  Your commit was blocked because it may contain a secret.        ║
║                                                                  ║
║  REMEDIATION STEPS:                                              ║
║  1. Run: git diff --staged                                       ║
║     Review what you are about to commit.                         ║
║                                                                  ║
║  2. Remove the secret from your code:                            ║
║     - Replace hardcoded value with an env var reference          ║
║     - Example: api_key = os.environ["BANCOSUR_API_KEY"]          ║
║                                                                  ║
║  3. Add the secret to .env (gitignored):                         ║
║     BANCOSUR_API_KEY=your_actual_value                           ║
║                                                                  ║
║  4. If you committed a secret previously:                        ║
║     - Rotate it IMMEDIATELY at the provider dashboard            ║
║     - Run: git filter-repo to purge history                      ║
║     - See: docs/rotation-runbook.md                              ║
║                                                                  ║
║  5. If this is a false positive:                                 ║
║     - Add an allowlist entry to .gitleaks.toml                   ║
║     - Never use --no-verify to bypass this check                 ║
║                                                                  ║
║  HELP: docs/rotation-runbook.md                                  ║
╚══════════════════════════════════════════════════════════════════╝

REMINDER

exit 0
