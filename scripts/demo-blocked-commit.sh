#!/usr/bin/env bash
# demo-blocked-commit.sh — demonstrates the pre-commit secret scanning in action
# Creates a temporary file with a fake API key, attempts to commit it, shows the block.
set -euo pipefail

DEMO_FILE="demo_secret_leak_$(date +%s).py"

echo "==> DEMO: Showing what happens when a developer accidentally commits a secret"
echo ""
echo "Step 1: Creating a file with a fake BancoSur API key..."

cat > "$DEMO_FILE" <<'PYEOF'
# payments.py — DO NOT COMMIT THIS (demo only)
import requests

# BAD: hardcoded API key — this would be caught by gitleaks
BANCOSUR_API_KEY = "bsur_a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"

def process_payment(amount: float) -> dict:
    response = requests.post(
        "https://api.bancosur.com/v1/payments",
        headers={"Authorization": f"Bearer {BANCOSUR_API_KEY}"},
        json={"amount": amount}
    )
    return response.json()
PYEOF

echo "    Created: $DEMO_FILE"
echo ""
echo "Step 2: Staging the file..."
git add "$DEMO_FILE"

echo ""
echo "Step 3: Attempting commit (this will be BLOCKED by gitleaks)..."
echo "------------------------------------------------------------------------"

set +e
git commit -m "Add payment integration" 2>&1
COMMIT_EXIT=$?
set -e

echo "------------------------------------------------------------------------"
echo ""

if [ $COMMIT_EXIT -ne 0 ]; then
  echo "✓ BLOCKED: The commit was rejected because it contained a secret."
  echo ""
  echo "The developer should now:"
  echo "  1. Move the key to .env: BANCOSUR_API_KEY=bsur_..."
  echo "  2. Update the code: api_key = os.environ['BANCOSUR_API_KEY']"
  echo "  3. Store the real key in Vault/AWS Secrets Manager"
else
  echo "⚠ WARNING: Commit was NOT blocked. Ensure pre-commit hooks are installed:"
  echo "  ./scripts/install-hooks.sh"
fi

echo ""
echo "Step 4: Cleaning up demo file..."
git rm --cached "$DEMO_FILE" 2>/dev/null || true
rm -f "$DEMO_FILE"
echo "    Cleaned up: $DEMO_FILE"
echo ""
echo "==> Demo complete."
