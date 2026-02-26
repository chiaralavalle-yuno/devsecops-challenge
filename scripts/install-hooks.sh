#!/usr/bin/env bash
# install-hooks.sh — installs pre-commit hooks for the Pagos DevSecOps demo
set -euo pipefail

echo "==> Installing Pagos DevSecOps pre-commit hooks..."

# Check dependencies
if ! command -v pre-commit &>/dev/null; then
  echo "ERROR: pre-commit not found. Install it:"
  echo "  pip install pre-commit"
  echo "  brew install pre-commit"
  exit 1
fi

if ! command -v gitleaks &>/dev/null; then
  echo "WARNING: gitleaks not found locally (pre-commit will download it automatically)"
  echo "  To install manually: brew install gitleaks"
fi

# Install hooks
pre-commit install --hook-type pre-commit
pre-commit install --hook-type commit-msg 2>/dev/null || true

echo ""
echo "==> Hooks installed successfully!"
echo "    Every commit will be scanned for secrets via gitleaks."
echo "    To test: ./scripts/demo-blocked-commit.sh"
echo "    To skip (EMERGENCY ONLY): git commit --no-verify"
echo "    To run manually: pre-commit run --all-files"
