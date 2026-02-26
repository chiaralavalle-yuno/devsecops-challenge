#!/usr/bin/env bash
# break-glass.sh — Emergency admin access for Pagos Vault
#
# Use ONLY during declared incidents when normal rotation tooling is down.
# Every break-glass activation is logged to audit/audit.log and (if configured)
# sent to Slack. A time-limited admin token (1h TTL) is created.
#
# Post-incident requirements (see docs/break-glass.md):
#   1. Revoke the token immediately after the incident
#   2. Rotate all secrets that were accessed
#   3. Write an incident report referencing the audit log
#
# Usage:
#   ./scripts/break-glass.sh
set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:-http://localhost:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-root}"
AUDIT_LOG="${AUDIT_LOG:-audit/audit.log}"
SLACK_WEBHOOK_URL="${SLACK_WEBHOOK_URL:-}"

export VAULT_ADDR VAULT_TOKEN

echo "╔══════════════════════════════════════════════════════════╗"
echo "║           PAGOS BREAK-GLASS PROCEDURE                   ║"
echo "║                                                          ║"
echo "║  This creates a time-limited admin Vault token (1h TTL) ║"
echo "║  Use ONLY for declared security incidents.               ║"
echo "║  All access is logged to audit/audit.log                 ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# ============================================================
# 1. Prompt for incident details
# ============================================================
read -rp "Enter your name/operator ID: " OPERATOR_NAME
if [ -z "$OPERATOR_NAME" ]; then
  echo "ERROR: Operator name is required."
  exit 1
fi

read -rp "Enter incident ticket number (e.g., INC-2024-001): " INCIDENT_TICKET
if [ -z "$INCIDENT_TICKET" ]; then
  echo "ERROR: Incident ticket number is required."
  exit 1
fi

read -rp "Enter reason for break-glass (brief description): " REASON
if [ -z "$REASON" ]; then
  echo "ERROR: Reason is required."
  exit 1
fi

echo ""
echo "⚠️  WARNING: You are about to create an admin-level Vault token."
echo "   Operator: $OPERATOR_NAME"
echo "   Incident: $INCIDENT_TICKET"
echo "   Reason:   $REASON"
echo ""
read -rp "Type 'CONFIRM' to proceed: " CONFIRM

if [ "$CONFIRM" != "CONFIRM" ]; then
  echo "Break-glass cancelled."
  exit 0
fi

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# ============================================================
# 2. Write audit event BEFORE creating token
# ============================================================
mkdir -p "$(dirname "$AUDIT_LOG")"

AUDIT_EVENT=$(cat <<AUDITEOF
{"timestamp":"${TIMESTAMP}","action":"break_glass_activated","actor":"${OPERATOR_NAME}","resource":"vault/*","backend":"vault","result":"initiated","metadata":{"incident_ticket":"${INCIDENT_TICKET}","reason":"${REASON}","token_ttl":"1h"}}
AUDITEOF
)

echo "$AUDIT_EVENT" >> "$AUDIT_LOG"
echo "✓ Break-glass activation logged to: $AUDIT_LOG"

# ============================================================
# 3. Create time-limited admin token
# ============================================================
echo ""
echo "==> Creating time-limited admin token (TTL: 1h)..."

if ! curl -sf "$VAULT_ADDR/v1/sys/health" > /dev/null; then
  echo "ERROR: Cannot connect to Vault at $VAULT_ADDR"
  echo "       Ensure Vault is running and VAULT_ADDR is set correctly."
  exit 1
fi

ADMIN_TOKEN=$(curl -s -X POST \
  -H "X-Vault-Token: $VAULT_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"policies\":[\"admin\"],\"ttl\":\"1h\",\"display_name\":\"break-glass-${INCIDENT_TICKET}\",\"meta\":{\"operator\":\"${OPERATOR_NAME}\",\"incident\":\"${INCIDENT_TICKET}\"}}" \
  "$VAULT_ADDR/v1/auth/token/create" | python3 -c "import sys,json; print(json.load(sys.stdin)['auth']['client_token'])")

# ============================================================
# 4. Write completion audit event
# ============================================================
COMPLETE_EVENT=$(cat <<COMPLETEEOF
{"timestamp":"$(date -u +"%Y-%m-%dT%H:%M:%SZ")","action":"break_glass_token_issued","actor":"${OPERATOR_NAME}","resource":"vault/*","backend":"vault","result":"success","metadata":{"incident_ticket":"${INCIDENT_TICKET}","token_display":"break-glass-${INCIDENT_TICKET}","token_ttl":"1h","auto_expires_at":"$(date -u -d '+1 hour' +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u -v+1H +"%Y-%m-%dT%H:%M:%SZ")"}}
COMPLETEEOF
)
echo "$COMPLETE_EVENT" >> "$AUDIT_LOG"

# ============================================================
# 5. Slack notification (mocked if no webhook configured)
# ============================================================
SLACK_PAYLOAD=$(cat <<SLACKEOF
{"text":":rotating_light: *BREAK-GLASS ACTIVATED* at Pagos\n*Operator:* ${OPERATOR_NAME}\n*Incident:* ${INCIDENT_TICKET}\n*Reason:* ${REASON}\n*Token TTL:* 1 hour\n*Timestamp:* ${TIMESTAMP}\n\nInspect audit log for full details.","username":"pagos-security","icon_emoji":":rotating_light:"}
SLACKEOF
)

if [ -n "$SLACK_WEBHOOK_URL" ]; then
  curl -s -X POST -H 'Content-type: application/json' \
    --data "$SLACK_PAYLOAD" "$SLACK_WEBHOOK_URL" &>/dev/null && \
    echo "✓ Slack alert sent to security channel"
else
  echo ""
  echo "📋 Slack notification payload (SLACK_WEBHOOK_URL not configured):"
  echo "   Payload logged to: $AUDIT_LOG"
  echo "$SLACK_PAYLOAD" >> "$AUDIT_LOG"
fi

# ============================================================
# 6. Output token
# ============================================================
echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║           BREAK-GLASS TOKEN ISSUED                      ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║                                                          ║"
echo "║  Token (valid for 1 hour):                              ║"
echo "║  $ADMIN_TOKEN"
echo "║                                                          ║"
echo "║  To use: export VAULT_TOKEN=$ADMIN_TOKEN                ║"
echo "║                                                          ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║  POST-INCIDENT REQUIREMENTS (see docs/break-glass.md):  ║"
echo "║  1. Revoke this token when incident is resolved:        ║"
echo "║     vault token revoke $ADMIN_TOKEN              ║"
echo "║  2. Rotate ALL secrets you accessed                     ║"
echo "║  3. Write incident report referencing: $INCIDENT_TICKET ║"
echo "╚══════════════════════════════════════════════════════════╝"
