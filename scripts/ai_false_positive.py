#!/usr/bin/env python3
"""
scripts/ai_false_positive.py — AI-assisted false positive analysis for gitleaks findings.

Usage:
    python scripts/ai_false_positive.py --file services/payments-api/app.py --rule pagos-bancosur-key
    python scripts/ai_false_positive.py --file docs/example.md --rule pagos-bancosur-key --secret bsur_fake_abc123

Decision logic (in order):
    1. IMMEDIATE PASS  — file in tests/fixtures/docs/ AND secret has safe prefix (fake_/test_/etc.)
    2. IMMEDIATE FAIL  — file in src/services/rotation/
    3. AI / FALLBACK   — ambiguous cases: call Claude API; deterministic fallback if no API key

Cache: /tmp/pagos_fp_cache.json (keyed by sha256 of file+rule)
Audit: appends to audit/audit.log

Exit codes:
    0 = false positive (safe to ignore)
    1 = real secret (block the commit)
"""

import argparse
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

AUDIT_LOG = Path(__file__).parent.parent / "audit" / "audit.log"
CACHE_FILE = Path("/tmp/pagos_fp_cache.json")

# Files under these prefixes are immediately flagged as real secrets — no API call
PRODUCTION_PATH_PREFIXES = ("src/", "services/", "rotation/")

# Files under these prefixes *may* be false positives — checked together with value prefix
SAFE_PATH_PREFIXES = ("tests/", "fixtures/", "docs/")

# Value prefixes that indicate a placeholder / non-real secret
SAFE_VALUE_PREFIXES = ("fake_", "test_", "example_", "mock_", "dummy_")

CLAUDE_MODEL = "claude-sonnet-4-20250514"
CLAUDE_API_URL = "https://api.anthropic.com/v1/messages"
API_TIMEOUT = 5  # seconds


# ============================================================
# Helpers
# ============================================================

def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def cache_key(file: str, rule: str) -> str:
    return hashlib.sha256(f"{file}:{rule}".encode()).hexdigest()


def load_cache() -> dict:
    if CACHE_FILE.exists():
        try:
            return json.loads(CACHE_FILE.read_text())
        except Exception:
            return {}
    return {}


def save_cache(cache: dict) -> None:
    try:
        CACHE_FILE.write_text(json.dumps(cache, indent=2))
    except Exception:
        pass  # non-fatal


def write_audit_event(
    file: str, rule: str, is_false_positive: bool,
    confidence: str, reason: str, mode: str,
) -> None:
    event = {
        "timestamp": utcnow(),
        "action": "ai_false_positive_analysis",
        "actor": "ai_false_positive.py",
        "resource": file,
        "backend": "local",
        "result": "false_positive" if is_false_positive else "real_secret",
        "metadata": {
            "rule": rule,
            "is_false_positive": is_false_positive,
            "confidence": confidence,
            "reason": reason,
            "mode": mode,
        },
    }
    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    with open(AUDIT_LOG, "a") as f:
        f.write(json.dumps(event) + "\n")


# ============================================================
# Claude API + deterministic fallback
# ============================================================

def call_claude(file: str, rule: str, secret: Optional[str]) -> dict:
    """
    Ask Claude whether a finding is a false positive.
    Returns dict with keys: is_false_positive (bool), confidence (str), reason (str).
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return deterministic_fallback(file)

    system = (
        "You are a security analyst reviewing a gitleaks finding. "
        "Respond only with JSON: "
        '{"is_false_positive": bool, "confidence": "high|medium|low", "reason": "one sentence"}'
    )
    user_lines = [f"File: {file}", f"Rule: {rule}"]
    if secret:
        user_lines.append(f"Secret prefix: {secret}")
    user = "\n".join(user_lines)

    payload = json.dumps({
        "model": CLAUDE_MODEL,
        "max_tokens": 128,
        "system": system,
        "messages": [{"role": "user", "content": user}],
    }).encode()

    req = urllib.request.Request(
        CLAUDE_API_URL,
        data=payload,
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=API_TIMEOUT) as resp:
            body = json.loads(resp.read())
            text = body["content"][0]["text"]
            return json.loads(text)
    except Exception as e:
        # API error → fail safe (treat as real secret)
        return {
            "is_false_positive": False,
            "confidence": "low",
            "reason": f"API error, failing safe: {e}",
        }


def deterministic_fallback(file: str) -> dict:
    """
    Used when ANTHROPIC_API_KEY is not set.
    Production path → real secret. Test/docs path → likely false positive. Unknown → fail safe.
    """
    if any(file.startswith(p) for p in PRODUCTION_PATH_PREFIXES):
        return {
            "is_false_positive": False,
            "confidence": "high",
            "reason": "Production path — treating as real secret",
        }
    if any(file.startswith(p) for p in SAFE_PATH_PREFIXES):
        return {
            "is_false_positive": True,
            "confidence": "medium",
            "reason": "Test/docs path — likely not a real secret",
        }
    return {
        "is_false_positive": False,
        "confidence": "low",
        "reason": "Unknown path, failing safe",
    }


# ============================================================
# Core analysis logic
# ============================================================

def analyze(
    file: str, rule: str, secret: Optional[str]
) -> tuple[bool, str, str, str]:
    """
    Returns (is_false_positive, confidence, reason, mode).
    mode: "immediate" | "cached" | "ai" | "deterministic"
    """
    # Check cache first (keyed by file + rule, not secret value)
    cache = load_cache()
    key = cache_key(file, rule)
    if key in cache:
        entry = cache[key]
        return entry["is_false_positive"], entry["confidence"], entry["reason"], "cached"

    # -- Immediate PASS: safe path AND safe value prefix --
    if any(file.startswith(p) for p in SAFE_PATH_PREFIXES):
        if secret and any(secret.startswith(v) for v in SAFE_VALUE_PREFIXES):
            is_fp, confidence, reason = True, "high", (
                "Safe path and safe value prefix — known false positive"
            )
            cache[key] = {"is_false_positive": is_fp, "confidence": confidence, "reason": reason}
            save_cache(cache)
            return is_fp, confidence, reason, "immediate"

    # -- Immediate FAIL: production path --
    if any(file.startswith(p) for p in PRODUCTION_PATH_PREFIXES):
        is_fp, confidence, reason = False, "high", (
            "Production path — treating as real secret"
        )
        cache[key] = {"is_false_positive": is_fp, "confidence": confidence, "reason": reason}
        save_cache(cache)
        return is_fp, confidence, reason, "immediate"

    # -- Ambiguous: AI or deterministic fallback --
    if os.environ.get("ANTHROPIC_API_KEY"):
        response = call_claude(file, rule, secret)
        mode = "ai"
    else:
        response = deterministic_fallback(file)
        mode = "deterministic"

    is_fp = bool(response.get("is_false_positive", False))
    confidence = response.get("confidence", "low")
    reason = response.get("reason", "No reason provided")

    cache[key] = {"is_false_positive": is_fp, "confidence": confidence, "reason": reason}
    save_cache(cache)

    return is_fp, confidence, reason, mode


# ============================================================
# Entry point
# ============================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="AI-assisted false positive analysis for gitleaks findings",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--file", required=True, help="File path of the finding")
    parser.add_argument("--rule", required=True, help="Gitleaks rule ID")
    parser.add_argument(
        "--secret", default=None,
        help="Redacted secret value or prefix (optional, not the full secret)",
    )
    args = parser.parse_args()

    is_false_positive, confidence, reason, mode = analyze(
        args.file, args.rule, args.secret
    )

    write_audit_event(args.file, args.rule, is_false_positive, confidence, reason, mode)

    GREEN, RED, RESET = "\033[32m", "\033[31m", "\033[0m"
    decision_label = "FALSE POSITIVE — safe to ignore" if is_false_positive else "REAL SECRET — block commit"
    decision_color = GREEN if is_false_positive else RED

    print(f"""
Gitleaks Finding Analysis
─────────────────────────
  File:       {args.file}
  Rule:       {args.rule}
  Secret:     {args.secret or '(not provided)'}
  Mode:       {mode}
  Confidence: {confidence}
  Reason:     {reason}
  Decision:   {decision_color}{decision_label}{RESET}
""")

    sys.exit(0 if is_false_positive else 1)


if __name__ == "__main__":
    main()
