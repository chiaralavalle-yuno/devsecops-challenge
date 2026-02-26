#!/usr/bin/env python3
"""
rotation/anomaly_detect.py — Parses audit.log for unusual access patterns.

Usage:
    python rotation/anomaly_detect.py                    # Analyze existing audit.log
    tail -f audit/audit.log | python rotation/anomaly_detect.py --stream  # Real-time
    python rotation/anomaly_detect.py --log audit/sample-audit.log        # Specific file

Detects:
  - New path accessed by a known actor (first-time access)
  - Access rate > 2x the 5-minute rolling average
  - Access by an unknown actor
  - Rotation failures (rotation_failed_rollback events)
  - Break-glass activations
"""
import argparse
import json
import logging
import os
import sys
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger(__name__)

AUDIT_LOG_PATH = Path(__file__).parent.parent / "audit" / "audit.log"

# Known actors — alerts fire for any actor NOT in this set
KNOWN_ACTORS = {
    "payments-api",
    "webhooks-service",
    "rotation-agent",
    "mock-provider",
    "vault-init",
}

# High-severity actions that always trigger alerts
HIGH_SEVERITY_ACTIONS = {
    "rotation_failed_rollback",
    "break_glass_activated",
    "rotation_preflight_failed",
}


class AnomalyDetector:
    """
    Stateful anomaly detector for Pagos audit events.

    Baseline: tracks which actors have accessed which paths.
    Rate: tracks access counts in 5-minute windows.
    """

    def __init__(self, alert_rate_multiplier: float = 2.0, window_minutes: int = 5) -> None:
        # actor → set of known paths
        self.baseline: dict[str, set[str]] = defaultdict(set)
        # actor → deque of recent access timestamps (for rate calculation)
        self.access_times: dict[str, deque] = defaultdict(
            lambda: deque(maxlen=1000)
        )
        self.alert_rate_multiplier = alert_rate_multiplier
        self.window_seconds = window_minutes * 60
        self.alerts: list[dict[str, Any]] = []
        self.event_count = 0

    def process_event(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Process a single audit event and return any alerts generated.
        """
        self.event_count += 1
        new_alerts = []

        action = event.get("action", "")
        actor = event.get("actor", "unknown")
        resource = event.get("resource", "")
        result = event.get("result", "")
        timestamp_str = event.get("timestamp", "")

        # Parse timestamp
        try:
            ts = timestamp_str.replace("Z", "+00:00")
            event_time = datetime.fromisoformat(ts)
            if event_time.tzinfo is None:
                event_time = event_time.replace(tzinfo=timezone.utc)
        except Exception:
            event_time = datetime.now(timezone.utc)

        # ----------------------------------------------------------
        # 1. High-severity action alert (always fires)
        # ----------------------------------------------------------
        if action in HIGH_SEVERITY_ACTIONS:
            alert = {
                "alert": "high_severity_action",
                "severity": "critical",
                "actor": actor,
                "action": action,
                "resource": resource,
                "result": result,
                "timestamp": timestamp_str,
            }
            new_alerts.append(alert)

        # ----------------------------------------------------------
        # 2. Unknown actor alert
        # ----------------------------------------------------------
        if actor not in KNOWN_ACTORS:
            alert = {
                "alert": "unknown_actor",
                "severity": "high",
                "actor": actor,
                "action": action,
                "resource": resource,
                "timestamp": timestamp_str,
                "expected_actors": sorted(KNOWN_ACTORS),
            }
            new_alerts.append(alert)

        # ----------------------------------------------------------
        # 3. New path accessed by known actor
        # ----------------------------------------------------------
        if resource and actor in KNOWN_ACTORS:
            if resource not in self.baseline[actor]:
                if self.baseline[actor]:  # Only alert if actor has existing baseline
                    alert = {
                        "alert": "new_path_access",
                        "severity": "medium",
                        "actor": actor,
                        "path": resource,
                        "expected": False,
                        "known_paths": sorted(self.baseline[actor]),
                        "timestamp": timestamp_str,
                    }
                    new_alerts.append(alert)
                self.baseline[actor].add(resource)

        # ----------------------------------------------------------
        # 4. Access rate anomaly (> 2x 5-minute rolling average)
        # ----------------------------------------------------------
        if resource:
            key = f"{actor}:{resource}"
            self.access_times[key].append(event_time.timestamp())

            # Count events in current window vs previous window
            now_ts = event_time.timestamp()
            window_start = now_ts - self.window_seconds
            prev_window_start = window_start - self.window_seconds

            current_count = sum(
                1 for t in self.access_times[key] if t >= window_start
            )
            prev_count = sum(
                1 for t in self.access_times[key]
                if prev_window_start <= t < window_start
            )

            if prev_count > 0 and current_count > self.alert_rate_multiplier * prev_count:
                alert = {
                    "alert": "access_rate_spike",
                    "severity": "medium",
                    "actor": actor,
                    "resource": resource,
                    "current_window_count": current_count,
                    "previous_window_count": prev_count,
                    "rate_multiplier": round(current_count / prev_count, 2),
                    "threshold": self.alert_rate_multiplier,
                    "timestamp": timestamp_str,
                }
                new_alerts.append(alert)

        self.alerts.extend(new_alerts)
        return new_alerts

    def print_summary(self) -> None:
        """Print a summary of detected anomalies."""
        log.info(f"\n{'='*60}")
        log.info(f"Anomaly Detection Summary")
        log.info(f"{'='*60}")
        log.info(f"Events processed: {self.event_count}")
        log.info(f"Alerts generated: {len(self.alerts)}")

        if not self.alerts:
            log.info("\n[OK] No anomalies detected.")
            return

        log.info("\nAlerts by severity:")
        by_severity: dict[str, list] = defaultdict(list)
        for alert in self.alerts:
            by_severity[alert.get("severity", "unknown")].append(alert)

        for severity in ["critical", "high", "medium", "low"]:
            if severity in by_severity:
                log.info(f"\n  {severity.upper()} ({len(by_severity[severity])}):")
                for alert in by_severity[severity]:
                    log.info(f"    {json.dumps(alert)}")

        log.info(f"\nBaseline (actor → known paths):")
        for actor, paths in sorted(self.baseline.items()):
            log.info(f"  {actor}:")
            for path in sorted(paths):
                log.info(f"    - {path}")


def analyze_file(log_path: Path, detector: AnomalyDetector) -> int:
    """Analyze a log file and return the number of alerts."""
    if not log_path.exists():
        log.error(f"Log file not found: {log_path}")
        return 0

    alert_count = 0
    with open(log_path) as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                alerts = detector.process_event(event)
                for alert in alerts:
                    print(json.dumps(alert))
                alert_count += len(alerts)
            except json.JSONDecodeError:
                log.warning(f"Line {line_num}: invalid JSON — skipped")

    return alert_count


def stream_stdin(detector: AnomalyDetector) -> None:
    """Process events from stdin in real-time (for tail -f piping)."""
    log.info("Streaming audit events from stdin (Ctrl+C to stop)...")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
            alerts = detector.process_event(event)
            for alert in alerts:
                # Print alerts immediately to stdout
                print(json.dumps(alert), flush=True)
        except json.JSONDecodeError:
            pass  # Skip invalid lines in stream mode


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Detect anomalies in Pagos audit logs",
        epilog="Example: tail -f audit/audit.log | python rotation/anomaly_detect.py --stream",
    )
    parser.add_argument(
        "--log",
        type=Path,
        default=AUDIT_LOG_PATH,
        help=f"Path to audit log (default: {AUDIT_LOG_PATH})",
    )
    parser.add_argument(
        "--stream",
        action="store_true",
        help="Read events from stdin in real-time (for tail -f piping)",
    )
    parser.add_argument(
        "--rate-multiplier",
        type=float,
        default=2.0,
        help="Alert if access rate exceeds N× the baseline (default: 2.0)",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print summary of actor baseline after analysis",
    )
    args = parser.parse_args()

    detector = AnomalyDetector(alert_rate_multiplier=args.rate_multiplier)

    if args.stream:
        try:
            stream_stdin(detector)
        except KeyboardInterrupt:
            pass
    else:
        alert_count = analyze_file(args.log, detector)
        if args.summary or alert_count == 0:
            detector.print_summary()
        if alert_count > 0:
            sys.exit(1)  # Non-zero exit for CI integration


if __name__ == "__main__":
    main()
