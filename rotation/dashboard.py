#!/usr/bin/env python3
"""
rotation/dashboard.py — Rich CLI dashboard showing secret ages and rotation status.

Usage:
    python rotation/dashboard.py                    # Vault backend (default)
    python rotation/dashboard.py --backend aws      # AWS Secrets Manager
    python rotation/dashboard.py --backend vault --watch  # Auto-refresh every 30s

Requires: pip install rich hvac boto3

Example output:
    ┌─────────────────────────────────────────────────────────────────┐
    │ Pagos Secrets Rotation Dashboard                                │
    ├──────────────────────┬──────────┬─────────────┬──────┬────────┤
    │ Secret Path          │ Version  │ Last Rotated│ Age  │ Status │
    ├──────────────────────┼──────────┼─────────────┼──────┼────────┤
    │ bancosur/api_key     │ v3       │ 2025-11-15  │ 42d  │ OK     │
    │ walletpro/webhook    │ v1       │ 2025-08-01  │ 148d │ DUE    │
    └──────────────────────┴──────────┴─────────────┴──────┴────────┘
"""
import argparse
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from rich.console import Console
    from rich.live import Live
    from rich.table import Table
    from rich.text import Text
except ImportError:
    print("ERROR: rich is required. Install with: pip install rich")
    sys.exit(1)

console = Console()

ROTATION_DUE_DAYS = 90   # PCI-DSS quarterly rotation
ROTATION_WARN_DAYS = 75  # Warn 15 days before due

SECRET_PATHS = [
    "pagos/providers/bancosur/api_key",
    "pagos/providers/bancosur/webhook_secret",
    "pagos/providers/walletpro/api_key",
    "pagos/providers/walletpro/webhook_secret",
    "pagos/database/transactions_url",
    "pagos/database/admin_password",
    "pagos/aws/iam_access_key",
]


def get_vault_metadata(paths: list[str]) -> list[dict[str, Any]]:
    """Fetch secret metadata from Vault KV v2."""
    try:
        import hvac  # type: ignore
    except ImportError:
        console.print("[red]hvac not installed. Run: pip install hvac[/red]")
        return []

    vault_addr = os.environ.get("VAULT_ADDR", "http://localhost:8200")
    role_id = os.environ.get("VAULT_ROLE_ID_ROTATION_AGENT")
    secret_id = os.environ.get("VAULT_SECRET_ID_ROTATION_AGENT")

    client = hvac.Client(url=vault_addr)
    if role_id and secret_id:
        client.auth.approle.login(role_id=role_id, secret_id=secret_id)
    else:
        client.token = os.environ.get("VAULT_TOKEN", "root")

    results = []
    for path in paths:
        try:
            metadata = client.secrets.kv.v2.read_secret_metadata(
                path=path, mount_point="secret"
            )
            data = metadata["data"]
            current_version = data["current_version"]
            version_data = data["versions"].get(str(current_version), {})
            created_time = version_data.get("created_time", "")

            results.append({
                "path": path,
                "version": current_version,
                "last_rotated": created_time,
                "error": None,
            })
        except Exception as e:
            results.append({
                "path": path,
                "version": "?",
                "last_rotated": None,
                "error": str(e),
            })
    return results


def get_aws_metadata(paths: list[str]) -> list[dict[str, Any]]:
    """Fetch secret metadata from AWS Secrets Manager."""
    try:
        import boto3
    except ImportError:
        console.print("[red]boto3 not installed. Run: pip install boto3[/red]")
        return []

    region = os.environ.get("AWS_REGION", "us-east-1")
    sm = boto3.client("secretsmanager", region_name=region)
    results = []

    for path in paths:
        try:
            versions = sm.list_secret_version_ids(SecretId=path)["Versions"]
            current = next(
                (v for v in versions if "AWSCURRENT" in v.get("VersionStages", [])), None
            )
            if current:
                last_rotated = current.get("LastAccessedDate") or current.get("CreatedDate")
                results.append({
                    "path": path,
                    "version": current.get("VersionId", "?")[:8] + "...",
                    "last_rotated": last_rotated.isoformat() if last_rotated else None,
                    "error": None,
                })
            else:
                results.append({
                    "path": path, "version": "?",
                    "last_rotated": None, "error": "No AWSCURRENT version"
                })
        except Exception as e:
            results.append({
                "path": path, "version": "?",
                "last_rotated": None, "error": str(e)
            })
    return results


def parse_age(last_rotated: str | None) -> tuple[int | None, str]:
    """Parse ISO timestamp and return (age_days, display_string)."""
    if not last_rotated:
        return None, "unknown"
    try:
        # Handle both "Z" and "+00:00" suffixes
        ts = last_rotated.replace("Z", "+00:00")
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - dt).days
        return age, f"{age}d"
    except Exception:
        return None, "?"


def status_indicator(age_days: int | None, path: str) -> Text:
    """Return a colored status indicator based on age."""
    if "database" in path:
        return Text("MANUAL", style="dim")
    if age_days is None:
        return Text("UNKNOWN", style="yellow")
    if age_days >= ROTATION_DUE_DAYS:
        return Text("DUE", style="bold red")
    if age_days >= ROTATION_WARN_DAYS:
        return Text("WARN", style="bold yellow")
    return Text("OK", style="green")


def build_table(backend_name: str, metadata: list[dict[str, Any]]) -> Table:
    """Build a Rich table from metadata."""
    table = Table(
        title=f"Pagos Secrets Rotation Dashboard  [dim]({backend_name} backend)[/dim]",
        show_header=True,
        header_style="bold cyan",
        border_style="blue",
        expand=True,
    )
    table.add_column("Secret Path", style="dim", min_width=35)
    table.add_column("Version", justify="center", min_width=8)
    table.add_column("Last Rotated", justify="center", min_width=20)
    table.add_column("Age", justify="center", min_width=6)
    table.add_column("Status", justify="center", min_width=8)

    for item in metadata:
        if item["error"]:
            table.add_row(
                item["path"],
                "?",
                f"[red]{item['error'][:30]}[/red]",
                "?",
                Text("ERROR", style="red"),
            )
            continue

        age_days, age_str = parse_age(item["last_rotated"])
        last_rotated_display = (
            item["last_rotated"][:10] if item["last_rotated"] else "unknown"
        )
        status = status_indicator(age_days, item["path"])

        short_path = item["path"].replace("pagos/providers/", "").replace("pagos/", "")
        table.add_row(
            f"pagos/{short_path}",
            f"v{item['version']}",
            last_rotated_display,
            age_str,
            status,
        )

    table.caption = (
        f"[dim]Rotation policy: quarterly (every {ROTATION_DUE_DAYS} days) | "
        f"WARN at {ROTATION_WARN_DAYS} days | "
        f"Run: python rotation/rotate.py --provider <name> --backend {backend_name}[/dim]"
    )
    return table


def main() -> None:
    parser = argparse.ArgumentParser(description="Pagos secrets rotation dashboard")
    parser.add_argument("--backend", choices=["vault", "aws"], default="vault")
    parser.add_argument("--watch", action="store_true", help="Auto-refresh every 30s")
    parser.add_argument("--interval", type=int, default=30, help="Refresh interval in seconds")
    args = parser.parse_args()

    fetch_fn = get_vault_metadata if args.backend == "vault" else get_aws_metadata

    if args.watch:
        with Live(console=console, refresh_per_second=0.1) as live:
            while True:
                metadata = fetch_fn(SECRET_PATHS)
                live.update(build_table(args.backend, metadata))
                time.sleep(args.interval)
    else:
        metadata = fetch_fn(SECRET_PATHS)
        console.print(build_table(args.backend, metadata))
        console.print("\n[dim]Commands:[/dim]")
        console.print(
            f"  [cyan]python rotation/rotate.py --provider bancosur --backend {args.backend}[/cyan]"
        )
        console.print(
            f"  [cyan]python rotation/dashboard.py --backend {args.backend} --watch[/cyan]"
        )


if __name__ == "__main__":
    main()
