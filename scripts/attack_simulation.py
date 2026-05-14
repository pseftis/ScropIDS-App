#!/usr/bin/env python3
"""
Harmless interactive attack simulation for macOS terminals.

This script does not attack anything, scan networks, change system settings,
or touch project files. It only prints simulated security events so you can
practice observing different alert levels.
"""

import random
import time
from datetime import datetime


LEVELS = {
    "1": {
        "name": "LOW",
        "rounds": 8,
        "delay": 0.55,
        "events": [
            "Unusual login time observed for local user",
            "Multiple failed sudo attempts from terminal session",
            "Suspicious browser extension permission request",
            "Unknown process requested access to Documents folder",
            "Repeated DNS lookup for newly registered domain",
        ],
    },
    "2": {
        "name": "MEDIUM",
        "rounds": 14,
        "delay": 0.38,
        "events": [
            "Credential stuffing pattern detected against local test service",
            "Unexpected launch agent persistence attempt simulated",
            "Simulated phishing payload opened in user Downloads folder",
            "Process tree resembles encoded command execution",
            "Untrusted binary blocked by Gatekeeper policy",
            "Sensitive file access pattern detected in home directory",
        ],
    },
    "3": {
        "name": "HIGH",
        "rounds": 22,
        "delay": 0.25,
        "events": [
            "Simulated privilege escalation chain started",
            "Fake ransomware behavior: rapid file rename pattern detected",
            "Command-and-control beacon pattern simulated",
            "Suspicious keychain access request observed",
            "Defensive tool discovery commands simulated",
            "Large archive staging behavior detected",
            "Endpoint isolation recommended by simulated policy",
        ],
    },
    "4": {
        "name": "CRITICAL",
        "rounds": 32,
        "delay": 0.16,
        "events": [
            "Critical simulation: fake data exfiltration sequence detected",
            "Multiple simulated persistence techniques triggered",
            "Simulated destructive command blocked before execution",
            "Fake lateral movement attempt against internal hosts",
            "High-confidence credential theft behavior simulated",
            "Mass file encryption pattern simulated and contained",
            "Incident response escalation required in simulation",
            "Containment playbook activated for simulated host compromise",
        ],
    },
}


SEVERITY_MARKERS = {
    "LOW": "[INFO]",
    "MEDIUM": "[WARN]",
    "HIGH": "[ALERT]",
    "CRITICAL": "[CRITICAL]",
}


def slow_print(text, delay=0.02):
    for char in text:
        print(char, end="", flush=True)
        time.sleep(delay)
    print()


def show_menu():
    print()
    print("macOS Attack Simulation - Harmless Training Mode")
    print("=" * 52)
    print("1. Low level")
    print("2. Medium level")
    print("3. High level")
    print("4. Critical level")
    print("q. Quit")
    print()


def simulated_event(level_name, event):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pid = random.randint(1200, 9800)
    source = random.choice(["endpoint", "identity", "network", "filesystem", "edr"])
    marker = SEVERITY_MARKERS[level_name]
    return f"{now} {marker} source={source} pid={pid} event=\"{event}\""


def run_simulation(config):
    level_name = config["name"]
    marker = SEVERITY_MARKERS[level_name]
    detections = 0
    contained = 0

    print()
    slow_print(f"Starting {level_name} simulation. No real attack will run.", 0.01)
    print("-" * 52)

    for step in range(1, config["rounds"] + 1):
        event = random.choice(config["events"])
        print(simulated_event(level_name, event))

        if random.random() > 0.25:
            detections += 1
            print(f"    {marker} detection=created rule=SIM-{random.randint(100, 999)}")

        if random.random() > 0.55:
            contained += 1
            print("    [ACTION] simulated containment action completed")

        progress = int((step / config["rounds"]) * 24)
        bar = "#" * progress + "." * (24 - progress)
        print(f"    progress=[{bar}] {step}/{config['rounds']}")
        time.sleep(config["delay"])

    print("-" * 52)
    print("Simulation summary")
    print(f"Level:              {level_name}")
    print(f"Events generated:   {config['rounds']}")
    print(f"Detections created: {detections}")
    print(f"Actions simulated:  {contained}")
    print("Real system impact: none")
    print()


def main():
    while True:
        show_menu()
        choice = input("Select a level: ").strip().lower()

        if choice in {"q", "quit", "exit"}:
            print("Exiting simulation.")
            return 0

        config = LEVELS.get(choice)
        if not config:
            print("Please choose 1, 2, 3, 4, or q.")
            continue

        run_simulation(config)
        again = input("Run another simulation? [y/N]: ").strip().lower()
        if again != "y":
            print("Done.")
            return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nSimulation stopped by user.")
        raise SystemExit(130)
