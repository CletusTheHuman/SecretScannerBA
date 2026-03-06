#!/usr/bin/env python3
"""
Secret Scanner - Secure Coding Final Project
Scans a file or directory for common hardcoded secret patterns using regex.
Outputs findings with filename, line number, and matched string.
"""

import argparse
import logging
import os
import re
import sys
from pathlib import Path

# Create a logger for reporting warnings, errors, and optional info messages
logger = logging.getLogger("secretscan")

# Define regex patterns used to detect common API keys and tokens
PATTERNS = [
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("GitHub PAT (Classic)", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("Slack Bot Token", re.compile(r"\bxoxb-[0-9]{11}-[0-9]{11}-[0-9A-Za-z]{24}\b")),
    ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Mailgun API Key", re.compile(r"\bkey-[0-9A-Za-z]{32}\b")),
]


def parse_args():
    # Build the command-line interface so the user can provide a file or directory to scan
    parser = argparse.ArgumentParser(
        prog="secretscan",
        description="Scan a file or directory for common hardcoded secrets (API keys/tokens).",
    )
    parser.add_argument("path", help="Path to a file or directory to scan")
    parser.add_argument(
        "--log-level",
        default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging level (default: WARNING)",
    )
    return parser.parse_args()


def configure_logging(level: str) -> None:
    # Configure logging so the program can display warnings, errors, or info messages
    logging.basicConfig(
        level=getattr(logging, level),
        format="%(levelname)s: %(message)s",
    )


def iter_files(target: Path):
    # Return either the single file provided or all files inside a directory
    if target.is_file():
        yield target
        return

    for dirpath, _, filenames in os.walk(target):
        for name in filenames:
            yield Path(dirpath) / name


def scan_file(path: Path):
    # Open a file and check each line against the regex patterns to find possible secrets
    findings = []
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, start=1):
                for detector_name, rx in PATTERNS:
                    for m in rx.finditer(line):
                        findings.append((str(path), line_num, m.group(0)))
    except (OSError, UnicodeError) as e:
        logger.warning("Could not read %s (%s)", path, e)
    return findings


def print_report(findings):
    # Display the scan results showing the file, line number, and detected key
    if not findings:
        print("No secrets detected.")
        return

    print("Findings:")
    print("-" * 80)
    for filename, line_num, match in findings:
        print(f"{filename} : line {line_num} : {match}")


def main():
    # Main program flow: read arguments, scan files, and print the results
    args = parse_args()
    configure_logging(args.log_level)

    target = Path(args.path).expanduser()

    if not target.exists():
        logger.error("Path not found: %s", target)
        return 2

    if not (target.is_file() or target.is_dir()):
        logger.error("Not a file or directory: %s", target)
        return 2

    all_findings = []
    file_count = 0

    for file_path in iter_files(target):
        if file_path.is_file():
            file_count += 1
            all_findings.extend(scan_file(file_path))

    logger.info("Scanned %d file(s). Found %d match(es).", file_count, len(all_findings))
    print_report(all_findings)

    # Exit code: 0 means no secrets found, 1 means secrets were detected
    return 1 if all_findings else 0


if __name__ == "__main__":
    # Start the program by running the main function
    sys.exit(main())