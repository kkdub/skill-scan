"""Triage runner for augmented int-list red-team corpus.

Scans each adversarial .py file and reports which patterns produce EXEC-002
findings vs which evade detection.
"""
from __future__ import annotations

import sys
from pathlib import Path

from skill_scan.ast_analyzer import analyze_python

CORPUS_DIR = Path(__file__).parent
DANGEROUS_RULES = {"EXEC-002", "EXEC-006"}


def scan_file(path: Path) -> list[dict]:
    """Scan a single file and return findings summary."""
    code = path.read_text(encoding="utf-8")
    findings = analyze_python(code, str(path))
    return [
        {"rule_id": f.rule_id, "line": f.line, "description": f.description}
        for f in findings
        if f.rule_id in DANGEROUS_RULES
    ]


def main() -> None:
    files = sorted(CORPUS_DIR.glob("*.py"))
    files = [f for f in files if f.name not in ("run_triage.py", "__init__.py")]

    total_files = 0
    detected_files = 0
    for path in files:
        total_files += 1
        results = scan_file(path)
        status = "DETECTED" if results else "EVADED"
        if results:
            detected_files += 1
        print(f"\n{'='*60}")
        print(f"File: {path.name} -> {status}")
        if results:
            for r in results:
                print(f"  L{r['line']}: {r['rule_id']} - {r['description'][:80]}")
        else:
            print("  No EXEC-002/EXEC-006 findings")

    print(f"\n{'='*60}")
    print(f"Summary: {detected_files}/{total_files} files produced findings")


if __name__ == "__main__":
    main()
