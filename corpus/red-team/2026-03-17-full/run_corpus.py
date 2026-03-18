"""Run each adversarial corpus directory through the scanner and report results."""

import json
import sys
from collections import defaultdict
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))

from skill_scan.scanner import scan

CORPUS_DIR = Path(__file__).resolve().parent
CATEGORIES = ["exec-evasion", "pi-evasion", "exfil-obfs-evasion", "split-kwargs-evasion"]
METADATA = {"SKILL.md", "manifest.json", "results.json", "regression-candidates.txt"}

results: dict[str, dict[str, object]] = {}
total_files = 0
total_detected = 0

for category in CATEGORIES:
    subdir = CORPUS_DIR / category
    if not subdir.is_dir():
        continue

    scan_result = scan(subdir)

    # Group findings by file path
    by_file: dict[str, list[object]] = defaultdict(list)
    for f in scan_result.findings:
        by_file[f.file].append(f)

    # Enumerate all input files (exclude metadata)
    input_files = sorted(
        p.relative_to(subdir).as_posix()
        for p in subdir.rglob("*")
        if p.is_file() and p.name not in METADATA
    )

    cat_results: dict[str, object] = {}
    for rel_path in input_files:
        findings = by_file.get(rel_path, [])
        detected = len(findings) > 0
        cat_results[rel_path] = {
            "detected": detected,
            "finding_count": len(findings),
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    "matched_text": f.matched_text,
                    "line": f.line,
                }
                for f in findings
            ],
        }
        total_files += 1
        if detected:
            total_detected += 1

    results[category] = cat_results

# Summary
total_evaded = total_files - total_detected

print("\n=== CORPUS RESULTS ===")
print(f"Total files: {total_files}")
print(f"Detected:    {total_detected}")
print(f"Evaded:      {total_evaded}")
if total_files:
    print(f"Evasion rate: {total_evaded / total_files * 100:.1f}%")

print("\n=== PER-CATEGORY RESULTS ===")
for category, cat_results in results.items():
    cat_total = len(cat_results)
    cat_detected = sum(1 for r in cat_results.values() if r["detected"])
    cat_evaded = cat_total - cat_detected
    rate = cat_evaded / cat_total * 100 if cat_total else 0
    print(f"\n  {category}: {cat_detected}/{cat_total} detected ({rate:.1f}% evasion)")
    for name, r in sorted(cat_results.items()):
        status = "DETECTED" if r["detected"] else "EVADED"
        print(f"    {status:>8}  {name}")
        for f in r["findings"]:
            print(f"             -> {f['rule_id']} L{f['line']}: {f['matched_text']}")

# Write JSON results
out_path = CORPUS_DIR / "results.json"
with open(out_path, "w") as fp:
    json.dump(results, fp, indent=2)
print(f"\nResults written to: {out_path}")
