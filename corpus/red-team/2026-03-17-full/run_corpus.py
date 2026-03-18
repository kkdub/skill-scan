"""Run each adversarial Python file through the scanner individually and report results."""
import json
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))

from skill_scan.ast_analyzer import analyze_python

CORPUS_DIR = Path(__file__).resolve().parent / "split-kwargs-evasion"

results = {}
for py_file in sorted(CORPUS_DIR.glob("*.py")):
    source = py_file.read_text(encoding="utf-8")
    findings = analyze_python(source, str(py_file))

    # Filter to EXEC-002, EXEC-006, EXEC-003 (the split/kwargs rules)
    relevant = [f for f in findings if f.rule_id in ("EXEC-002", "EXEC-006", "EXEC-003")]

    detected = len(relevant) > 0
    results[py_file.name] = {
        "detected": detected,
        "finding_count": len(relevant),
        "findings": [
            {"rule_id": f.rule_id, "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity), "matched_text": f.matched_text, "line": f.line}
            for f in relevant
        ],
    }

# Summary
total = len(results)
detected = sum(1 for r in results.values() if r["detected"])
evaded = total - detected

print(f"\n=== CORPUS RESULTS ===")
print(f"Total files: {total}")
print(f"Detected:    {detected}")
print(f"Evaded:      {evaded}")
print(f"Evasion rate: {evaded/total*100:.1f}%")

print(f"\n=== PER-FILE RESULTS ===")
for name, r in sorted(results.items()):
    status = "DETECTED" if r["detected"] else "EVADED"
    print(f"  {status:>8}  {name}")
    for f in r["findings"]:
        print(f"           -> {f['rule_id']} L{f['line']}: {f['matched_text']}")

# Write JSON results
out_path = Path(__file__).resolve().parent / "results.json"
with open(out_path, "w") as fp:
    json.dump(results, fp, indent=2)
print(f"\nResults written to: {out_path}")
