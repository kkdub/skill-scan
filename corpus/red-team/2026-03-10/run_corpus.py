"""Run adversarial corpus through analyze_python() and measure evasion rates.

Outputs JSON results and a human-readable summary.
"""

from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path

# Add project src to path
project_root = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(project_root / "src"))

from adversarial_corpus import CORPUS

from skill_scan.ast_analyzer import analyze_python


def run_corpus() -> dict:
    """Run all corpus inputs and return structured results."""
    results = []
    category_stats: dict[str, dict[str, int]] = {}

    for category, test_id, code, should_detect, description in CORPUS:
        code = textwrap.dedent(code)
        findings = analyze_python(code, "adversarial_test.py")

        # Filter to split-evasion and EXEC-* findings only
        relevant = [
            f for f in findings
            if f.rule_id in ("EXEC-002", "EXEC-006")
        ]

        detected = len(relevant) > 0

        if should_detect:
            # Positive case: should detect
            evaded = not detected
            status = "EVADED" if evaded else "DETECTED"
        else:
            # Negative case: should NOT detect
            false_positive = detected
            evaded = False  # not an evasion test
            status = "FALSE_POSITIVE" if false_positive else "TRUE_NEGATIVE"

        result = {
            "category": category,
            "id": test_id,
            "description": description,
            "should_detect": should_detect,
            "detected": detected,
            "status": status,
            "finding_count": len(relevant),
            "finding_details": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity.value,
                    "matched_text": f.matched_text,
                    "line": f.line,
                }
                for f in relevant
            ],
        }
        results.append(result)

        # Accumulate category stats
        if category not in category_stats:
            category_stats[category] = {
                "total": 0,
                "positive_total": 0,
                "positive_detected": 0,
                "positive_evaded": 0,
                "negative_total": 0,
                "false_positives": 0,
                "true_negatives": 0,
            }
        stats = category_stats[category]
        stats["total"] += 1
        if should_detect:
            stats["positive_total"] += 1
            if detected:
                stats["positive_detected"] += 1
            else:
                stats["positive_evaded"] += 1
        else:
            stats["negative_total"] += 1
            if detected:
                stats["false_positives"] += 1
            else:
                stats["true_negatives"] += 1

    # Overall stats
    positive_total = sum(1 for r in results if r["should_detect"])
    positive_detected = sum(1 for r in results if r["should_detect"] and r["detected"])
    positive_evaded = positive_total - positive_detected
    negative_total = sum(1 for r in results if not r["should_detect"])
    false_positives = sum(
        1 for r in results if not r["should_detect"] and r["detected"]
    )

    evasion_rate = positive_evaded / positive_total if positive_total > 0 else 0.0
    detection_rate = positive_detected / positive_total if positive_total > 0 else 0.0
    fp_rate = false_positives / negative_total if negative_total > 0 else 0.0

    return {
        "summary": {
            "total_inputs": len(results),
            "positive_total": positive_total,
            "positive_detected": positive_detected,
            "positive_evaded": positive_evaded,
            "negative_total": negative_total,
            "false_positives": false_positives,
            "detection_rate": round(detection_rate, 4),
            "evasion_rate": round(evasion_rate, 4),
            "false_positive_rate": round(fp_rate, 4),
        },
        "category_stats": category_stats,
        "results": results,
    }


def print_summary(data: dict) -> None:
    """Print human-readable summary."""
    s = data["summary"]
    print("=" * 72)
    print("RED-TEAM ADVERSARIAL CORPUS RESULTS")
    print("=" * 72)
    print(f"Total inputs:        {s['total_inputs']}")
    print(f"Positive cases:      {s['positive_total']}")
    print(f"  Detected:          {s['positive_detected']}")
    print(f"  Evaded:            {s['positive_evaded']}")
    print(f"Negative cases:      {s['negative_total']}")
    print(f"  True negatives:    {s['negative_total'] - s['false_positives']}")
    print(f"  False positives:   {s['false_positives']}")
    print(f"Detection rate:      {s['detection_rate']:.1%}")
    print(f"Evasion rate:        {s['evasion_rate']:.1%}")
    print(f"False positive rate: {s['false_positive_rate']:.1%}")
    print()

    # Category breakdown
    print("-" * 72)
    print(f"{'Category':<30} {'Inputs':>6} {'Evaded':>7} {'Rate':>8}")
    print("-" * 72)
    for cat, stats in sorted(data["category_stats"].items()):
        if stats["positive_total"] > 0:
            rate = stats["positive_evaded"] / stats["positive_total"]
            print(
                f"{cat:<30} {stats['positive_total']:>6} "
                f"{stats['positive_evaded']:>7} {rate:>7.0%}"
            )
        elif stats["negative_total"] > 0:
            fp = stats["false_positives"]
            print(
                f"{cat:<30} {stats['negative_total']:>6}    (neg) "
                f"{'FP=' + str(fp):>5}"
            )
    print()

    # Evaded inputs
    evaded = [r for r in data["results"] if r["status"] == "EVADED"]
    if evaded:
        print("-" * 72)
        print(f"EVADED INPUTS ({len(evaded)}):")
        print("-" * 72)
        for r in evaded:
            print(f"  [{r['category']}] {r['id']}: {r['description']}")

    # False positives
    fps = [r for r in data["results"] if r["status"] == "FALSE_POSITIVE"]
    if fps:
        print()
        print("-" * 72)
        print(f"FALSE POSITIVES ({len(fps)}):")
        print("-" * 72)
        for r in fps:
            print(f"  [{r['category']}] {r['id']}: {r['description']}")
            for f in r["finding_details"]:
                print(f"    -> {f['rule_id']}: {f['matched_text']}")


if __name__ == "__main__":
    data = run_corpus()

    # Save JSON results
    output_dir = Path(__file__).resolve().parent
    with open(output_dir / "results.json", "w") as f:
        json.dump(data, f, indent=2)

    # Save regression candidates
    evaded = [r for r in data["results"] if r["status"] == "EVADED"]
    with open(output_dir / "regression-candidates.txt", "w") as f:
        for r in evaded:
            f.write(f"[{r['category']}] {r['id']}: {r['description']}\n")

    print_summary(data)
