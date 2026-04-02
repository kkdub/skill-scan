- [issue]: `patterns=[]` for `AGENT-006` will fail current validation unless additional files are changed outside `allowed_files`. `test_rules_have_patterns` only exempts `{"OBFS-001","EXFIL-008","EXEC-011","PI-030"}` in [tests/unit/test_rule_validation.py](/home/kkdub/skill-scan/tests/unit/test_rule_validation.py#L31), and the plan explicitly requires `[rules.AGENT-006] patterns=[]` in [plan.yaml](/home/kkdub/skill-scan/.agent/plans/041/plan.yaml#L135).

- [issue]: Updating `agent_manipulation.toml` without regenerating `RULES.md` will break CI, but `RULES.md` is missing from `allowed_files`. Freshness is enforced in [tests/unit/test_rule_validation.py](/home/kkdub/skill-scan/tests/unit/test_rule_validation.py#L74), and current catalog only contains `AGENT-001` in [RULES.md](/home/kkdub/skill-scan/RULES.md#L122).

- [issue]: The utilities audit contains an incorrect factual claim: plan says `agent_manipulation.toml — AGENT-001 stub + patterns=[]` in [plan.yaml](/home/kkdub/skill-scan/.agent/plans/041/plan.yaml#L30), but AGENT-001 is regex-based with non-empty patterns in [agent_manipulation.toml](/home/kkdub/skill-scan/src/skill_scan/rules/data/agent_manipulation.toml#L10). That weakens trust in the audit and likely missed dependencies.

- [issue]: Dispatch-order rationale is risky. Plan says run `(suppress_agent_findings, detect_compound_attack)` so AGENT-006 survives filtering in [plan.yaml](/home/kkdub/skill-scan/.agent/plans/041/plan.yaml#L160). In current engine, `_STRUCTURAL_DETECTORS` is a post-filter pass in [engine.py](/home/kkdub/skill-scan/src/skill_scan/rules/engine.py#L175). If AGENT-006 is appended after suppression, it bypasses existing agent-context suppression heuristics entirely, increasing doc/test false-positive risk.

- [issue]: Requirement coverage is incomplete for spec intent. Spec includes exfil chain variants such as “write to public location -> push” in [rules-to-build.md](/home/kkdub/skill-scan/.agent/roadmap/rules-to-build.md#L141), but planned tests focus mainly on URL POST and generic negatives in [plan.yaml](/home/kkdub/skill-scan/.agent/plans/041/plan.yaml#L260). You can pass acceptance while still breaking key chain variants.

- [question]: Should AGENT-006 be path-excluded for `tests?/` like AGENT-001, or intentionally scan test fixtures? This matters because AGENT-006 is structural (not regex-rule driven), and the plan doesn’t define path-exclusion behavior for it.

- [assumption]: [verified] — “No extra files beyond allowed list are needed” is false. CI contracts in [tests/unit/test_rule_validation.py](/home/kkdub/skill-scan/tests/unit/test_rule_validation.py#L31) and [tests/unit/test_rule_validation.py](/home/kkdub/skill-scan/tests/unit/test_rule_validation.py#L74) imply at least one of these must change: AST-only allowlist, `RULES.md`, or both.

- [assumption]: [unverified] — “Suppress-first then detect is correct long-term.” I verified the current dispatch order in [engine.py](/home/kkdub/skill-scan/src/skill_scan/rules/engine.py#L175), but cannot confirm without implementation/tests whether AGENT-006 false positives remain acceptable when it bypasses `suppress_agent_findings`.

- [claim from plan]: [confirmed by reading /home/kkdub/skill-scan/src/skill_scan/rules/engine.py] `_STRUCTURAL_DETECTORS` exists and currently contains `suppress_agent_findings` in [engine.py](/home/kkdub/skill-scan/src/skill_scan/rules/engine.py#L33).

- [claim from plan]: [confirmed by reading /home/kkdub/skill-scan/tests/unit/test_agent_manipulation_structural.py] Structural test precedent exists and already validates detector registration/dispatch patterns in [test_agent_manipulation_structural.py](/home/kkdub/skill-scan/tests/unit/test_agent_manipulation_structural.py#L53).

- [claim from plan]: [confirmed by reading /home/kkdub/skill-scan/src/skill_scan/_package_risk_correlations.py] Correlation logic precedent is table-driven in [\_package_risk_correlations.py](/home/kkdub/skill-scan/src/skill_scan/_package_risk_correlations.py#L12).

This plan is not ready to execute as written. The single biggest risk is integration failure despite “local part completion,” because mandatory repo-wide validation constraints (`test_rule_validation` and `RULES.md` freshness) are outside the allowed change surface, so `make check` is likely to fail even if detector code and new tests look correct.

## Verification Summary
Date: 2026-04-02
Plan: plan.yaml (PLAN-041)
Reviewer model: gpt-5.3-codex

| # | Finding | Verdict | Action |
|---|---------|---------|--------|
| 1 | patterns=[] fails test allowlist | valid | fixed: added test_rule_validation.py to allowed_files + step |
| 2 | RULES.md missing from allowed_files | valid | fixed: added RULES.md to allowed_files + regen step |
| 3 | Utilities audit says AGENT-001 has patterns=[] | valid | fixed: corrected audit text to reference OBFS-001/PI-030 |
| 4 | AGENT-006 bypasses agent-context suppression | valid | user decided: keep bypass (option A) |
| 5 | Spec exfil chain variant not tested | valid | fixed: added write-to-public+push test criterion |
| 6 | Path exclusion for tests?/ | question | user decided: no path exclusion |
| 7 | Extra files needed beyond allowed_files | assumption verified false | fixed: covered by findings 1 and 2 |
| 8 | Suppress-first ordering correct long-term | assumption unverified | user decided: keep current order (finding 4) |
| 9 | _STRUCTURAL_DETECTORS exists | verified claim | acknowledged |
| 10 | Structural test precedent exists | verified claim | acknowledged |
| 11 | Correlation logic is table-driven | verified claim | acknowledged |
