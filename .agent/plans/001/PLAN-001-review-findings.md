# PLAN-001 Review Findings

Post-implementation findings from architecture and security reviews (2026-02-15).
All items are non-blocking — MVP is complete and functional.

---

## Security Findings

### [MEDIUM] No per-pattern regex timeout — DEFERRED

- **File:** `src/skill_scan/rules/engine.py` (`match_line`)
- **Status:** Deferred (stdlib limitation)
- **Risk:** No defense-in-depth against ReDoS from future rule patterns. Current
  PI-001 through PI-006 patterns are safe (tested), but new rules could introduce
  vulnerable patterns. The `max_file_size` limit (500KB) bounds input but a single
  long line matched against a vulnerable regex could still hang.
- **Note:** Python stdlib `re` module does not support a `timeout` parameter on
  `re.compile()` or `re.search()`. Would require the third-party `regex` package,
  which conflicts with the stdlib-only constraint. Current mitigations (bounded
  input via `max_file_size`, vetted built-in patterns) are sufficient for MVP.


### [LOW] Path disclosure in error messages

- **Files:** `src/skill_scan/parser.py:38`, `src/skill_scan/_fetchers.py:47,49`
- **Status:** Accepted (CLI-only tool)
- **Risk:** Full filesystem paths in error messages. Fine for CLI, would need
  sanitization if the tool is ever wrapped in a web API.
---

