
  1. DEBT-018-T2-CONTAINERS not fully covered — Debt includes both dicts and lists (parts[0]='ev'), but Part (d) narrows to
  string-key subscripts/dict literals only. List index cases excluded.
  2. R-IMP006 verify path broken — Points to tests/unit/test_split_evasion_fixtures.py which does not exist. Actual file is
  tests/unit/test_evasion_corpus.py.
  3. Scope vs completion conflict — Plan requires debt items be removable from debt.yaml, but debt.yaml is not in
  allowed_files.
  4. Stale forbidden path — src/skill_scan/engine.py doesn't exist; actual engine is at src/skill_scan/rules/engine.py.
  5. Stop condition weaker than acceptance criteria — Doesn't require tests or acceptance scenarios to pass.
  6. Part (f) hidden dependency — Plan says to use get_call_name() for alias resolution, but alias_map isn't threaded into
  _resolve_join_call().
  7. map(chr) acceptance can false-pass — Direct exec(payload) already triggers EXEC-002 via unsafe-call detector, masking
  whether join reconstruction actually works.
  8. Mixed %-specifier under-specified — Proposed regex ignores width/precision/flags, and _substitute_percent() still does
  %s-only replacement.
  9. Part (e) depends on (d) unnecessarily — String-multiply is independent of dict tracking; reduces parallelism.

  Questions

  - Should DEBT-018-T2-CONTAINERS also close list indices (parts[0]) or defer to a later plan?
  - Should acceptance checks assert split-detector evidence (description text) rather than generic EXEC-002 presence?

  Verified Assumptions

  - Fixture auto-discovery picks up new pos_*.py files automatically
  - _ast_symbol_table.py at 244/250 lines — extraction mandatory
  - Build environment claims (pyproject, Makefile, uv) accurate
  - Line-count audit accurate for all 3 core files
  - Reusable helpers exist as claimed
  - build_symbol_table re-exported from facade

  Unverified Assumptions

  - Extracting helpers while keeping _Ref in _ast_symbol_table.py can be done without circular-import issues — plan doesn't
  describe import boundary strategy

  Assessment

  Plan is not ready to execute as-is. Biggest risk: it claims full closure of container debt while scoping to string-key dict
  paths only, which leaves list-index evasions unresolved while appearing "green" due to weak acceptance checks and
  scope/stop-condition contradictions.
