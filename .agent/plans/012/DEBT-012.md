# Debt — PLAN-012

Items are removed from this file as they are resolved. Check git history if needed.

## String-splitting evasion bypasses decoder extraction

- **Files**: `src/skill_scan/decoder.py`
- **Why not fixed**: Regex-based extraction cannot detect payloads split across multiple variables or string concatenations (e.g., `a = "aWdub3Jl"; b = "IHByZXZpb3Vz"`). PLAN-018 added AST-level detection for split evasion, but the decoder's own `extract_encoded_strings()` regex layer still operates on single contiguous strings. Class-level scope and cross-function dataflow remain out of scope.
- **Resolution**: Extend AST-level analysis for class-level scope and cross-function dataflow (Tier 2-4 from PLAN-018 red-team).
- **Target**: Future plan when evasion rate data justifies the complexity.
