# Debt — PLAN-012

Items are removed from this file as they are resolved. Check git history if needed.

## String-splitting evasion bypasses decoder extraction

- **Files**: `src/skill_scan/decoder.py:1-240`
- **Why not fixed**: Regex-based extraction cannot detect payloads split across multiple variables or string concatenations (e.g., `a = "aWdub3Jl"; b = "IHByZXZpb3Vz"`). Addressing this requires AST-level analysis, which is out of scope for a regex-only decoder module.
- **Resolution**: Add an AST-based extraction pass that traces string concatenation and variable assignment to reconstruct split payloads before decoding.
- **Target**: Future plan when evasion rate data justifies the complexity.

## Alternative encoding evasion (rot13, URL-encoding, unicode escapes)

- **Files**: `src/skill_scan/decoder.py:1-240`
- **Why not fixed**: PLAN-012 scope covers base64 and hex only. Adding rot13, URL-encoding, or unicode escape decoding requires additional extraction regexes and decode functions, expanding the module beyond its current scope.
- **Resolution**: Add `decode_rot13()`, `decode_url()`, and `decode_unicode_escape()` functions with corresponding extraction patterns. Each encoding type gets its own regex and decoder, following the existing pattern.
- **Target**: Future plan if red-team data shows these encodings used in real evasion attempts.

## `_depth` parameter on match_content() accessible to external callers

- **Files**: `src/skill_scan/rules/engine.py:113`
- **Why not fixed**: Python has no enforcement mechanism for keyword-only private parameters. The underscore prefix convention communicates intent. Making it truly private would require wrapping match_content() in a public function that delegates, adding complexity for marginal benefit.
- **Resolution**: If external misuse occurs, wrap match_content() in a public entry point that omits the depth parameter and delegates to an internal `_match_content_recursive()`.
- **Target**: Address if external callers misuse the parameter.
