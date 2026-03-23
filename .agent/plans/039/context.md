# Plan Context

Accumulated knowledge across sessions. Updated by /run at session end.

Entry format: `- [ISO-timestamp] (part-ref) content`

## Decisions

- [2026-03-23T12:00:00Z] (part-a) Used Finding() directly instead of _make_finding since _ast_detectors.py is frozen at 349/350 lines
- [2026-03-23T12:00:00Z] (part-a) Non-dangerous dunders (e.g., __init__) treated as transparent bridges in chain walking — real exploits chain __init__.__globals__

## Learnings

- [2026-03-23T12:00:00Z] (part-a) Inner chain nodes need dedup via _dunder_inner marker attribute to prevent overlapping findings from ast.walk visiting same chain at multiple depths
- [2026-03-23T12:00:00Z] (part-a) Module ended at 153 lines — well under 350 limit

## Completion

- [2026-03-23T13:00:00Z] (docs) CLAUDE.md updated: _ast_dunder_chain_detector.py in Project Structure, test_dunder_chain_detector.py in tests, MRO_WALK_DUNDERS/EXEC_ESCAPE_DUNDERS/detect_dunder_chain arch notes, 4 invariants, line count in Known debt. Plan status set to Done. handoff.yaml finalized.

## Blockers

<!-- Record issues that stopped or slowed execution and their resolutions.
     Example: - [2026-03-20T15:00:00Z] (part-c) RESOLVED: Import error caused by missing __init__.py -->
