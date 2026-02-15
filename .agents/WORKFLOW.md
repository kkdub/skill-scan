# Skill-Scan Workflow

## Commands

Commands are installed at `~/.claude/commands/`. See the hub project's `.agent/WORKFLOW.md` for full documentation.

| Command | Purpose |
|---------|---------|
| `/plan "<title>"` | Create a new plan from template |
| `/run <id>` | Execute a plan as orchestrator |
| `/fix "<desc>"` | Quick single-agent fixes |
| `/verify [id]` | Reality-check implementation |
| `/save` | Checkpoint progress |
| `/precommit` | Fix pre-commit issues |
| `/pr "<title>"` | Create clean PR |

## Execution Model

Each plan part follows: implementer → test-writer → test-runner → refactorer → test-runner → verifier

## Key Rules for This Project

1. **Max 250 lines per file** in `src/` and `tests/`
2. Use `click` for CLI
3. Core scanner engine uses stdlib only (`re`, `pathlib`, `json`, `tomllib`)
4. Run `make check` before committing

## Plan Files

Plans live at `.agents/plans/`. Templates at `.agents/plans/templates/`.
