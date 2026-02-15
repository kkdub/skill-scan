#!/usr/bin/env python3
"""Constants and data structures for architecture smell detection."""

from __future__ import annotations

from enum import Enum
from types import MappingProxyType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping


class Severity(Enum):
    """Severity level for detected smells.

    CRITICAL: Core domain/business logic - mixing here is a serious problem
    WARNING: Service layer - mixing should be reviewed
    INFO: Infrastructure/glue code - mixing is often acceptable
    """

    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


# Directories to always exclude from scanning
EXCLUDED_DIRS: frozenset[str] = frozenset(
    {
        "tests",
        "migrations",
        "fixtures",
        "generated",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
    }
)

# Severity mapping for file patterns (filename -> severity)
# Files not listed default to CRITICAL severity
FILE_SEVERITY: Mapping[str, Severity] = MappingProxyType(
    {
        # Glue layer files - INFO (acceptable mixing)
        "main.py": Severity.INFO,
        "app.py": Severity.INFO,
        "cli.py": Severity.INFO,
        "conftest.py": Severity.INFO,
        "routes.py": Severity.INFO,
        "handlers.py": Severity.INFO,
        "controllers.py": Severity.INFO,
        "endpoints.py": Severity.INFO,
        "lifespan.py": Severity.INFO,
        "dependencies.py": Severity.INFO,
        "setup.py": Severity.INFO,
        # MCP server entry points
        "server_multi_repo.py": Severity.INFO,
    }
)

# Severity mapping for directories (dirname -> severity)
# Directories not listed default to CRITICAL severity
DIR_SEVERITY: Mapping[str, Severity] = MappingProxyType(
    {
        # Infrastructure layer - INFO (acceptable mixing)
        "infrastructure": Severity.INFO,
        "adapters": Severity.INFO,
        "mcp_clients": Severity.INFO,
        "resilience": Severity.INFO,
        # API/presentation layer - WARNING (review mixing)
        "api": Severity.WARNING,
        "routes": Severity.WARNING,
        "handlers": Severity.WARNING,
        "controllers": Severity.WARNING,
        # Data access layer - WARNING (should separate query building from execution)
        "storage": Severity.WARNING,
        "db": Severity.WARNING,
        # Auth - WARNING (often has policy logic mixed with I/O)
        "auth": Severity.WARNING,
        # Scripts - INFO (CLI glue code)
        "scripts": Severity.INFO,
        # Infra directories in services - WARNING
        "infra": Severity.WARNING,
    }
)

# Legacy allowlist support (for backward compatibility)
# These are now INFO severity
ALLOWLIST_PATTERNS: frozenset[str] = frozenset(FILE_SEVERITY.keys())
ALLOWLIST_DIRS: frozenset[str] = frozenset(k for k, v in DIR_SEVERITY.items() if v == Severity.INFO)

# Infrastructure: actual I/O callsites (method calls)
# NOTE: "get" excluded from http - too many false positives with dict.get()
# HTTP detection relies on object name patterns instead
# Using MappingProxyType + frozenset for immutability
INFRA_CALLS: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        "db": frozenset(
            {
                # SQLAlchemy
                "execute",
                "scalar",
                "scalars",
                "add",
                "delete",
                "commit",
                "rollback",
                "flush",
                "refresh",
                "merge",
                "begin",
                "close",
                # Raw DB
                "cursor",
                "fetchone",
                "fetchall",
                "fetchmany",
            }
        ),
        "http": frozenset(
            {
                # requests/httpx/aiohttp - explicit HTTP verbs only
                "post",
                "put",
                "patch",
                "head",
                "options",
                "request",
                "send",
                "fetch",
                # aiohttp specific
                "get_json",
                "post_json",
            }
        ),
        "filesystem": frozenset(
            {
                # Path methods
                "read_text",
                "read_bytes",
                "write_text",
                "write_bytes",
                "mkdir",
                "rmdir",
                "unlink",
                "rename",
                "replace",
                "iterdir",
                "glob",
                "rglob",
            }
        ),
        "env": frozenset(
            {
                # os.environ access
                "getenv",
            }
        ),
        "logging": frozenset(
            {
                # structlog / logging methods - these ARE side effects
                "info",
                "debug",
                "warning",
                "error",
                "exception",
                "critical",
                "fatal",
                "warn",
                "msg",  # structlog
                "bind",  # structlog context binding
            }
        ),
        "time": frozenset(
            {
                # Time/clock access - non-deterministic I/O
                "now",
                "utcnow",
                "today",
                "time",
                "monotonic",
                "perf_counter",
                "sleep",
            }
        ),
        "random": frozenset(
            {
                # Random/non-deterministic operations
                "random",
                "randint",
                "randrange",
                "choice",
                "choices",
                "shuffle",
                "sample",
                "uniform",
                "gauss",
                # secrets module
                "token_hex",
                "token_bytes",
                "token_urlsafe",
                "randbits",
            }
        ),
        "subprocess": frozenset(
            {
                # Process execution
                "run",
                "call",
                "check_call",
                "check_output",
                "Popen",
                "communicate",
            }
        ),
    }
)

# Infrastructure: objects that indicate I/O context
# Using MappingProxyType + frozenset for immutability
INFRA_OBJECTS: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        "db": frozenset(
            {
                "session",
                "Session",
                "engine",
                "Engine",
                "connection",
                "Connection",
                "cursor",
            }
        ),
        "http": frozenset({"client", "Client", "AsyncClient", "httpx", "requests", "aiohttp"}),
        "filesystem": frozenset({"Path", "pathlib"}),
        "env": frozenset({"os", "environ", "dotenv"}),
        "logging": frozenset({"logger", "log", "logging", "structlog", "_logger", "_log"}),
        "time": frozenset({"datetime", "time", "date", "timedelta"}),
        "random": frozenset({"random", "secrets", "Random", "SystemRandom"}),
        "subprocess": frozenset({"subprocess", "Popen", "process"}),
    }
)


# Decision logic: functions that indicate boolean/conditional logic
# Used to detect hidden decision logic in function calls
DECISION_FUNCTIONS: frozenset[str] = frozenset(
    {
        "any",
        "all",
        "filter",
        "isinstance",
        "issubclass",
        "hasattr",
        "callable",
        "bool",
    }
)
