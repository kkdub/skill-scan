"""Tests for _ast_imports -- build_alias_map ast.Try recursion and star imports.

Covers build_alias_map walking imports inside try/except/else/finally blocks,
and star import expansion for known-dangerous modules.
"""

from __future__ import annotations

import ast
from pathlib import Path

from skill_scan._ast_imports import build_alias_map
from skill_scan.ast_analyzer import analyze_python

_FILE = "test.py"


# -- build_alias_map with ast.Try blocks --------------------------------------


class TestBuildAliasMapTry:
    def test_import_inside_try_body(self) -> None:
        code = "try:\n    import os\nexcept ImportError:\n    pass\n"
        tree = ast.parse(code)
        alias_map = build_alias_map(tree)
        assert alias_map == {"os": "os"}

    def test_from_import_inside_try_body(self) -> None:
        code = "try:\n    from subprocess import call as harmless_func\nexcept ImportError:\n    pass\n"
        tree = ast.parse(code)
        alias_map = build_alias_map(tree)
        assert alias_map == {"harmless_func": "subprocess.call"}

    def test_import_inside_except_handler(self) -> None:
        code = "try:\n    pass\nexcept ImportError:\n    import fallback as fb\n"
        tree = ast.parse(code)
        alias_map = build_alias_map(tree)
        assert alias_map == {"fb": "fallback"}

    def test_import_inside_else(self) -> None:
        code = "try:\n    pass\nexcept ImportError:\n    pass\nelse:\n    import extras\n"
        tree = ast.parse(code)
        alias_map = build_alias_map(tree)
        assert alias_map == {"extras": "extras"}

    def test_import_inside_finally(self) -> None:
        code = "try:\n    pass\nfinally:\n    import cleanup\n"
        tree = ast.parse(code)
        alias_map = build_alias_map(tree)
        assert alias_map == {"cleanup": "cleanup"}

    def test_imports_in_all_try_sections(self) -> None:
        code = (
            "try:\n"
            "    import a\n"
            "except Exception:\n"
            "    import b\n"
            "else:\n"
            "    import c\n"
            "finally:\n"
            "    import d\n"
        )
        tree = ast.parse(code)
        alias_map = build_alias_map(tree)
        assert alias_map == {"a": "a", "b": "b", "c": "c", "d": "d"}

    def test_nested_try_blocks(self) -> None:
        code = "try:\n    try:\n        from os import path\n    except:\n        pass\nexcept:\n    pass\n"
        tree = ast.parse(code)
        alias_map = build_alias_map(tree)
        assert alias_map == {"path": "os.path"}

    def test_mixed_toplevel_and_try_imports(self) -> None:
        code = "import os\ntry:\n    import sys\nexcept ImportError:\n    pass\n"
        tree = ast.parse(code)
        alias_map = build_alias_map(tree)
        assert alias_map == {"os": "os", "sys": "sys"}

    def test_function_inside_try_not_leaked(self) -> None:
        """Imports inside functions inside try should not leak."""
        code = "try:\n    def f():\n        import secret\nexcept:\n    pass\n"
        tree = ast.parse(code)
        alias_map = build_alias_map(tree)
        # The function-level import should not be in the alias map
        # because _collect_imports only recurses into ast.Try, not functions
        assert alias_map == {}

    def test_no_regression_plain_imports(self) -> None:
        """Existing plain import behavior still works."""
        code = "import codecs as c\nfrom os import path as p\n"
        tree = ast.parse(code)
        alias_map = build_alias_map(tree)
        assert alias_map == {"c": "codecs", "p": "os.path"}


# -- End-to-end: corpus try/except evasion pattern ----------------------------


class TestCorpusTryExceptEvasion:
    def test_try_except_evasion_produces_exec002(self) -> None:
        """Corpus: from subprocess import call as harmless_func inside try block."""
        code = (
            "try:\n"
            "    from subprocess import call as harmless_func\n"
            "except ImportError:\n"
            "    harmless_func = lambda *a: None\n"
            "harmless_func('echo pwned', shell=True)\n"
        )
        findings = analyze_python(code, _FILE)
        exec002 = [f for f in findings if f.rule_id == "EXEC-002"]
        assert len(exec002) >= 1

    def test_try_except_alias_resolves_subprocess(self) -> None:
        """Alias map resolves harmless_func -> subprocess.call inside try."""
        code = "try:\n    from subprocess import call as harmless_func\nexcept ImportError:\n    pass\n"
        tree = ast.parse(code)
        alias_map = build_alias_map(tree)
        assert alias_map["harmless_func"] == "subprocess.call"


# -- Star import expansion ---------------------------------------------------


class TestStarImportExpansion:
    """build_alias_map expands 'from X import *' for known-dangerous modules."""

    def test_from_os_star_expands_system(self) -> None:
        code = "from os import *\n"
        tree = ast.parse(code)
        alias_map = build_alias_map(tree)
        assert alias_map["system"] == "os.system"

    def test_from_os_star_expands_popen(self) -> None:
        code = "from os import *\n"
        tree = ast.parse(code)
        alias_map = build_alias_map(tree)
        assert alias_map["popen"] == "os.popen"

    def test_from_os_star_expands_exec_family(self) -> None:
        code = "from os import *\n"
        tree = ast.parse(code)
        alias_map = build_alias_map(tree)
        for name in ("execl", "execle", "execlp", "execv", "execve", "execvp", "execvpe"):
            assert alias_map[name] == f"os.{name}", f"Missing expansion for os.{name}"

    def test_from_os_star_expands_spawn_family(self) -> None:
        code = "from os import *\n"
        tree = ast.parse(code)
        alias_map = build_alias_map(tree)
        for name in ("spawnl", "spawnle", "spawnlp", "spawnlpe"):
            assert alias_map[name] == f"os.{name}", f"Missing expansion for os.{name}"

    def test_from_subprocess_star_expands_run(self) -> None:
        code = "from subprocess import *\n"
        tree = ast.parse(code)
        alias_map = build_alias_map(tree)
        assert alias_map["run"] == "subprocess.run"

    def test_from_subprocess_star_expands_all(self) -> None:
        code = "from subprocess import *\n"
        tree = ast.parse(code)
        alias_map = build_alias_map(tree)
        for name in ("run", "call", "check_output", "check_call", "Popen"):
            assert alias_map[name] == f"subprocess.{name}"

    def test_from_shutil_star_expands(self) -> None:
        code = "from shutil import *\n"
        tree = ast.parse(code)
        alias_map = build_alias_map(tree)
        for name in ("rmtree", "move", "copy", "copy2"):
            assert alias_map[name] == f"shutil.{name}"

    def test_unknown_module_star_no_expansion(self) -> None:
        """Star import of unknown module should not crash or expand."""
        code = "from mylib import *\n"
        tree = ast.parse(code)
        alias_map = build_alias_map(tree)
        assert alias_map == {}

    def test_explicit_import_still_works_alongside_star(self) -> None:
        """Explicit imports are not broken by star import expansion."""
        code = "from os import *\nimport subprocess as sp\n"
        tree = ast.parse(code)
        alias_map = build_alias_map(tree)
        assert alias_map["system"] == "os.system"
        assert alias_map["sp"] == "subprocess"

    def test_star_import_inside_try_block(self) -> None:
        """Star import inside try block should also expand."""
        code = "try:\n    from os import *\nexcept ImportError:\n    pass\n"
        tree = ast.parse(code)
        alias_map = build_alias_map(tree)
        assert alias_map["system"] == "os.system"

    def test_from_socket_star_expands_getaddrinfo(self) -> None:
        code = "from socket import *\n"
        tree = ast.parse(code)
        alias_map = build_alias_map(tree)
        assert alias_map["getaddrinfo"] == "socket.getaddrinfo"

    def test_from_socket_star_expands_all(self) -> None:
        code = "from socket import *\n"
        tree = ast.parse(code)
        alias_map = build_alias_map(tree)
        for name in ("getaddrinfo", "gethostbyname", "create_connection"):
            assert alias_map[name] == f"socket.{name}"


# -- End-to-end: star import evasion detection --------------------------------


class TestStarImportEvasionDetection:
    """Star import + bare call produces EXEC-002/EXEC-003 via analyze_python."""

    def test_from_os_star_system_call_detected(self) -> None:
        """R001: from os import *; system() must be detected."""
        code = "from os import *\nsystem('echo pwned')\n"
        findings = analyze_python(code, _FILE)
        exec_findings = [f for f in findings if f.rule_id in ("EXEC-002", "EXEC-003")]
        assert len(exec_findings) >= 1

    def test_from_subprocess_star_call_detected(self) -> None:
        code = "from subprocess import *\ncall('echo pwned', shell=True)\n"
        findings = analyze_python(code, _FILE)
        exec_findings = [f for f in findings if f.rule_id in ("EXEC-002", "EXEC-003")]
        assert len(exec_findings) >= 1


# -- Corpus: star_import_evasion.py ------------------------------------------


class TestCorpusStarImportEvasion:
    _CORPUS_PATH = (
        Path(__file__).resolve().parents[2]
        / "corpus"
        / "red-team"
        / "2026-03-17-full"
        / "exec-evasion"
        / "star_import_evasion.py"
    )

    def test_corpus_star_import_produces_exec_finding(self) -> None:
        assert self._CORPUS_PATH.exists(), f"Corpus file not found: {self._CORPUS_PATH}"
        content = self._CORPUS_PATH.read_text(encoding="utf-8")
        findings = analyze_python(content, str(self._CORPUS_PATH))
        exec_findings = [f for f in findings if f.rule_id in ("EXEC-002", "EXEC-003")]
        assert len(exec_findings) >= 1, (
            f"Expected EXEC-002 or EXEC-003 finding, got: {[f.rule_id for f in findings]}"
        )
