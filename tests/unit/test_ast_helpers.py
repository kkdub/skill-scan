"""Tests for _ast_helpers -- build_alias_map ast.Try recursion.

Covers build_alias_map walking imports inside try/except/else/finally blocks.
"""

from __future__ import annotations

import ast

from skill_scan._ast_helpers import build_alias_map
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
