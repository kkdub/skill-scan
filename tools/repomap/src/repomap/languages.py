"""
Language detection and SCM query file mapping for RepoMap.
"""

from pathlib import Path

# Mapping of language names to their .scm query files
SCM_FILES = {
    "arduino": "arduino-tags.scm",
    "chatito": "chatito-tags.scm",
    "commonlisp": "commonlisp-tags.scm",
    "cpp": "cpp-tags.scm",
    "csharp": "csharp-tags.scm",
    "c": "c-tags.scm",
    "dart": "dart-tags.scm",
    "d": "d-tags.scm",
    "elisp": "elisp-tags.scm",
    "elixir": "elixir-tags.scm",
    "elm": "elm-tags.scm",
    "gleam": "gleam-tags.scm",
    "go": "go-tags.scm",
    "javascript": "javascript-tags.scm",
    "java": "java-tags.scm",
    "lua": "lua-tags.scm",
    "ocaml_interface": "ocaml_interface-tags.scm",
    "ocaml": "ocaml-tags.scm",
    "pony": "pony-tags.scm",
    "properties": "properties-tags.scm",
    "python": "python-tags.scm",
    "racket": "racket-tags.scm",
    "r": "r-tags.scm",
    "ruby": "ruby-tags.scm",
    "rust": "rust-tags.scm",
    "solidity": "solidity-tags.scm",
    "swift": "swift-tags.scm",
    "udev": "udev-tags.scm",
    "c_sharp": "c_sharp-tags.scm",
    "hcl": "hcl-tags.scm",
    "kotlin": "kotlin-tags.scm",
    "php": "php-tags.scm",
    "ql": "ql-tags.scm",
    "scala": "scala-tags.scm",
    "typescript": "typescript-tags.scm",
}

# Queries directory is inside the package
_QUERIES_DIR = Path(__file__).parent / "queries"


def get_scm_fname(lang: str) -> str | None:
    """Get the SCM query file path for a language.

    Args:
        lang: Language name as recognized by grep-ast.

    Returns:
        Absolute path to the .scm query file, or None if not found.
    """
    if lang not in SCM_FILES:
        return None

    scm_filename = SCM_FILES[lang]

    # Search in tree-sitter-language-pack first
    scm_path = _QUERIES_DIR / "tree-sitter-language-pack" / scm_filename
    if scm_path.exists():
        return str(scm_path)

    # Fall back to tree-sitter-languages
    scm_path = _QUERIES_DIR / "tree-sitter-languages" / scm_filename
    if scm_path.exists():
        return str(scm_path)

    return None
