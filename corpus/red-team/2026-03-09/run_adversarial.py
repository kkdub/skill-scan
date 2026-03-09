"""Adversarial corpus runner for ast_analyzer.analyze_python().

Runs each adversarial input through the analyzer, checks whether it was
detected, and reports evasion rates by category.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Add project src to path
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))

from skill_scan.ast_analyzer import analyze_python

_FILE = "adversarial_test.py"


def _detected(code: str, rule_ids: set[str] | None = None) -> bool:
    """Return True if analyze_python produces any finding for code."""
    findings = analyze_python(code, _FILE)
    if rule_ids:
        findings = [f for f in findings if f.rule_id in rule_ids]
    return len(findings) > 0


def _detected_any(code: str) -> bool:
    """Return True if any finding at all is produced."""
    return len(analyze_python(code, _FILE)) > 0


# ============================================================================
# ADVERSARIAL CORPUS
# ============================================================================
# Each entry: (category, id, code, should_detect, description)
# should_detect=True  -> evasion test (tool SHOULD detect, evasion if it misses)
# should_detect=False -> false positive test (tool should NOT detect)

CORPUS: list[tuple[str, str, str, bool, str]] = []


# ---------------------------------------------------------------------------
# Category 1: String construction evasion (novel methods)
# ---------------------------------------------------------------------------

# 1a: format() method
CORPUS.append((
    "string-construction",
    "format-method-eval",
    "x = '{}{}'.format('ev', 'al')\n",
    True,
    "str.format() building 'eval'",
))

CORPUS.append((
    "string-construction",
    "format-method-exec",
    "x = '{0}{1}'.format('ex', 'ec')\n",
    True,
    "str.format() with positional args building 'exec'",
))

# 1b: f-string
CORPUS.append((
    "string-construction",
    "fstring-eval",
    "a = 'ev'; b = 'al'; x = f'{a}{b}'\n",
    True,
    "f-string building 'eval' from variables",
))

# 1c: % formatting
CORPUS.append((
    "string-construction",
    "percent-format-eval",
    "x = '%s%s' % ('ev', 'al')\n",
    True,
    "%-formatting building 'eval'",
))

# 1d: bytes decode
CORPUS.append((
    "string-construction",
    "bytes-decode-eval",
    "x = b'eval'.decode('utf-8')\n",
    True,
    "bytes.decode() producing 'eval'",
))

CORPUS.append((
    "string-construction",
    "bytes-decode-exec",
    "x = b'exec'.decode()\n",
    True,
    "bytes.decode() producing 'exec'",
))

# 1e: bytearray decode
CORPUS.append((
    "string-construction",
    "bytearray-eval",
    "x = bytearray(b'eval').decode()\n",
    True,
    "bytearray.decode() producing 'eval'",
))

# 1f: codecs.decode
CORPUS.append((
    "string-construction",
    "codecs-decode-eval",
    "import codecs\nx = codecs.decode(b'eval', 'utf-8')\n",
    True,
    "codecs.decode() producing 'eval'",
))

# 1g: str() constructor
CORPUS.append((
    "string-construction",
    "str-constructor-eval",
    "x = str(b'eval', 'utf-8')\n",
    True,
    "str() constructor from bytes producing 'eval'",
))

# 1h: reversed + join
CORPUS.append((
    "string-construction",
    "reversed-join-eval",
    "x = ''.join(reversed('lave'))\n",
    True,
    "reversed() + join building 'eval'",
))

# 1i: list comprehension in join
CORPUS.append((
    "string-construction",
    "listcomp-join-eval",
    "x = ''.join([chr(c) for c in [101, 118, 97, 108]])\n",
    True,
    "List comprehension with chr() in join building 'eval'",
))

# 1j: map + chr + join
CORPUS.append((
    "string-construction",
    "map-chr-join-eval",
    "x = ''.join(map(chr, [101, 118, 97, 108]))\n",
    True,
    "map(chr, ...) + join building 'eval'",
))

# 1k: nested chr building
CORPUS.append((
    "string-construction",
    "nested-chr-ord",
    "x = chr(ord('e')) + chr(ord('v')) + chr(ord('a')) + chr(ord('l'))\n",
    True,
    "chr(ord(...)) nesting building 'eval'",
))

# 1l: string multiplication + slice
CORPUS.append((
    "string-construction",
    "slice-evasion",
    "x = 'xxevalxx'[2:6]\n",
    True,
    "String slicing to extract 'eval'",
))

# 1m: replace to build
CORPUS.append((
    "string-construction",
    "replace-build",
    "x = 'xvxl'.replace('x', 'ea'[:1]).replace('x', 'ea'[1:])\n",
    True,
    "String replace building 'eval'",
))

# 1n: tuple join
CORPUS.append((
    "string-construction",
    "tuple-join-eval",
    "x = ''.join(('e', 'v', 'a', 'l'))\n",
    True,
    "Tuple in join building 'eval' (should work, tuple is handled)",
))

# 1o: generator expression in join
CORPUS.append((
    "string-construction",
    "genexpr-join-eval",
    "x = ''.join(chr(c) for c in [101, 118, 97, 108])\n",
    True,
    "Generator expression with chr() in join building 'eval'",
))

# 1p: base64 decode
CORPUS.append((
    "string-construction",
    "base64-decode-eval",
    "import base64\nx = base64.b64decode(b'ZXZhbA==').decode()\n",
    True,
    "base64 decode producing 'eval'",
))

# 1q: hex decode
CORPUS.append((
    "string-construction",
    "hex-decode-eval",
    "x = bytes.fromhex('6576616c').decode()\n",
    True,
    "bytes.fromhex() producing 'eval'",
))


# ---------------------------------------------------------------------------
# Category 2: Indirect call patterns
# ---------------------------------------------------------------------------

# 2a: Alias eval
CORPUS.append((
    "indirect-calls",
    "alias-eval",
    "e = eval\ne('1+1')\n",
    True,
    "Aliasing eval to variable then calling",
))

# 2b: Alias via getattr from builtins
CORPUS.append((
    "indirect-calls",
    "getattr-builtins-eval",
    "e = getattr(__builtins__, 'eval')\ne('1+1')\n",
    True,
    "getattr(__builtins__, 'eval') - plain string, no concat",
))

# 2c: vars() access
CORPUS.append((
    "indirect-calls",
    "vars-builtins-eval",
    "x = vars(__builtins__)['eval']('1+1')\n",
    True,
    "vars(__builtins__)['eval'] dynamic access",
))

# 2d: globals() access
CORPUS.append((
    "indirect-calls",
    "globals-eval",
    "globals()['__builtins__']['eval']('1+1')\n",
    True,
    "globals() chain to eval",
))

# 2e: __dict__ access
CORPUS.append((
    "indirect-calls",
    "dict-access-eval",
    "import os\nos.__dict__['system']('ls')\n",
    True,
    "__dict__ access bypassing attribute detection",
))

# 2f: functools.reduce for building string
CORPUS.append((
    "indirect-calls",
    "reduce-concat",
    "import functools\nx = functools.reduce(lambda a,b: a+b, ['ev','al'])\n",
    True,
    "functools.reduce to concatenate string",
))

# 2g: operator.add for building string
CORPUS.append((
    "indirect-calls",
    "operator-add-concat",
    "import operator\nx = operator.add('ev', 'al')\n",
    True,
    "operator.add() to concatenate string",
))

# 2h: nested getattr
CORPUS.append((
    "indirect-calls",
    "nested-getattr",
    "getattr(getattr(__builtins__, '__im' + 'port__')('os'), 'sys' + 'tem')('ls')\n",
    True,
    "Nested getattr with concat",
))

# 2i: type() metaclass trick
CORPUS.append((
    "indirect-calls",
    "type-call-exec",
    "type('X', (), {'__init__': lambda s: exec('import os')})()\n",
    True,
    "type() metaclass with exec in lambda",
))

# 2j: compile + exec
CORPUS.append((
    "indirect-calls",
    "compile-exec",
    "exec(compile('import os', '<string>', 'exec'))\n",
    True,
    "compile() + exec() combination",
))


# ---------------------------------------------------------------------------
# Category 3: Deep attribute chains / module aliasing
# ---------------------------------------------------------------------------

# 3a: Deep dotted call (a.b.c.d())
CORPUS.append((
    "module-aliasing",
    "deep-dotted-pickle",
    "import _pickle\n_pickle.loads(data)\n",
    True,
    "_pickle (C implementation alias) loads",
))

# 3b: from-import aliasing
CORPUS.append((
    "module-aliasing",
    "from-import-loads",
    "from pickle import loads\nloads(data)\n",
    True,
    "from pickle import loads - direct name call",
))

# 3c: as aliasing
CORPUS.append((
    "module-aliasing",
    "import-as-alias",
    "import pickle as p\np.loads(data)\n",
    True,
    "import pickle as p; p.loads()",
))

# 3d: from-import eval
CORPUS.append((
    "module-aliasing",
    "from-builtins-eval",
    "from builtins import eval as e\ne('1+1')\n",
    True,
    "from builtins import eval as e",
))

# 3e: sys.modules trick
CORPUS.append((
    "module-aliasing",
    "sys-modules-os",
    "import sys\nsys.modules['os'].system('ls')\n",
    True,
    "sys.modules['os'].system() bypass",
))

# 3f: importlib aliased
CORPUS.append((
    "module-aliasing",
    "importlib-alias",
    "import importlib as il\nil.import_module('os')\n",
    True,
    "importlib aliased then import_module",
))


# ---------------------------------------------------------------------------
# Category 4: Obfuscation layers (multiple indirection levels)
# ---------------------------------------------------------------------------

# 4a: chr + getattr + call
CORPUS.append((
    "obfuscation-layers",
    "chr-getattr-call",
    "getattr(__builtins__, chr(101)+chr(118)+chr(97)+chr(108))('1+1')\n",
    True,
    "chr()-built 'eval' in getattr then called",
))

# 4b: join + getattr + import
CORPUS.append((
    "obfuscation-layers",
    "join-getattr-import",
    "getattr(__builtins__, ''.join(['__','im','po','rt','__']))('os')\n",
    True,
    "join-built '__import__' in getattr",
))

# 4c: double encoding via chr(ord())
CORPUS.append((
    "obfuscation-layers",
    "double-indirection-chr",
    "x = chr(51+50) + chr(60+58) + chr(48+49) + chr(54+54)\n",
    True,
    "chr() with arithmetic expressions (not plain int constants)",
))

# 4d: lambda wrapper
CORPUS.append((
    "obfuscation-layers",
    "lambda-eval",
    "f = lambda code: eval(code)\nf('1+1')\n",
    True,
    "eval() inside lambda (should detect the eval call itself)",
))

# 4e: exec with string concat
CORPUS.append((
    "obfuscation-layers",
    "exec-concat-payload",
    "exec('imp' + 'ort os; os.sys' + 'tem(\"ls\")')\n",
    True,
    "exec() with concatenated payload string",
))

# 4f: triple layer: join -> getattr -> call
CORPUS.append((
    "obfuscation-layers",
    "triple-layer",
    "fn = getattr(__builtins__, ''.join([chr(101),chr(118),chr(97),chr(108)]))\nfn('1+1')\n",
    True,
    "Triple: chr->join->getattr building eval",
))


# ---------------------------------------------------------------------------
# Category 5: subprocess / os evasions
# ---------------------------------------------------------------------------

# 5a: os.popen
CORPUS.append((
    "os-subprocess-evasion",
    "os-popen",
    "import os\nos.popen('ls')\n",
    True,
    "os.popen() -- not in the direct detection list?",
))

# 5b: subprocess.call with shell=True
CORPUS.append((
    "os-subprocess-evasion",
    "subprocess-call-shell",
    "import subprocess\nsubprocess.call('ls', shell=True)\n",
    True,
    "subprocess.call with shell=True",
))

# 5c: subprocess.Popen with shell=True
CORPUS.append((
    "os-subprocess-evasion",
    "subprocess-popen-shell",
    "import subprocess\nsubprocess.Popen('ls', shell=True)\n",
    True,
    "subprocess.Popen with shell=True",
))

# 5d: subprocess.check_output with shell=True
CORPUS.append((
    "os-subprocess-evasion",
    "subprocess-check-output-shell",
    "import subprocess\nsubprocess.check_output('ls', shell=True)\n",
    True,
    "subprocess.check_output with shell=True",
))

# 5e: os.execv family
CORPUS.append((
    "os-subprocess-evasion",
    "os-execv",
    "import os\nos.execv('/bin/sh', ['/bin/sh', '-c', 'ls'])\n",
    True,
    "os.execv() family",
))

# 5f: os.spawn*
CORPUS.append((
    "os-subprocess-evasion",
    "os-spawnl",
    "import os\nos.spawnl(os.P_WAIT, '/bin/sh', 'sh', '-c', 'ls')\n",
    True,
    "os.spawnl() family",
))

# 5g: shell=True via variable (not literal)
CORPUS.append((
    "os-subprocess-evasion",
    "subprocess-shell-variable",
    "import subprocess\nshell_flag = True\nsubprocess.run('ls', shell=shell_flag)\n",
    True,
    "shell=<variable> instead of shell=True literal",
))

# 5h: subprocess.run with **kwargs
CORPUS.append((
    "os-subprocess-evasion",
    "subprocess-kwargs",
    "import subprocess\nopts = {'shell': True}\nsubprocess.run('ls', **opts)\n",
    True,
    "shell=True hidden in **kwargs",
))


# ---------------------------------------------------------------------------
# Category 6: Deserialization evasions
# ---------------------------------------------------------------------------

# 6a: shelve (uses pickle internally)
CORPUS.append((
    "deserialization-evasion",
    "shelve-open",
    "import shelve\ndb = shelve.open('data')\n",
    True,
    "shelve.open() uses pickle internally",
))

# 6b: yaml.load with FullLoader (still unsafe for untrusted)
CORPUS.append((
    "deserialization-evasion",
    "yaml-fullloader",
    "import yaml\nyaml.load(data, Loader=yaml.FullLoader)\n",
    True,
    "yaml.load with FullLoader (not SafeLoader)",
))

# 6c: yaml.unsafe_load
CORPUS.append((
    "deserialization-evasion",
    "yaml-unsafe-load",
    "import yaml\nyaml.unsafe_load(data)\n",
    True,
    "yaml.unsafe_load() explicitly unsafe",
))

# 6d: pickle via cloudpickle
CORPUS.append((
    "deserialization-evasion",
    "cloudpickle-loads",
    "import cloudpickle\ncloudpickle.loads(data)\n",
    True,
    "cloudpickle.loads() (pickle-based)",
))

# 6e: dill.loads
CORPUS.append((
    "deserialization-evasion",
    "dill-loads",
    "import dill\ndill.loads(data)\n",
    True,
    "dill.loads() (pickle-based)",
))

# 6f: pickle via from-import
CORPUS.append((
    "deserialization-evasion",
    "from-pickle-loads",
    "from pickle import loads\nloads(data)\n",
    True,
    "from pickle import loads - bare function call",
))

# 6g: yaml.load with positional SafeLoader (not keyword)
CORPUS.append((
    "false-positives",
    "yaml-positional-safeloader",
    "import yaml\nyaml.load(data, yaml.SafeLoader)\n",
    False,
    "yaml.load with positional SafeLoader (safe -- should not flag)",
))


# ---------------------------------------------------------------------------
# Category 7: False positive tests (should NOT detect)
# ---------------------------------------------------------------------------

CORPUS.append((
    "false-positives",
    "safe-string-concat-hello",
    "x = 'hello' + ' world'\n",
    False,
    "Safe string concatenation",
))

CORPUS.append((
    "false-positives",
    "safe-join-abc",
    "x = ''.join(['a', 'b', 'c'])\n",
    False,
    "Safe join of innocuous strings",
))

CORPUS.append((
    "false-positives",
    "safe-chr-building",
    "x = chr(65) + chr(66) + chr(67)\n",
    False,
    "chr() building 'ABC' (not dangerous)",
))

CORPUS.append((
    "false-positives",
    "safe-getattr-name",
    "x = getattr(obj, 'name')\n",
    False,
    "Safe getattr with innocuous attribute",
))

CORPUS.append((
    "false-positives",
    "safe-literal-eval",
    "import ast\nresult = ast.literal_eval('[1,2,3]')\n",
    False,
    "ast.literal_eval is safe, should not flag",
))

CORPUS.append((
    "false-positives",
    "safe-yaml-safe-load",
    "import yaml\ndata = yaml.safe_load(content)\n",
    False,
    "yaml.safe_load is safe",
))

CORPUS.append((
    "false-positives",
    "safe-subprocess-no-shell",
    "import subprocess\nsubprocess.run(['ls', '-la'])\n",
    False,
    "subprocess without shell=True",
))

CORPUS.append((
    "false-positives",
    "safe-subprocess-shell-false",
    "import subprocess\nsubprocess.run(['ls'], shell=False)\n",
    False,
    "subprocess with shell=False",
))

CORPUS.append((
    "false-positives",
    "safe-json-loads",
    "import json\ndata = json.loads(text)\n",
    False,
    "json.loads is safe",
))

CORPUS.append((
    "false-positives",
    "safe-string-eval-word",
    "x = 'evaluation_metric'\n",
    False,
    "String containing 'eval' as substring should not flag",
))

CORPUS.append((
    "false-positives",
    "safe-function-named-evaluate",
    "def evaluate(model): return model.score()\n",
    False,
    "Function named 'evaluate' should not flag",
))

CORPUS.append((
    "false-positives",
    "safe-class-named-executor",
    "class Executor:\n    def execute(self): pass\n",
    False,
    "Class named 'Executor' should not flag",
))

CORPUS.append((
    "false-positives",
    "safe-comment-eval",
    "# eval() is dangerous, never use it\nx = 1\n",
    False,
    "Comment mentioning eval should not flag",
))

CORPUS.append((
    "false-positives",
    "safe-string-system",
    "x = 'system' + '_config'\n",
    False,
    "Building 'system_config' should not flag (dangerous prefix but safe result)",
))

CORPUS.append((
    "false-positives",
    "safe-getattr-system-info",
    "getattr(obj, 'system_info')\n",
    False,
    "getattr with 'system_info' -- contains 'system' but not exact match",
))

CORPUS.append((
    "false-positives",
    "safe-join-evaluation",
    "x = ''.join(['e', 'v', 'a', 'l', 'u', 'a', 't', 'i', 'o', 'n'])\n",
    False,
    "Join building 'evaluation' (not 'eval')",
))


# ---------------------------------------------------------------------------
# Category 8: Edge cases / crash resistance
# ---------------------------------------------------------------------------

CORPUS.append((
    "edge-cases",
    "empty-string",
    "",
    False,
    "Empty input should not crash or produce findings",
))

CORPUS.append((
    "edge-cases",
    "syntax-error",
    "def foo(\n",
    False,
    "Syntax error should return empty list",
))

CORPUS.append((
    "edge-cases",
    "very-deep-nesting",
    "x = " + " + ".join(["'e'", "'v'", "'a'", "'l'"]) * 50 + "\n",
    False,  # May or may not detect, but should not crash
    "Very deep nesting -- should not crash",
))

CORPUS.append((
    "edge-cases",
    "unicode-identifiers",
    "\u0435val('1+1')\n",  # Cyrillic 'e' (U+0435) + val
    False,  # Not actually eval, different character
    "Unicode homoglyph for 'eval' (Cyrillic e) -- should NOT flag as eval",
))

CORPUS.append((
    "edge-cases",
    "null-bytes",
    "x = 'ev' + '\\x00' + 'al'\n",
    False,
    "String with null byte is not 'eval'",
))

CORPUS.append((
    "edge-cases",
    "very-long-string-concat",
    "x = " + " + ".join([f"'{c}'" for c in "eval" * 100]) + "\n",
    False,  # Should not crash; result is 'evaleval...' not in dangerous names
    "Very long repeated concat -- should not crash",
))

CORPUS.append((
    "edge-cases",
    "multiline-concat",
    "x = ('ev'\n     'al')\n",
    True,
    "Implicit string concat across lines (Python auto-concat)",
))

CORPUS.append((
    "edge-cases",
    "walrus-operator",
    "if (x := eval('1+1')): pass\n",
    True,
    "eval inside walrus operator",
))

CORPUS.append((
    "edge-cases",
    "decorator-eval",
    "@eval\ndef foo(): pass\n",
    True,
    "eval used as decorator",
))

CORPUS.append((
    "edge-cases",
    "star-import-exec",
    "exec('from os import *')\n",
    True,
    "exec() with import star payload",
))


# ============================================================================
# RUNNER
# ============================================================================

def run_corpus():
    """Execute corpus and collect results."""
    results = []
    crashes = []

    for category, test_id, code, should_detect, description in CORPUS:
        try:
            findings = analyze_python(code, _FILE)
            detected = len(findings) > 0

            if should_detect:
                # Evasion test: should detect but missed = evasion
                evaded = not detected
                status = "EVADED" if evaded else "DETECTED"
            else:
                # False positive test: should not detect but did = FP
                evaded = detected
                status = "FALSE_POSITIVE" if evaded else "CLEAN"

            results.append({
                "category": category,
                "id": test_id,
                "code": code.strip()[:120],
                "should_detect": should_detect,
                "detected": detected,
                "evaded": evaded,
                "status": status,
                "description": description,
                "findings": [f.rule_id for f in findings],
            })
        except Exception as e:
            crashes.append({
                "category": category,
                "id": test_id,
                "error": str(e),
                "description": description,
            })
            results.append({
                "category": category,
                "id": test_id,
                "code": code.strip()[:120],
                "should_detect": should_detect,
                "detected": False,
                "evaded": True,
                "status": "CRASHED",
                "description": description,
                "findings": [],
            })

    return results, crashes


def print_report(results, crashes):
    """Print formatted report."""
    # Group by category
    categories = {}
    for r in results:
        cat = r["category"]
        if cat not in categories:
            categories[cat] = {"total": 0, "evaded": 0, "items": []}
        categories[cat]["total"] += 1
        if r["evaded"]:
            categories[cat]["evaded"] += 1
        categories[cat]["items"].append(r)

    total = len(results)
    total_evaded = sum(1 for r in results if r["evaded"])

    print("=" * 72)
    print("ADVERSARIAL CORPUS RESULTS")
    print("=" * 72)
    print(f"Total inputs: {total}")
    print(f"Total evasions/failures: {total_evaded}")
    print(f"Overall evasion rate: {total_evaded/total*100:.1f}%")
    print()

    # Per-category table
    print(f"{'Category':<30} {'Total':>6} {'Evaded':>7} {'Rate':>7}")
    print("-" * 54)
    for cat, data in sorted(categories.items()):
        rate = data["evaded"] / data["total"] * 100 if data["total"] else 0
        print(f"{cat:<30} {data['total']:>6} {data['evaded']:>7} {rate:>6.1f}%")
    print("-" * 54)
    print(f"{'TOTAL':<30} {total:>6} {total_evaded:>7} {total_evaded/total*100:>6.1f}%")
    print()

    # Evasion details
    evasions = [r for r in results if r["evaded"]]
    if evasions:
        print("EVASION DETAILS:")
        print("-" * 72)
        for r in evasions:
            print(f"  [{r['status']}] {r['id']}")
            print(f"    Category: {r['category']}")
            print(f"    Description: {r['description']}")
            print(f"    Code: {r['code']}")
            if r["findings"]:
                print(f"    Unexpected findings: {r['findings']}")
            print()

    # Crashes
    if crashes:
        print("CRASHES:")
        print("-" * 72)
        for c in crashes:
            print(f"  {c['id']}: {c['error']}")
        print()

    # Save JSON results
    out_dir = Path(__file__).parent
    with open(out_dir / "results.json", "w") as f:
        json.dump({"results": results, "crashes": crashes}, f, indent=2)
    print(f"Full results saved to: {out_dir / 'results.json'}")

    # Save regression candidates
    regression = [r for r in results if r["evaded"] and r["should_detect"]]
    if regression:
        with open(out_dir / "regression-candidates.txt", "w") as f:
            for r in regression:
                f.write(f"# {r['id']}: {r['description']}\n")
                f.write(f"# Category: {r['category']}\n")
                f.write(f"{r['code']}\n\n")
        print(f"Regression candidates saved to: {out_dir / 'regression-candidates.txt'}")

    return total_evaded, total


if __name__ == "__main__":
    results, crashes = run_corpus()
    evaded, total = print_report(results, crashes)
    sys.exit(1 if evaded > 0 else 0)
