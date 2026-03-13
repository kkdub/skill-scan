"""Adversarial corpus for split-evasion detection.

Each entry is a (category, id, code, should_detect, description) tuple.
- should_detect=True: the code assembles a dangerous name; scanner SHOULD flag it
- should_detect=False: the code is safe; scanner should NOT flag it (false positive check)

Categories:
- dict_storage: fragments stored in dict values
- list_storage: fragments stored in list elements
- tuple_unpacking: fragments via tuple/list unpacking
- walrus_operator: fragments assigned via :=
- augmented_assign: fragments built via +=
- string_multiply: string repetition to build names
- chr_building: chr() calls to build individual chars then concatenate via vars
- class_scope: fragments stored as class attributes
- nested_function: fragments in nested function scopes
- global_nonlocal: fragments using global/nonlocal declarations
- conditional_assign: fragments assigned conditionally
- reassignment: variable reassigned after initial tracking
- cross_function: fragments split across function boundaries
- generator_join: join with generator expression
- map_join: join via map() call
- format_method: str.format() instead of f-string
- percent_format: %-formatting
- slice_build: slicing a string to extract fragments
- reverse_build: reversed string reassembled
- lambda_build: lambda returning fragment
- comprehension_build: list/dict comprehension building fragments
- starargs_build: *args unpacking to build string
- encode_decode: encode/decode round-trip
- multiline_string: triple-quoted string fragments
- bytes_concat: bytes concatenation then decode
- unicode_names: unicode escape in variable names or values
- attribute_chain: object attribute access to store fragments
- importlib_split: splitting importlib.import_module target
- false_positive: safe patterns that must NOT trigger
"""

CORPUS = [
    # =========================================================================
    # CATEGORY: dict_storage -- fragments in dict values
    # =========================================================================
    (
        "dict_storage",
        "dict_concat_eval",
        """\
d = {}
d['a'] = 'ev'
d['b'] = 'al'
result = d['a'] + d['b']
""",
        True,
        "Dict subscript assignment then concatenation",
    ),
    (
        "dict_storage",
        "dict_literal_concat",
        """\
parts = {'a': 'ex', 'b': 'ec'}
name = parts['a'] + parts['b']
""",
        True,
        "Dict literal values concatenated",
    ),
    (
        "dict_storage",
        "dict_get_concat",
        """\
d = {'x': 'sy', 'y': 'stem'}
name = d.get('x', '') + d.get('y', '')
""",
        True,
        "Dict .get() method for fragments",
    ),

    # =========================================================================
    # CATEGORY: list_storage -- fragments in list elements
    # =========================================================================
    (
        "list_storage",
        "list_index_concat",
        """\
parts = ['ev', 'al']
name = parts[0] + parts[1]
""",
        True,
        "List index access then concatenation",
    ),
    (
        "list_storage",
        "list_join_variable",
        """\
parts = ['e', 'x', 'e', 'c']
name = ''.join(parts)
""",
        True,
        "Join on a list variable (not literal list in join call)",
    ),
    (
        "list_storage",
        "list_pop_concat",
        """\
parts = ['ev', 'al']
a = parts.pop(0)
b = parts.pop(0)
name = a + b
""",
        True,
        "List pop() to extract fragments",
    ),

    # =========================================================================
    # CATEGORY: tuple_unpacking -- fragments via unpacking
    # =========================================================================
    (
        "tuple_unpacking",
        "tuple_unpack_concat",
        """\
a, b = 'ev', 'al'
name = a + b
""",
        True,
        "Tuple unpacking assignment then concatenation",
    ),
    (
        "tuple_unpacking",
        "list_unpack_concat",
        """\
[a, b] = ['ex', 'ec']
name = a + b
""",
        True,
        "List unpacking assignment then concatenation",
    ),
    (
        "tuple_unpacking",
        "star_unpack_concat",
        """\
a, *rest = ['e', 'v', 'a', 'l']
name = a + ''.join(rest)
""",
        True,
        "Star unpacking then join of remainder",
    ),
    (
        "tuple_unpacking",
        "triple_unpack_concat",
        """\
a, b, c = 'po', 'pe', 'n'
name = a + b + c
""",
        True,
        "Three-way tuple unpacking for 'popen'",
    ),

    # =========================================================================
    # CATEGORY: walrus_operator -- walrus := assignments
    # =========================================================================
    (
        "walrus_operator",
        "walrus_in_if",
        """\
if (a := 'ev') and (b := 'al'):
    name = a + b
""",
        True,
        "Walrus operator in if-condition",
    ),
    (
        "walrus_operator",
        "walrus_in_while",
        """\
data = ['ev', 'al']
i = 0
while (chunk := data[i] if i < len(data) else None) is not None:
    i += 1
name = data[0] + data[1]
""",
        True,
        "Walrus operator in while-loop header",
    ),

    # =========================================================================
    # CATEGORY: augmented_assign -- += to build strings
    # =========================================================================
    (
        "augmented_assign",
        "aug_assign_eval",
        """\
name = 'ev'
name += 'al'
""",
        True,
        "Augmented assignment (+=) to build 'eval'",
    ),
    (
        "augmented_assign",
        "aug_assign_three_step",
        """\
name = 'ex'
name += 'e'
name += 'c'
""",
        True,
        "Three-step augmented assignment to build 'exec'",
    ),
    (
        "augmented_assign",
        "aug_assign_system",
        """\
cmd = 'sys'
cmd += 'tem'
""",
        True,
        "Augmented assignment to build 'system'",
    ),

    # =========================================================================
    # CATEGORY: string_multiply -- string repetition
    # =========================================================================
    (
        "string_multiply",
        "multiply_then_concat",
        """\
a = 'e' * 1
b = 'val'
name = a + b
""",
        True,
        "String multiply (* 1) then concatenation",
    ),
    (
        "string_multiply",
        "multiply_to_pad",
        """\
base = 'eval'
padded = base * 1
""",
        True,
        "Multiply dangerous name by 1 (identity but different AST node)",
    ),

    # =========================================================================
    # CATEGORY: chr_building -- chr() to build chars, then variable concat
    # =========================================================================
    (
        "chr_building",
        "chr_vars_concat",
        """\
a = chr(101)
b = chr(118)
c = chr(97)
d = chr(108)
name = a + b + c + d
""",
        True,
        "chr() per character stored in vars then concatenated",
    ),
    (
        "chr_building",
        "chr_vars_join",
        """\
e = chr(101)
v = chr(118)
a = chr(97)
l = chr(108)
name = ''.join([e, v, a, l])
""",
        True,
        "chr() per character stored in vars then joined",
    ),
    (
        "chr_building",
        "chr_vars_fstring",
        """\
e = chr(101)
x = chr(120)
e2 = chr(101)
c = chr(99)
name = f'{e}{x}{e2}{c}'
""",
        True,
        "chr() chars in vars then f-string interpolation for 'exec'",
    ),

    # =========================================================================
    # CATEGORY: class_scope -- fragments as class attributes
    # =========================================================================
    (
        "class_scope",
        "class_attr_concat",
        """\
class Payload:
    a = 'ev'
    b = 'al'
    name = a + b
""",
        True,
        "Class attributes concatenated within class body",
    ),
    (
        "class_scope",
        "class_method_concat",
        """\
class Exploit:
    prefix = 'ex'
    suffix = 'ec'

    def run(self):
        return self.prefix + self.suffix
""",
        True,
        "Class attributes concatenated via self in method",
    ),
    (
        "class_scope",
        "class_init_concat",
        """\
class Builder:
    def __init__(self):
        self.a = 'po'
        self.b = 'pen'

    def build(self):
        return self.a + self.b
""",
        True,
        "Instance attributes set in __init__ then concatenated",
    ),

    # =========================================================================
    # CATEGORY: nested_function -- fragments in nested scopes
    # =========================================================================
    (
        "nested_function",
        "nested_func_concat",
        """\
def outer():
    a = 'ev'
    def inner():
        b = 'al'
        return a + b
    return inner()
""",
        True,
        "Closure: outer var + inner var concatenated",
    ),
    (
        "nested_function",
        "nested_func_fstring",
        """\
def outer():
    prefix = 'ex'
    def inner():
        suffix = 'ec'
        return f'{prefix}{suffix}'
    return inner()
""",
        True,
        "Closure with f-string interpolation",
    ),

    # =========================================================================
    # CATEGORY: global_nonlocal -- global/nonlocal keyword usage
    # =========================================================================
    (
        "global_nonlocal",
        "global_var_concat",
        """\
a = 'ev'
def build():
    global a
    b = 'al'
    return a + b
""",
        True,
        "Global variable read in function then concatenated",
    ),
    (
        "global_nonlocal",
        "nonlocal_var_concat",
        """\
def outer():
    a = 'ex'
    def inner():
        nonlocal a
        b = 'ec'
        return a + b
    return inner()
""",
        True,
        "Nonlocal variable modified and concatenated",
    ),

    # =========================================================================
    # CATEGORY: conditional_assign -- conditional/branching assignment
    # =========================================================================
    (
        "conditional_assign",
        "ternary_assign_concat",
        """\
x = True
a = 'ev' if x else 'safe'
b = 'al' if x else 'word'
name = a + b
""",
        True,
        "Ternary assignment, dangerous on true branch",
    ),
    (
        "conditional_assign",
        "if_else_assign_concat",
        """\
import random
if True:
    a = 'ev'
    b = 'al'
else:
    a = 'he'
    b = 'lo'
name = a + b
""",
        True,
        "If/else branch assignment then concatenation",
    ),

    # =========================================================================
    # CATEGORY: reassignment -- variable overwritten after tracking
    # =========================================================================
    (
        "reassignment",
        "reassign_to_dangerous",
        """\
a = 'safe'
b = 'word'
a = 'ev'
b = 'al'
name = a + b
""",
        True,
        "Variables reassigned from safe to dangerous",
    ),
    (
        "reassignment",
        "reassign_from_dangerous",
        """\
a = 'ev'
b = 'al'
a = 'hello'
b = 'world'
name = a + b
""",
        False,
        "Variables reassigned from dangerous to safe -- should NOT trigger",
    ),

    # =========================================================================
    # CATEGORY: cross_function -- fragments split across function boundaries
    # =========================================================================
    (
        "cross_function",
        "func_return_concat",
        """\
def get_prefix():
    return 'ev'

def get_suffix():
    return 'al'

name = get_prefix() + get_suffix()
""",
        True,
        "Function return values concatenated at module level",
    ),
    (
        "cross_function",
        "func_arg_concat",
        """\
def combine(a, b):
    return a + b

name = combine('ev', 'al')
""",
        True,
        "Function called with dangerous fragments as arguments",
    ),

    # =========================================================================
    # CATEGORY: generator_join -- generator expression in join
    # =========================================================================
    (
        "generator_join",
        "genexpr_join_eval",
        """\
parts = ['ev', 'al']
name = ''.join(p for p in parts)
""",
        True,
        "Generator expression in join over list variable",
    ),
    (
        "generator_join",
        "genexpr_join_chr",
        """\
codes = [101, 118, 97, 108]
name = ''.join(chr(c) for c in codes)
""",
        True,
        "Generator expression with chr() in join",
    ),

    # =========================================================================
    # CATEGORY: map_join -- map() in join
    # =========================================================================
    (
        "map_join",
        "map_chr_join_var",
        """\
codes = [101, 118, 97, 108]
name = ''.join(map(chr, codes))
""",
        True,
        "map(chr, list_var) in join -- list is a variable not literal",
    ),

    # =========================================================================
    # CATEGORY: format_method -- str.format()
    # =========================================================================
    (
        "format_method",
        "format_concat_eval",
        """\
a = 'ev'
b = 'al'
name = '{}{}'.format(a, b)
""",
        True,
        "str.format() with tracked variables",
    ),
    (
        "format_method",
        "format_named_args",
        """\
a = 'ex'
b = 'ec'
name = '{x}{y}'.format(x=a, y=b)
""",
        True,
        "str.format() with named args from tracked variables",
    ),

    # =========================================================================
    # CATEGORY: percent_format -- %-formatting
    # =========================================================================
    (
        "percent_format",
        "percent_format_eval",
        """\
a = 'ev'
b = 'al'
name = '%s%s' % (a, b)
""",
        True,
        "%-formatting with tracked variables",
    ),

    # =========================================================================
    # CATEGORY: slice_build -- slicing to extract fragments
    # =========================================================================
    (
        "slice_build",
        "slice_from_safe_string",
        """\
data = 'evaluation'
name = data[:4]
""",
        True,
        "Slice from innocent-looking string to extract 'eval'",
    ),
    (
        "slice_build",
        "slice_concat",
        """\
data = 'extreme_value'
a = data[0:2]
b = data[8:10]
name = a + b
""",
        True,
        "Slices from different positions concatenated",
    ),

    # =========================================================================
    # CATEGORY: reverse_build -- reversed string
    # =========================================================================
    (
        "reverse_build",
        "reverse_dangerous",
        """\
rev = 'lave'
name = rev[::-1]
""",
        True,
        "Reversed string sliced to get 'eval'",
    ),
    (
        "reverse_build",
        "reversed_join",
        """\
rev = 'cexe'
name = ''.join(reversed(rev))
""",
        True,
        "reversed() built-in with join to get 'exec'",
    ),

    # =========================================================================
    # CATEGORY: lambda_build -- lambda returning fragments
    # =========================================================================
    (
        "lambda_build",
        "lambda_concat",
        """\
get_a = lambda: 'ev'
get_b = lambda: 'al'
name = get_a() + get_b()
""",
        True,
        "Lambda functions returning fragments",
    ),

    # =========================================================================
    # CATEGORY: comprehension_build -- comprehension to build strings
    # =========================================================================
    (
        "comprehension_build",
        "listcomp_chr_join",
        """\
codes = [101, 118, 97, 108]
name = ''.join([chr(c) for c in codes])
""",
        True,
        "List comprehension with chr() -- codes in variable not literal",
    ),
    (
        "comprehension_build",
        "dictcomp_fragments",
        """\
raw = {0: 'ev', 1: 'al'}
fragments = {k: v for k, v in raw.items()}
name = fragments[0] + fragments[1]
""",
        True,
        "Dict comprehension producing fragments then concatenated",
    ),

    # =========================================================================
    # CATEGORY: starargs_build -- *args or unpacking
    # =========================================================================
    (
        "starargs_build",
        "starargs_format",
        """\
parts = ('ev', 'al')
name = '{}{}'.format(*parts)
""",
        True,
        "Star-unpacking into format()",
    ),

    # =========================================================================
    # CATEGORY: encode_decode -- encoding round-trips
    # =========================================================================
    (
        "encode_decode",
        "encode_decode_roundtrip",
        """\
a = b'ev'.decode()
b = b'al'.decode()
name = a + b
""",
        True,
        "Bytes decode to string then concatenation",
    ),
    (
        "encode_decode",
        "hex_decode_concat",
        """\
a = bytes.fromhex('6576').decode()
b = bytes.fromhex('616c').decode()
name = a + b
""",
        True,
        "Hex-decoded bytes to string then concatenation",
    ),

    # =========================================================================
    # CATEGORY: multiline_string -- triple-quoted fragments
    # =========================================================================
    (
        "multiline_string",
        "triple_quote_concat",
        """\
a = '''ev'''
b = '''al'''
name = a + b
""",
        True,
        "Triple-quoted string fragments concatenated",
    ),

    # =========================================================================
    # CATEGORY: bytes_concat -- bytes then decode
    # =========================================================================
    (
        "bytes_concat",
        "bytes_add_decode",
        """\
a = b'ev'
b = b'al'
name = (a + b).decode()
""",
        True,
        "Bytes concatenation then .decode()",
    ),

    # =========================================================================
    # CATEGORY: unicode_names -- unicode in values
    # =========================================================================
    (
        "unicode_names",
        "unicode_escape_concat",
        """\
a = '\\x65\\x76'
b = '\\x61\\x6c'
name = a + b
""",
        True,
        "Hex escape sequences in string values that form 'eval'",
    ),
    (
        "unicode_names",
        "unicode_name_escape",
        """\
a = '\\N{LATIN SMALL LETTER E}\\N{LATIN SMALL LETTER V}'
b = '\\N{LATIN SMALL LETTER A}\\N{LATIN SMALL LETTER L}'
name = a + b
""",
        True,
        "Unicode name escapes that resolve to 'eval'",
    ),

    # =========================================================================
    # CATEGORY: attribute_chain -- object attribute storage
    # =========================================================================
    (
        "attribute_chain",
        "namedtuple_attrs",
        """\
from collections import namedtuple
Parts = namedtuple('Parts', ['a', 'b'])
p = Parts('ev', 'al')
name = p.a + p.b
""",
        True,
        "Named tuple attribute access for fragments",
    ),

    # =========================================================================
    # CATEGORY: importlib_split -- splitting module name for dynamic import
    # =========================================================================
    (
        "importlib_split",
        "importlib_split_name",
        """\
import importlib
a = 'o'
b = 's'
mod = importlib.import_module(a + b)
""",
        True,
        "importlib.import_module with split module name",
    ),

    # =========================================================================
    # CATEGORY: indirect_call -- using the assembled name to actually call
    # =========================================================================
    (
        "indirect_call",
        "eval_from_vars",
        """\
a = 'ev'
b = 'al'
func = a + b
globals()[func]('print(1)')
""",
        True,
        "Assembled name used via globals() to call eval",
    ),
    (
        "indirect_call",
        "getattr_from_vars",
        """\
import builtins
a = 'ev'
b = 'al'
fn = getattr(builtins, a + b)
""",
        True,
        "getattr(builtins, assembled_name)",
    ),

    # =========================================================================
    # CATEGORY: multi_indirection -- deep variable chains
    # =========================================================================
    (
        "multi_indirection",
        "four_level_chain",
        """\
x1 = 'ev'
x2 = x1
x3 = x2
x4 = x3
b = 'al'
name = x4 + b
""",
        True,
        "Four-level indirection chain before concatenation",
    ),
    (
        "multi_indirection",
        "cross_assign_chain",
        """\
a = 'ev'
b = a
c = 'al'
d = c
name = b + d
""",
        True,
        "Cross-assignment indirection for both operands",
    ),

    # =========================================================================
    # CATEGORY: mixed_methods -- combining multiple evasion techniques
    # =========================================================================
    (
        "mixed_methods",
        "chr_plus_literal_concat",
        """\
a = chr(101) + chr(118)
b = 'al'
name = a + b
""",
        True,
        "chr() resolved to string, then variable concat with literal",
    ),
    (
        "mixed_methods",
        "indirection_then_fstring",
        """\
x = 'sy'
y = x
suffix = 'stem'
name = f'{y}{suffix}'
""",
        True,
        "Indirection chain then f-string interpolation",
    ),
    (
        "mixed_methods",
        "join_with_indirection",
        """\
x = 'po'
y = x
z = 'pen'
name = ''.join([y, z])
""",
        True,
        "Indirection then join",
    ),

    # =========================================================================
    # CATEGORY: false_positive -- safe patterns that MUST NOT trigger
    # =========================================================================
    (
        "false_positive",
        "safe_path_concat",
        """\
base = '/usr/local'
sub = '/bin'
path = base + sub
""",
        False,
        "Path concatenation -- safe",
    ),
    (
        "false_positive",
        "safe_url_concat",
        """\
scheme = 'https://'
host = 'example.com'
url = scheme + host
""",
        False,
        "URL construction -- safe",
    ),
    (
        "false_positive",
        "safe_log_fstring",
        """\
level = 'INFO'
msg = 'started'
log = f'[{level}] {msg}'
""",
        False,
        "Log message f-string -- safe",
    ),
    (
        "false_positive",
        "safe_config_join",
        """\
host = '127.0.0.1'
port = '8080'
addr = ':'.join([host, port])
""",
        False,
        "Config join -- safe",
    ),
    (
        "false_positive",
        "safe_html_concat",
        """\
tag = '<div>'
content = 'hello'
html = tag + content
""",
        False,
        "HTML concatenation -- safe",
    ),
    (
        "false_positive",
        "safe_multivar_concat",
        """\
a = 'hello'
b = ' '
c = 'world'
msg = a + b + c
""",
        False,
        "Three-variable safe concatenation -- safe",
    ),

    # =========================================================================
    # CATEGORY: format_spec_fstring -- f-string with format spec
    # =========================================================================
    (
        "format_spec_fstring",
        "fstring_with_conversion",
        """\
a = 'ev'
b = 'al'
name = f'{a!s}{b!s}'
""",
        True,
        "F-string with !s conversion",
    ),
    (
        "format_spec_fstring",
        "fstring_with_format_spec",
        """\
a = 'ev'
b = 'al'
name = f'{a:>2}{b:>2}'
""",
        True,
        "F-string with format spec (:>2)",
    ),

    # =========================================================================
    # CATEGORY: encoded_split -- splitting encoded payloads
    # =========================================================================
    (
        "encoded_split",
        "hex_string_split",
        """\
a = '6576616c28'
b = '27707269'
c = '6e742831'
d = '2927290a'
payload = a + b + c + d
""",
        True,
        "Hex-encoded payload split across 4 variables",
    ),

    # =========================================================================
    # CATEGORY: deferred_eval -- assembling name for later use
    # =========================================================================
    (
        "deferred_eval",
        "stored_in_dict",
        """\
a = 'ev'
b = 'al'
config = {'func': a + b}
""",
        True,
        "Dangerous name assembled and stored in dict -- still has the BinOp",
    ),
    (
        "deferred_eval",
        "passed_to_function",
        """\
a = 'ev'
b = 'al'
some_function(a + b)
""",
        True,
        "Dangerous name assembled and passed as function argument",
    ),
    (
        "deferred_eval",
        "returned_from_function",
        """\
a = 'ev'
b = 'al'
def get_name():
    return a + b
""",
        True,
        "Dangerous name assembled in return statement of function",
    ),

    # =========================================================================
    # CATEGORY: obfuscated_indirection -- hiding the chain
    # =========================================================================
    (
        "obfuscated_indirection",
        "var_name_misleading",
        """\
config_host = 'ev'
config_port = 'al'
server_name = config_host + config_port
""",
        True,
        "Misleading variable names to hide intent",
    ),
    (
        "obfuscated_indirection",
        "many_safe_vars_with_one_dangerous",
        """\
x1 = 'hello'
x2 = 'world'
x3 = 'ev'
x4 = 'al'
x5 = 'goodbye'
safe = x1 + x2
danger = x3 + x4
also_safe = x1 + x5
""",
        True,
        "Many safe concatenations with one dangerous buried in the middle",
    ),
    (
        "obfuscated_indirection",
        "long_chain_of_assignments",
        """\
v1 = 'e'
v2 = 'v'
v3 = 'a'
v4 = 'l'
p1 = v1
p2 = v2
p3 = v3
p4 = v4
q1 = p1
q2 = p2
q3 = p3
q4 = p4
name = q1 + q2 + q3 + q4
""",
        True,
        "Long indirection chain (3 levels) per character",
    ),

    # =========================================================================
    # CATEGORY: scope_leak -- information leaking between scopes
    # =========================================================================
    (
        "scope_leak",
        "for_loop_assignment",
        """\
for a in ['ev']:
    pass
for b in ['al']:
    pass
name = a + b
""",
        True,
        "For-loop variable leak (Python loop vars persist)",
    ),
    (
        "scope_leak",
        "with_statement_as",
        """\
import io
with io.StringIO('ev') as a:
    pass
b = 'al'
name = a + b
""",
        True,
        "with-as variable persists after block",
    ),
    (
        "scope_leak",
        "except_var",
        """\
try:
    pass
except Exception as e:
    a = 'ev'
b = 'al'
name = a + b
""",
        True,
        "Variable assigned in except block persists",
    ),
]

# Count categories
if __name__ == "__main__":
    from collections import Counter
    cats = Counter(c[0] for c in CORPUS)
    total_should_detect = sum(1 for c in CORPUS if c[3])
    total_safe = sum(1 for c in CORPUS if not c[3])
    print(f"Total inputs: {len(CORPUS)}")
    print(f"Should detect (positive): {total_should_detect}")
    print(f"Should NOT detect (negative): {total_safe}")
    print(f"\nCategories ({len(cats)}):")
    for cat, count in sorted(cats.items()):
        print(f"  {cat}: {count}")
