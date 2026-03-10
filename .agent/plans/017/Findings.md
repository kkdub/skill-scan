 Findings

       1. Do security scanners use heuristic detection vs. explicit invocation matching for ROT13?

       The universal answer from all surveyed tooling (Bandit, Semgrep, CodeQL, YARA-Rules, Elastic, Splunk, MobSF) is:
       none of them detect ROT13 at all, either heuristically or via invocation pattern matching. Zero results were found
        in every major SAST and rule-database search.

       The practical consensus from the field is:

       - Invocation-pattern matching is the dominant approach used by any scanner that does address encoding obfuscation.
        The model is: flag the call site (e.g., codecs.decode(..., 'rot_13')), not the encoded text itself.
       - Heuristic/frequency-analysis detection of standalone ROT13 text is not done by any mainstream scanner. ROT13
       preserves English letter frequency perfectly (it is a letter bijection), so standard entropy measures cannot
       distinguish ROT13 text from plain English. This makes purely heuristic detection of ROT13-encoded payloads
       infeasible without decoding first.
       - The only tools approaching heuristic obfuscation detection use Shannon entropy (e.g., ForgeScan), which is
       effective for base64/zlib but useless for ROT13 since ROT13 does not change the character frequency distribution.

       2. Python ROT13 invocation patterns

       From Python's official documentation and Lib/encodings/rot_13.py source:

       Primary codec access (codecs module):
       codecs.encode(text, 'rot_13')        # primary name
       codecs.encode(text, 'rot13')         # alias (restored Python 3.4)
       codecs.decode(text, 'rot_13')        # symmetric — same result
       codecs.decode(text, 'rot13')

       Indirect codec access:
       codecs.getencoder('rot_13')(text)[0]
       codecs.getdecoder('rot_13')(text)[0]
       codecs.lookup('rot_13').encode(text)
       for chunk in codecs.iterencode([text], 'rot_13'): ...

       str.encode() does NOT work for ROT13 — it is a text transform (str-to-str), not a bytes codec. This is a
       documented Python constraint.

       Custom str.translate() implementations — the stdlib this.py easter egg uses this pattern directly:
       d = {c: chr((ord(c) - base + 13) % 26 + base) for base in (65, 97) for c in ...}
       text.translate(d)
       # or with str.maketrans:
       table = str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                             'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm')
       text.translate(table)

       encodings.rot_13 module's own rot13() function — the module exposes a file-object filter rot13(file) that is
       importable directly but rarely used.

       The complete list of valid codec name strings for Python's codecs machinery: 'rot_13' and 'rot13'. The internal
       module name is rot-13 (with hyphen, as returned by getregentry()), but this is not user-facing.

       3. False positive challenges

       ROT13 has several high-signal legitimate uses:

       - import this — Python's own stdlib easter egg (Lib/this.py) uses a manual ROT13 str.translate implementation to
       encode the Zen of Python. Any scanner matching str.translate with a ROT13 table will hit this.
       - Forum/spoiler obfuscation — legitimate tools and libraries implement ROT13 for hiding spoilers, NSFW content
       labels, or puzzle answers.
       - Encoding round-trip tests — codecs.encode(x, 'rot13') appears in unit tests for the codecs module itself.
       - Educational/documentation code — ROT13 is the canonical example of a simple cipher in cryptography tutorials.
       - Network protocol implementations — NNTP newsgroup headers historically used ROT13; any NNTP-related Python
       library may use it.

       The invocation-pattern approach (matching codecs.encode/decode with rot_13/rot13 as the encoding argument) will
       produce false positives on all of the above unless context is examined (e.g., whether the result feeds into eval()
        or a network call).

       4. SAST tool coverage: none found

       ┌──────────────────────────────┬─────────────┬─────────────────────────────────┐
       │             Tool             │ ROT13 Rules │              Notes              │
       ├──────────────────────────────┼─────────────┼─────────────────────────────────┤
       │ Bandit                       │ None        │ 0 results in full source search │
       ├──────────────────────────────┼─────────────┼─────────────────────────────────┤
       │ Semgrep (semgrep-rules repo) │ None        │ 0 results                       │
       ├──────────────────────────────┼─────────────┼─────────────────────────────────┤
       │ CodeQL Python queries        │ None        │ Explicit confirmation from docs │
       ├──────────────────────────────┼─────────────┼─────────────────────────────────┤
       │ YARA-Rules/rules             │ None        │ 0 results                       │
       ├──────────────────────────────┼─────────────┼─────────────────────────────────┤
       │ Elastic detection-rules      │ None        │ 0 results                       │
       ├──────────────────────────────┼─────────────┼─────────────────────────────────┤
       │ Splunk security_content      │ None        │ 0 results                       │
       ├──────────────────────────────┼─────────────┼─────────────────────────────────┤
       │ MobSF                        │ None        │ 0 results                       │
       └──────────────────────────────┴─────────────┴─────────────────────────────────┘

       YARA supports XOR-obfuscated string matching natively (xor modifier) and base64 natively (base64 modifier), but
       has no ROT13 modifier or built-in support. ROT13 detection in YARA would require a custom external module or
       pre-processing.

       5. ROT13 in LLM prompt injection and jailbreaking

       This is the strongest research finding. The paper "GPT-4 Is Too Smart To Be Safe: Stealthy Chat with LLMs via
       Cipher" (Yuan et al., arXiv:2308.06463, March 2024) provides the definitive study:

       ROT13 is explicitly named in the paper as one of the non-natural language encodings that LLMs understand and that
       can be used to bypass safety alignment. The paper's introduction states: "recent works show that LLMs exhibit
       unexpected capabilities in understanding non-natural languages like the Morse Code, ROT13, and Base64."

       The attack mechanism (CipherChat framework) works as follows:
       1. Assign the LLM a role as "cipher expert"
       2. Teach the LLM the cipher rules in-context
       3. Feed harmful queries encoded in the cipher
       4. The LLM responds in the cipher; decode with a rule-based decrypter

       The ciphers tested include: Caesar (shift-3, which is the same family as ROT13/shift-13), ASCII encoding, Unicode,
        Atbash, Morse Code, GBK/UTF character encoding, and SelfCipher (an implicit cipher the LLM invents itself).

       Key quantitative results for the Caesar cipher (closest to ROT13, shift-3 vs shift-13):
       - GPT-4 unsafe response rate on English: 73.4% (vs. 0% for vanilla GPT-4)
       - GPT-3.5-Turbo (Turbo) unsafe response rate: 0% — Turbo could not reliably decode Caesar cipher, producing
       invalid responses, so the attack was ineffective

       The paper explicitly distinguishes that simulated ciphers that never appeared in pretraining data cannot work —
       the attack depends on the model having seen the cipher encoding during pretraining. ROT13, being extremely common
       in pretraining data (Python docs, internet forums, newsgroups), is a high-risk cipher for this attack vector.

       Prompt injection skill file context: ROT13 obfuscation in agent skill files serves the same evasion purpose —
       encoding malicious instructions so that:
       - Static text scanners scanning for literal strings like exfiltrate, eval, os.system will not match
       - The instruction is decoded at LLM inference time by the agent's underlying model, which understands ROT13

       This is distinct from the Python code obfuscation threat (where the skill file contains Python that calls
       codecs.decode(..., 'rot13') to reconstruct a payload at runtime).

       Confidence: High

       Sources:
       - Yuan et al. (2024), "GPT-4 Is Too Smart To Be Safe: Stealthy Chat with LLMs via Cipher," arXiv:2308.06463 —
       https://arxiv.org/abs/2308.06463
       - Python official docs, codecs module text transforms — https://docs.python.org/3/library/codecs.html
       - CPython source, Lib/encodings/rot_13.py —
       https://raw.githubusercontent.com/python/cpython/main/Lib/encodings/rot_13.py
       - Bandit plugin index (confirmed no ROT13 coverage) — https://bandit.readthedocs.io/en/latest/plugins/index.html
       - YARA docs, string modifiers — https://yara.readthedocs.io/en/stable/writingrules.html
       - JFrog blog on obfuscated packages (2026) — https://jfrog.com/blog/breaking-appsec-myths-obfuscated-packages/

       Gaps:
       - No published research on whether real-world malicious PyPI packages have been found using codecs.decode(...,
       'rot13') specifically (Base64 and hex are far more common in the wild)
       - No tested data on whether ROT13 in a skill's YAML/markdown text (not Python code) successfully evades current
       LLM safety filters in production agent frameworks
       - The CipherChat paper tested Caesar (shift-3), not ROT13 (shift-13) directly, though both are alphabetic rotation
        ciphers; their effectiveness should be comparable since GPT-4 knows both
  ⎿  Done (139 tool uses · 59.3k tokens · 14m 20s)

● web-researcher(Research URL-encoding detection thresholds)
  ⎿  Prompt:
       Research best practices for detecting malicious URL-encoded payloads in security scanners and static analysis
       tools.

       Specific questions:
       1. What density/threshold of %XX sequences indicates malicious encoding vs. normal URL usage? How many consecutive
        percent-encoded bytes should trigger suspicion?
       2. What are common evasion patterns using URL encoding? (e.g., double encoding like %2565 for %65 for 'e', mixed
       case %2F vs %2f, encoding normally safe characters)
       3. How do SAST tools and WAFs distinguish between legitimate URL encoding (spaces as %20, special chars) and
       malicious payload encoding (encoding alphanumeric characters that don't need encoding)?
       4. What's the best regex approach for extracting suspicious URL-encoded sequences from source code?
       5. Should the scanner also detect double-encoding (%25XX patterns)?
       6. In agent skill files (YAML, Markdown, Python), what does malicious URL encoding typically look like?

       Search security scanner docs, OWASP resources, WAF rule documentation, and prompt injection research.
  ⎿  Fetch(url: "https://owasp.org/www-community/attacks/Double_Encoding", prompt: "What are best practices for detecting
  ⎿  Fetch(url: "https://owasp.org/www-community/attacks/Percent_Encoding", prompt: "What does OWASP say about malicious
  ⎿  Fetch(url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html", prompt: "What does
  ⎿  Error: Request failed with status code 404
  ⎿  Cancelled: parallel tool call WebFetch errored
  ⎿  Cancelled: parallel tool call WebFetch errored
  ⎿  Fetch(url: "https://owasp.org/www-community/attacks/Double_Encoding", prompt: "What are best practices for detecting
  ⎿  Error: Request failed with status code 404
  ⎿  Fetch(url: "https://owasp.org/www-community/attacks/", prompt: "List the attack categories and any related to URL
  ⎿  Fetch(url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html", prompt: "What does
  ⎿  Fetch(url: "https://owasp.org/www-community/attacks/Unicode_Encoding", prompt: "What are techniques attackers use
  ⎿  Fetch(url: "https://www.cloudflare.com/learning/security/threats/sql-injection/", prompt: "How do WAFs detect
  ⎿  Fetch(url: "https://coreruleset.org/docs/rules/", prompt: "How does the OWASP Core Rule Set detect malicious URL
  ⎿  Error: Request failed with status code 404
  ⎿  Fetch(url: "https://coreruleset.org/docs/", prompt: "Find links to documentation about URL encoding detection rules,
  ⎿  Fetch(url: "https://github.com/coreruleset/coreruleset/blob/main/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf",
  ⎿  Error: Request failed with status code 429
  ⎿  Cancelled: parallel tool call WebFetch errored
  ⎿  Fetch(url: "https://coreruleset.org/docs/", prompt: "Find links to documentation about URL encoding detection
  ⎿  Fetch(url:
  ⎿  Fetch(url: "https://portswigger.net/web-security/essential-skills/obfuscating-attacks-using-encodings", prompt:
  ⎿  Fetch(url: "https://portswigger.net/web-security/essential-skills/obfuscating-attacks-using-encodings", prompt:
  ⎿  Fetch(url: "https://raw.githubusercontent.com/coreruleset/coreruleset/main/rules/REQUEST-942-APPLICATION-ATTACK-SQLI
  ⎿  Fetch(url: "https://semgrep.dev/docs/writing-rules/pattern-syntax/", prompt: "Does Semgrep have patterns for
  ⎿  Fetch(url: "https://www.sans.org/blog/url-encoding-evasion-techniques/", prompt: "What URL encoding evasion
  ⎿  Error: Request failed with status code 404
  ⎿  Fetch(url: "https://security.stackexchange.com/questions/48050/when-is-url-encoding-suspicious", prompt: "What makes
  ⎿  Fetch(url:
  ⎿  Error: Request failed with status code 429
  ⎿  Cancelled: parallel tool call WebFetch errored
  ⎿  Fetch(url: "https://security.stackexchange.com/questions/48050/when-is-url-encoding-suspicious", prompt: "What makes
  ⎿  Error: Claude Code is unable to fetch from security.stackexchange.com
  ⎿  Fetch(url: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-In
  ⎿  Fetch(url: "https://www.modsecurity.org/CRS/Documentation/manipulation.html", prompt: "How does ModSecurity's CRS
  ⎿  Error: Request failed with status code 404
  ⎿  Fetch(url: "https://coreruleset.org/20231027/how-crs-handles-encoding/", prompt: "How does CRS handle and detect
  ⎿  Error: Request failed with status code 404
  ⎿  Fetch(url: "https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#t:urlDecode", prompt: "How does
  ⎿  Cancelled: parallel tool call WebFetch errored
  ⎿  Fetch(url: "https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)", prompt: "What transformation
  ⎿  Fetch(url: "https://raw.githubusercontent.com/coreruleset/coreruleset/main/rules/REQUEST-921-PROTOCOL-ATTACK.conf",
  ⎿  Fetch(url: "https://research.nccgroup.com/2021/11/09/prompt-injection-attacks-on-large-language-models/", prompt:
  ⎿  Fetch(url: "https://learnbyexample.github.io/python-regex-cheatsheet/", prompt: "What regex patterns efficiently
  ⎿  Fetch(url: "https://github.com/greshake/llm-security/blob/main/docs/README.md", prompt: "Do prompt injection attacks
  ⎿  Error: Request failed with status code 429
  ⎿  Fetch(url: "https://owasp.org/www-project-top-10-for-large-language-model-applications/", prompt: "Does OWASP LLM
  ⎿  Cancelled: parallel tool call WebFetch errored
  ⎿  Fetch(url: "https://owasp.org/www-project-top-10-for-large-language-model-applications/", prompt: "Does OWASP LLM
  ⎿  Fetch(url: "https://genai.owasp.org/llmrisk/llm01-prompt-injection/", prompt: "Does OWASP LLM01 address URL encoding
  ⎿  Fetch(url: "https://arxiv.org/abs/2302.12173", prompt: "Do prompt injection attacks use URL encoding or percent
  ⎿  Fetch(url: "https://github.com/protectai/rebuff/blob/main/README.md", prompt: "How does Rebuff detect encoded prompt
  ⎿  Error: Request failed with status code 429
  ⎿  Fetch(url: "https://securecoding.cert.org/confluence/display/java/IDS02-J.+Canonicalize+path+names+before+validating
  ⎿  Cancelled: parallel tool call WebFetch errored
  ⎿  Fetch(url: "https://www.iana.org/assignments/uri-schemes/uri-schemes.xhtml", prompt: "What characters are reserved
  ⎿  Fetch(url: "https://www.rfc-editor.org/rfc/rfc3986#section-2.3", prompt: "What are the unreserved characters in URI
  ⎿  Fetch(url: "https://github.com/nicowillis/url-encoding-detection-rules", prompt: "What rules or patterns are used to
  ⎿  Error: Request failed with status code 404
  ⎿  Cancelled: parallel tool call WebFetch errored
  ⎿  Fetch(url: "https://www.rfc-editor.org/rfc/rfc3986#section-2.3", prompt: "What are the unreserved characters in URI
  ⎿  Fetch(url:
  ⎿  Fetch(url: "https://github.com/coreruleset/coreruleset/blob/main/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf",
  ⎿  Error: Request failed with status code 429
  ⎿  Fetch(url: "https://www.acunetix.com/blog/articles/url-encoding/", prompt: "What makes URL encoding suspicious vs
  ⎿  Fetch(url: "https://brightsec.com/blog/url-encoding/", prompt: "What URL encoding patterns are used for attacks? How
  ⎿  Error: Request failed with status code 404
  ⎿  Cancelled: parallel tool call WebFetch errored
  ⎿  Fetch(url: "https://www.netsparker.com/blog/web-security/url-encoding/", prompt: "What URL encoding patterns are
  ⎿  Fetch(url: "https://github.com/PyCQA/bandit/blob/main/bandit/plugins/", prompt: "Does bandit have plugins for
  ⎿  Error: Request failed with status code 429
  ⎿  Cancelled: parallel tool call WebFetch errored
  ⎿  Fetch(url: "https://docs.snyk.io/scan-using-snyk/snyk-code/snyk-code-security-rules", prompt: "Does Snyk Code detect
  ⎿  Error: Request failed with status code 404
  ⎿  Fetch(url: "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html", prompt: "What
  ⎿  Fetch(url: "https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/URL%20Encoding/README.md", prompt: "What
  ⎿  Error: Request failed with status code 429
  ⎿  Cancelled: parallel tool call WebFetch errored
  ⎿  Fetch(url: "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html", prompt: "What
  ⎿  Fetch(url: "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Methodology%20and%20Resources", prompt:
  ⎿  Fetch(url: "https://developer.mozilla.org/en-US/docs/Glossary/Percent-encoding", prompt: "What characters are
  ⎿  Fetch(url: "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Methodology%20and%20Resources/
  ⎿  Error: Request failed with status code 404
  ⎿  Fetch(url: "https://github.com/swisskyrepo/PayloadsAllTheThings", prompt: "What folders or files cover URL encoding,
  ⎿  Fetch(url:
  ⎿  Fetch(url: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Co
  ⎿  Fetch(url: "https://owasp.org/www-project-web-security-testing-guide/latest/6-Appendix/D-Encoded_Injection", prompt:
  ⎿  Fetch(url: "https://github.com/coreruleset/coreruleset/blob/main/CHANGES.md", prompt: "Are there any recent changes
  ⎿  Error: Request failed with status code 429
  ⎿  Cancelled: parallel tool call WebFetch errored
  ⎿  Fetch(url: "https://owasp.org/www-project-web-security-testing-guide/latest/6-Appendix/D-Encoded_Injection", prompt:
  ⎿  Fetch(url: "https://github.com/coreruleset/coreruleset/blob/main/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf",
  ⎿  Error: Request failed with status code 429
  ⎿  Fetch(url:
  ⎿  Fetch(url: "https://portswigger.net/kb/issues/00400550_url-encoded-data-in-params", prompt: "What does Burp Suite
  ⎿  Fetch(url: "https://github.com/nicowillis/semgrep-rules/tree/main/generic", prompt: "Are there Semgrep rules for
  ⎿  Error: Request failed with status code 404
  ⎿  Cancelled: parallel tool call WebFetch errored
  ⎿  Fetch(url: "https://semgrep.dev/r?q=url+encoding+injection", prompt: "What Semgrep rules detect URL-encoded payloads
  ⎿  Fetch(url: "https://github.com/PyCQA/bandit/issues?q=url+encoding+detection", prompt: "Does bandit have any open
  ⎿  Fetch(url: "https://github.com/nicowillis/semgrep-rules", prompt: "Are there semgrep rules for detecting prompt
  ⎿  Error: Request failed with status code 404
  ⎿  Fetch(url: "https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/", prompt: "Does TruffleHog detect
  ⎿  Cancelled: parallel tool call WebFetch errored
  ⎿  Fetch(url: "https://lexi-lambda.github.io/blog/2019/11/05/parse-don-t-validate/", prompt: "Does this discuss
  ⎿  Fetch(url: "https://github.com/digininja/CeWL/blob/master/cewl.rb", prompt: "Skip this - look for something else")
  ⎿  Error: Request failed with status code 429
  ⎿  Cancelled: parallel tool call WebFetch errored
  ⎿  Fetch(url: "https://blog.detectify.com/2019/01/10/url-encoding-attacks-and-how-to-detect-them/", prompt: "What are
  ⎿  Error: Permission for this tool use was denied. The tool use was rejected (eg. if it was a file edit, the new_string
  ⎿  Fetch(url: "https://www.invicti.com/learn/url-encoding/", prompt: "What URL encoding patterns are used in attacks?
  ⎿  Error: Request failed with status code 404
  ⎿  Fetch(url: "https://www.netsparker.com/blog/web-security/why-is-url-encoding-important/", prompt: "What URL encoding
  ⎿  Fetch(url: "https://www.invicti.com/blog/web-security/why-is-url-encoding-important/", prompt: "What URL encoding
  ⎿  Error: Request failed with status code 404
  ⎿  Fetch(url: "https://www.cloudflare.com/learning/security/threats/owasp-top-10/", prompt: "How does Cloudflare's WAF
  ⎿  Fetch(url: "https://blog.chromium.org/2022/05/url-encoding-security-analysis.html", prompt: "What URL encoding
  ⎿  Error: Request failed with status code 404
  ⎿  Fetch(url: "https://github.com/nicowillis/semgrep-rules/search?q=url+encoding", prompt: "Are there Semgrep rules for
  ⎿  Error: Request failed with status code 404
  ⎿  Fetch(url: "https://github.com/returntocorp/semgrep-rules/search?q=percent+encoded", prompt: "Are there Semgrep
  ⎿  Cancelled: parallel tool call WebFetch errored
  ⎿  Fetch(url: "https://semgrep.dev/blog/2022/static-analysis-security-scanner-how-it-works", prompt: "How does static
  ⎿  Error: Request failed with status code 404
  ⎿  Fetch(url: "https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html", prompt: "What URL
  ⎿  Cancelled: parallel tool call WebFetch errored
  ⎿  Fetch(url: "https://owasp.org/www-community/xss-filter-evasion-cheatsheet", prompt: "What URL encoding and double
  ⎿  Fetch(url: "https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html", prompt: "What URL
  ⎿  Fetch(url: "https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html", prompt:
  ⎿  Response:
       Now I have sufficient information to synthesize findings. Let me compile the research into a comprehensive answer.

       ---
       Status: FOUND (with some gaps noted per question)

       ---
       Research Findings: Detecting Malicious URL-Encoded Payloads in Security Scanners

       Question 1: Density/Threshold of %XX Sequences

       There is no universally agreed-upon numeric count (e.g., "5 consecutive %XX sequences") in any published standard.
        The research reveals two distinct approaches used by practitioners:

       Pattern-based (CRS/WAF approach): The OWASP Core Rule Set uses binary match/no-match triggers with paranoia
       levels, not numeric density counters. Rules 920230, 920240, and 920270 apply validation operators rather than
       "count ≥ N" thresholds. The CRS escalates across four paranoia levels (PL1-PL4), progressively restricting
       character sets.

       Key practical threshold from the attack literature: The XSS filter evasion cheat sheet shows real payloads like
       %77%77%77%2E%67%6F%6F%67%6C%65%2E%63%6F%6D — this is 8 consecutive %XX sequences encoding "http://www.google.com".
        The suspicious signal there is not raw count but that alphanumeric characters (w, g, o) are being encoded
       unnecessarily.

       Recommended approach for a static scanner: The distinguishing heuristic is not density alone but what is being
       encoded. Two or more consecutive %XX sequences encoding characters from [A-Za-z0-9-._~] (RFC 3986 unreserved
       characters that should never be encoded) is a stronger signal than any density threshold on reserved characters.

       Sources: CRS REQUEST-920 ruleset (raw GitHub), RFC 3986 section 2.3, OWASP XSS Evasion Cheat Sheet,
       PayloadsAllTheThings Directory Traversal README

       ---
       Question 2: Common Evasion Patterns

       The attack literature documents these primary techniques:

       Double encoding: A percent sign is itself encoded as %25, so a second pass encodes %2F (slash) to %252F, %2E (dot)
        to %252E. Real payload example from PayloadsAllTheThings: /%255c%255c..%255c/..%255c/ (double-encoded backslashes
        for directory traversal). The Spring MVC path traversal CVE used exactly this pattern.

       Encoding of unreserved/alphanumeric characters: RFC 3986 says ALPHA (%41-%5A, %61-%7A) and DIGIT (%30-%39) "should
        not be created by URI producers." Encoding a as %61 or e as %65 has no legitimate purpose. The OWASP XSS sheet
       shows %77%77%77 for "www."

       Unicode overlong encoding: Characters represented as multi-byte sequences beyond their shortest form — e.g., / as
       %C0%AF or . as %C0%2E. These exploit decoders that accept overlong UTF-8. Documented in PayloadsAllTheThings and
       OWASP Unicode Encoding attack page.

       Full/half-width Unicode abuse: CRS Rule 920260 specifically targets %uff[0-9a-f]{2} patterns historically used
       against IIS.

       Mixed case: %2F vs %2f — not suspicious by itself (RFC allows either), but mixed case combined with other
       indicators is a signal. CRS applies t:lowercase transformations for this reason.

       Encoding of attack keywords: SELECT → %53%45%4C%45%43%54, <script> → %3C%73%63%72%69%70%74%3E. When a sequence of
       %XX bytes decodes to recognizable injection keywords, that is high-confidence malicious.

       Sources: PayloadsAllTheThings Directory Traversal README, OWASP XSS Filter Evasion Cheat Sheet, CRS REQUEST-920,
       RFC 3986, PortSwigger Web Security Academy (obfuscating attacks using encodings), MDN Percent-encoding

       ---
       Question 3: SAST Tools and WAFs — Legitimate vs. Malicious Encoding

       The fundamental distinction documented across all sources:

       Legitimate encoding (WAF/SAST consider normal):
       - Reserved characters that have syntactic meaning in URLs: : / ? # [ ] @ ! $ & ' ( ) * + , ; = (MDN list)
       - Spaces as %20 or +
       - Non-ASCII characters in query strings or path segments
       - The % character itself encoded as %25 when the percent is literal data

       Malicious encoding signals:
       1. Encoding of unreserved characters (A-Z, a-z, 0-9, -._~) — RFC 3986 explicitly says these "should not be created
        by URI producers." This is the clearest red flag.
       2. Double-encoded sequences: %25XX patterns where %25 is an encoded percent and XX is a hex pair — this only makes
        sense as obfuscation.
       3. Sequences that decode to known attack strings (SQL keywords, script tags, path traversal ../, shell
       metacharacters).
       4. Overlong/invalid UTF-8 sequences encoded as percent bytes (e.g., %C0%AF for /).

       What SAST tools actually do (Semgrep/CRS approach): CRS applies t:urlDecodeUni (normalize) then matches decoded
       content against injection patterns. Semgrep uses metavariable-regex on string literals. Neither SAST-specific tool
        has published built-in rules targeting URL encoding density in source code — this is a gap that custom scanners
       must fill.

       Sources: CRS REQUEST-942 (urlDecodeUni transformation), RFC 3986 section 2.3, MDN Percent-encoding, PortSwigger,
       Semgrep docs

       ---
       Question 4: Best Regex Approach for Source Code Scanning

       Based on the patterns documented across WAF rules and attack literature, the recommended regex hierarchy:

       Core detection pattern (consecutive %XX runs):
       (?:%[0-9A-Fa-f]{2}){2,}
       This matches 2 or more consecutive %XX sequences. Threshold of 2 is supported by attack payloads in the literature
        (single %20 for space is routine; 2+ consecutive is already unusual in source code strings).

       Unreserved-character encoding (high-confidence malicious):
       %(?:4[1-9A-Fa-f]|[5-6][0-9A-Fa-f]|7[0-9Aa])
       More readably: match %[41-5A] (uppercase letters), %[61-7A] (lowercase letters), %[30-39] (digits), %2[Dd] (-),
       %2[Ee] (.), %5[Ff] (_), %7[Ee] (~). Encoding any of these in source code is always suspicious.

       Double encoding detection:
       %25[0-9A-Fa-f]{2}
       %25 is the encoded percent sign. When followed by two more hex chars, this is double encoding. This is documented
       as the specific pattern for %252F, %252E, %255C path traversal payloads.

       Overlong UTF-8 (path traversal):
       %[Cc][0-9A-Fa-f]%[Aa][EeFf]   # covers %C0%AE (..) and %C0%AF (/)

       Sources: PayloadsAllTheThings README, CRS rule 920230 (%[0-9a-fA-F]{2}), RFC 3986, OWASP Encoded Injection
       appendix

       ---
       Question 5: Should the Scanner Detect Double Encoding (%25XX)?

       Yes, definitively. The research is unambiguous:

       The PortSwigger obfuscation guide documents %253C (double-encoded <) as a specific WAF bypass technique: "If the
       back-end server subsequently double-decodes this input, the payload will be successfully injected." The
       PayloadsAllTheThings directory traversal section documents %252e (double-encoded .) and %255c (double-encoded \)
       as real CVE-exploiting patterns. CRS Rule 920230 targets exactly "multiple URL encoding."

       For a static scanner reading source code, %25 followed by two hex digits is particularly suspicious because:
       - %25 as standalone data (literal percent) is legitimate
       - %25XX where XX are hex digits indicates a source-level encoding of an already-encoded sequence — this has no
       legitimate use case in a skill file's hardcoded string

       Regex: %25[0-9A-Fa-f]{2} — simple, high-precision.

       Sources: PortSwigger obfuscation guide, PayloadsAllTheThings Directory Traversal README, CRS REQUEST-920

       ---
       Question 6: Malicious URL Encoding in Agent Skill Files (YAML, Markdown, Python)

       No dedicated research exists specifically on agent skill file encoding attacks — this is a gap in the literature.
       However, the principles from prompt injection research and general encoding attack literature suggest:

       What malicious URL encoding in skill files would look like:

       In YAML/Markdown (skill metadata, system prompts):
       - Hardcoded strings with %XX sequences encoding instruction keywords: %49gnore%20previous%20instructions (encoding
        "I" and space to evade string matching)
       - URL values with encoded path traversal: url: http://evil.com/%2F..%2F..%2Fetc%2Fpasswd
       - Embedded data-exfiltration URLs with encoded query parameters: https://attacker.com/?data=%75%73%65%72%3D
       encoding user=
       - Double-encoded sequences in any string field: %252F, %255C

       In Python (skill implementation):
       - String literals containing percent-encoded data passed to urllib.parse.unquote(), requests.get(), or subprocess
       — the concern is the encoded content being decoded at runtime
       - Obfuscated command injection: os.system(urllib.parse.unquote("%72%6D%20%2D%72%66%20%2F")) decodes to rm -rf /

       Key detection insight: For skill files, the scanner is looking at static source, not runtime traffic. The threat
       model is different from a WAF — the attacker controls the file content and may use encoding to evade the scanner's
        own string-matching rules. Any %XX sequence encoding characters that don't need encoding in a context where URL
       encoding makes no semantic sense (e.g., a YAML string field value, a Python string literal not used as a URL) is
       suspicious.

       Sources: OWASP LLM01 (Prompt Injection), PortSwigger obfuscation guide, OWASP Encoded Injection appendix (Appendix
        D), general encoding attack literature

       ---
       Summary Table

       ┌────────────────────┬──────────────────────────────────────────────────────────────────────────┬─────────────────
       ──────┐
       │      Question      │                                 Finding                                  │      Confidence
             │
       ├────────────────────┼──────────────────────────────────────────────────────────────────────────┼─────────────────
       ──────┤
       │ Density threshold  │ No universal numeric threshold; 2+ consecutive is the practical minimum; │ Medium
             │
       │ for %XX            │  encoding unreserved chars (A-Za-z0-9) is stronger signal                │
             │
       ├────────────────────┼──────────────────────────────────────────────────────────────────────────┼─────────────────
       ──────┤
       │ Common evasion     │ Double encoding (%252F), unreserved char encoding (%61=%a), overlong     │ High
             │
       │ patterns           │ UTF-8 (%C0%AF), full-width Unicode (%uffXX)                              │
             │
       ├────────────────────┼──────────────────────────────────────────────────────────────────────────┼─────────────────
       ──────┤
       │ SAST/WAF           │ Encode-then-match (decode first, then pattern match on decoded content); │ High
             │
       │ distinction        │  unreserved char encoding is primary static signal                       │
             │
       ├────────────────────┼──────────────────────────────────────────────────────────────────────────┼─────────────────
       ──────┤
       │ Best regex         │ (?:%[0-9A-Fa-f]{2}){2,} for runs; %25[0-9A-Fa-f]{2} for double-encoding; │ High
             │
       │ approach           │  unreserved char ranges for alphanumeric encoding                        │
             │
       ├────────────────────┼──────────────────────────────────────────────────────────────────────────┼─────────────────
       ──────┤
       │ Detect double      │ Yes, definitively — %25XX is a documented real-world attack pattern      │ High
             │
       │ encoding           │                                                                          │
             │
       ├────────────────────┼──────────────────────────────────────────────────────────────────────────┼─────────────────
       ──────┤
       │ Skill file         │ Encoded instruction keywords, exfil URLs with encoded params, Python     │ Medium (limited
             │
       │ manifestation      │ string literals decoded at runtime                                       │ specific
       research)    │
       └────────────────────┴──────────────────────────────────────────────────────────────────────────┴─────────────────
       ──────┘

       Confidence: High for questions 2-5 (strong authoritative sources). Medium for questions 1 and 6 (no specific
       numeric standard published; no agent-skill-specific research found).

       Sources:
       - OWASP CRS REQUEST-920:
       https://raw.githubusercontent.com/coreruleset/coreruleset/v4.3.0/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf
       - RFC 3986 section 2.3 (unreserved characters): https://www.rfc-editor.org/rfc/rfc3986#section-2.3
       - PortSwigger obfuscating attacks using encodings:
       https://portswigger.net/web-security/essential-skills/obfuscating-attacks-using-encodings
       - PayloadsAllTheThings Directory Traversal:
       https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Directory%20Traversal/README.md
       - OWASP XSS Filter Evasion Cheat Sheet:
       https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html
       - OWASP WSTG Appendix D Encoded Injection:
       https://owasp.org/www-project-web-security-testing-guide/latest/6-Appendix/D-Encoded_Injection
       - MDN Percent-encoding: https://developer.mozilla.org/en-US/docs/Glossary/Percent-encoding
       - OWASP Unicode Encoding attack: https://owasp.org/www-community/attacks/Unicode_Encoding

       Gaps: No published numeric density threshold standard found. No prior art specifically on URL encoding detection
       in LLM agent skill files (YAML/Markdown) — the threat model is extrapolated from general encoding attack research.
  ⎿  Done (82 tool uses · 29.6k tokens · 12m 8s)
