"""
Zero-Knowledge Regex Engine — Pattern Matching on Encrypted Data
=================================================================

Two-phase encrypted regex search:

Phase 1 (Server-side, Zero-Knowledge):
  - Parse regex pattern into a DFA-like structure
  - Extract literal fragments (fixed substrings) from the pattern
  - Expand character classes [a-z], [0-9] into concrete n-grams
  - Generate HMAC tokens for each fragment
  - Server matches tokens without seeing the pattern

Phase 2 (Client-side, Verification):
  - Decrypt candidate results from Phase 1
  - Apply actual regex to decrypted content
  - Return only true matches

Supported syntax:
  .       — any single character
  *       — zero or more of preceding
  +       — one or more of preceding
  ?       — zero or one of preceding
  [a-z]   — character class (range)
  [0-9]   — digit class
  [abc]   — character set
  [^abc]  — negated set
  (a|b)   — alternation
  ^       — start anchor
  $       — end anchor
  \\d      — digit [0-9]
  \\w      — word char [a-zA-Z0-9_]

Example patterns:
  doc[0-9]+         — "doc" followed by digits
  encrypt(ion|ed)   — "encryption" or "encrypted"
  patient_?name     — "patient" + optional char + "name"
  [a-z]+tion        — any word ending in "tion"
  data.*key         — "data" ... "key" with anything between
"""

import re
import string


# ---------------------------------------------------------------------------
# Pattern analysis — extract searchable fragments from regex
# ---------------------------------------------------------------------------

def extract_literal_fragments(pattern: str) -> list:
    """Extract literal (fixed) substrings from a regex pattern.

    These fragments are the searchable parts that we can generate
    HMAC tokens for. The server matches tokens for these fragments
    without knowing the original regex.

    Returns list of dicts:
        {"text": "literal", "type": "exact"|"ngram"|"prefix"|"suffix"}
    """
    fragments = []

    # Remove anchors (they don't contribute to searchable text)
    clean = pattern.strip("^$")

    # Split on alternation at top level
    alternatives = _split_alternation(clean)

    for alt in alternatives:
        frags = _extract_from_branch(alt)
        fragments.extend(frags)

    # Deduplicate
    seen = set()
    unique = []
    for f in fragments:
        key = f["text"]
        if key not in seen and len(key) >= 2:
            seen.add(key)
            unique.append(f)

    return unique


def _split_alternation(pattern: str) -> list:
    """Split pattern on top-level | (respecting parentheses)."""
    depth = 0
    parts = []
    current = []
    for ch in pattern:
        if ch == '(':
            depth += 1
            current.append(ch)
        elif ch == ')':
            depth -= 1
            current.append(ch)
        elif ch == '|' and depth == 0:
            parts.append(''.join(current))
            current = []
        else:
            current.append(ch)
    parts.append(''.join(current))
    return [p for p in parts if p]


def _extract_from_branch(branch: str) -> list:
    """Extract literal fragments from a single branch of the pattern."""
    fragments = []
    i = 0
    current_literal = []

    while i < len(branch):
        ch = branch[i]

        if ch == '\\' and i + 1 < len(branch):
            # Escape sequence
            next_ch = branch[i + 1]
            if next_ch in ('d', 'w', 's', 'D', 'W', 'S'):
                # Character class shorthand — breaks literal
                if current_literal:
                    fragments.append({"text": ''.join(current_literal), "type": "ngram"})
                    current_literal = []
                i += 2
            else:
                # Escaped literal character
                current_literal.append(next_ch)
                i += 2

        elif ch == '[':
            # Character class — breaks literal but we can expand it
            if current_literal:
                fragments.append({"text": ''.join(current_literal), "type": "ngram"})
                current_literal = []
            # Find closing ]
            j = i + 1
            if j < len(branch) and branch[j] == '^':
                j += 1
            while j < len(branch) and branch[j] != ']':
                j += 1
            i = j + 1

        elif ch == '(':
            # Group — recurse into subpattern
            if current_literal:
                fragments.append({"text": ''.join(current_literal), "type": "ngram"})
                current_literal = []
            # Find matching )
            depth = 1
            j = i + 1
            while j < len(branch) and depth > 0:
                if branch[j] == '(':
                    depth += 1
                elif branch[j] == ')':
                    depth -= 1
                j += 1
            inner = branch[i + 1:j - 1]
            # Process alternation inside group
            for alt in _split_alternation(inner):
                sub_frags = _extract_from_branch(alt)
                fragments.extend(sub_frags)
            i = j

        elif ch in '.+*?{}':
            # Metacharacter — breaks literal
            if ch in '+*?' and current_literal:
                # The quantifier applies to last char — pop it
                last = current_literal.pop()
                if current_literal:
                    fragments.append({"text": ''.join(current_literal), "type": "ngram"})
                    current_literal = []
            elif current_literal:
                fragments.append({"text": ''.join(current_literal), "type": "ngram"})
                current_literal = []
            i += 1

        else:
            # Regular literal character
            current_literal.append(ch)
            i += 1

    if current_literal:
        text = ''.join(current_literal)
        fragments.append({"text": text, "type": "ngram"})

    return fragments


# ---------------------------------------------------------------------------
# Character class expansion — generate concrete strings from [a-z] etc.
# ---------------------------------------------------------------------------

def expand_character_class(pattern: str, max_expansions: int = 50) -> list:
    """Expand a character class into concrete characters.

    [a-z] → ['a','b',...,'z']
    [0-9] → ['0','1',...,'9']
    [abc] → ['a','b','c']
    """
    if not pattern.startswith('[') or not pattern.endswith(']'):
        return [pattern]

    inner = pattern[1:-1]
    negated = False
    if inner.startswith('^'):
        negated = True
        inner = inner[1:]

    chars = set()
    i = 0
    while i < len(inner):
        if i + 2 < len(inner) and inner[i + 1] == '-':
            # Range
            start_c, end_c = inner[i], inner[i + 2]
            for c in range(ord(start_c), ord(end_c) + 1):
                chars.add(chr(c))
            i += 3
        elif inner[i] == '\\' and i + 1 < len(inner):
            nc = inner[i + 1]
            if nc == 'd':
                chars.update(string.digits)
            elif nc == 'w':
                chars.update(string.ascii_letters + string.digits + '_')
            else:
                chars.add(nc)
            i += 2
        else:
            chars.add(inner[i])
            i += 1

    if negated:
        all_printable = set(string.printable) - set(string.whitespace)
        chars = all_printable - chars

    result = sorted(chars)[:max_expansions]
    return result


# ---------------------------------------------------------------------------
# Regex-to-tokens: the core engine
# ---------------------------------------------------------------------------

def regex_to_search_fragments(pattern: str) -> dict:
    """Analyze a regex pattern and produce searchable fragments.

    Returns:
        {
            "pattern": original pattern,
            "compiled": compiled re.Pattern,
            "fragments": [{"text": ..., "type": ...}, ...],
            "alternations": [...],
            "has_wildcards": bool,
            "complexity": "simple"|"moderate"|"complex",
        }
    """
    # Try to compile — validate regex
    try:
        compiled = re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        raise ValueError(f"Invalid regex: {e}")

    fragments = extract_literal_fragments(pattern)

    # Detect alternation groups for separate searching
    alternatives = _split_alternation(pattern.strip("^$"))
    has_wildcards = bool(re.search(r'[.*+?\[\]{}\\()]', pattern))

    # Classify complexity
    if not has_wildcards:
        complexity = "simple"
    elif len(fragments) <= 2:
        complexity = "moderate"
    else:
        complexity = "complex"

    return {
        "pattern": pattern,
        "compiled": compiled,
        "fragments": fragments,
        "alternations": alternatives if len(alternatives) > 1 else [],
        "has_wildcards": has_wildcards,
        "complexity": complexity,
    }


def verify_regex_match(pattern_compiled, text: str) -> list:
    """Apply compiled regex to decrypted text and return all matches.

    This is the Phase 2 (client-side) verification step.
    """
    matches = []
    for m in pattern_compiled.finditer(text):
        matches.append({
            "match": m.group(),
            "start": m.start(),
            "end": m.end(),
            "context": text[max(0, m.start() - 30):m.end() + 30],
        })
    return matches


def get_pattern_description(pattern: str) -> str:
    """Human-readable description of what a regex pattern matches."""
    desc = []
    # Common patterns
    if '\\d' in pattern or '[0-9]' in pattern:
        desc.append("digits")
    if '\\w' in pattern or '[a-z]' in pattern:
        desc.append("letters")
    if '.' in pattern:
        desc.append("any character")
    if '*' in pattern or '+' in pattern:
        desc.append("repeated")
    if '|' in pattern or '(' in pattern:
        desc.append("alternatives")
    if '^' in pattern:
        desc.append("start-anchored")
    if '$' in pattern:
        desc.append("end-anchored")

    frags = extract_literal_fragments(pattern)
    if frags:
        literals = [f["text"] for f in frags[:3]]
        desc.append(f"containing: {', '.join(literals)}")

    return " | ".join(desc) if desc else "custom pattern"
