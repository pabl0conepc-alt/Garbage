"""A YARA-compatible rule engine for a well-defined subset of the language.

Supported: ``private``/``global`` rules, tags, ``meta``, text strings with
``nocase``, ``wide``, ``ascii``, ``fullword``, ``private`` and ``xor``; hex
strings with wildcards, nibble wildcards, negation, bounded jumps and
alternatives; regular expressions with ``i``/``s`` flags; conditions with
``and``/``or``/``not``, arithmetic and bitwise operators, ``filesize``,
``uintN``/``intN`` (and ``be`` variants), ``$a``, ``#a``, ``@a[i]``, ``!a[i]``,
``at``, ``in``, ``N of``/``any of``/``all of``/``none of`` over strings or
rules, ``for ... of`` and ``for ... in`` loops, ``defined`` and references to
earlier rules. ``import``, ``include``, modules, ``base64`` and ``entrypoint``
are rejected or undefined with a clear message.

Results were compared with YARA 4.5.5 on the rules in the test suite. Text
patterns become ``re`` byte patterns, so matching itself runs in CPython's C
regex engine. Because a hostile pattern can still take a long time, callers
outside tests use :func:`run_isolated`, which scans in a separate process with
a deadline.

A matching rule means the bytes fit the author's pattern. It is not a verdict.
"""

from __future__ import annotations

import multiprocessing
import re
import struct
from dataclasses import dataclass, field
from typing import Any

MAX_SOURCE = 256 * 1024
MAX_RULES = 500
MAX_STRINGS = 10_000
MAX_MATCHES_PER_STRING = 10_000
MAX_JUMP = 65_536
MAX_REPORTED_MATCHES = 10


class YaraError(ValueError):
    def __init__(self, message: str, line: int = 0) -> None:
        super().__init__(f"line {line}: {message}" if line else message)
        self.line = line


@dataclass
class YaraString:
    identifier: str
    pattern: re.Pattern[bytes]
    literal: bytes | None
    fullword: bool
    private: bool
    kind: str


@dataclass
class YaraRule:
    name: str
    tags: list[str]
    meta: dict[str, Any]
    strings: list[YaraString]
    condition: Any
    private: bool = False
    is_global: bool = False


@dataclass
class RuleSet:
    rules: list[YaraRule] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Lexing helpers

_KEYWORDS = {
    "all", "and", "any", "at", "condition", "contains", "defined", "endswith", "entrypoint", "false",
    "filesize", "for", "global", "icontains", "iendswith", "iequals", "import", "in", "include",
    "istartswith", "matches", "meta", "none", "not", "of", "or", "private", "rule", "startswith",
    "strings", "them", "true",
}
_INT_FUNCTIONS = {
    "uint8": ("<B", 1), "uint16": ("<H", 2), "uint32": ("<I", 4),
    "int8": ("<b", 1), "int16": ("<h", 2), "int32": ("<i", 4),
    "uint8be": (">B", 1), "uint16be": (">H", 2), "uint32be": (">I", 4),
    "int8be": (">b", 1), "int16be": (">h", 2), "int32be": (">i", 4),
}
_TEXT_ESCAPES = {"n": b"\n", "t": b"\t", "r": b"\r", '"': b'"', "\\": b"\\"}


class _Source:
    def __init__(self, text: str) -> None:
        self.text = text
        self.position = 0

    @property
    def line(self) -> int:
        return self.text.count("\n", 0, self.position) + 1

    def error(self, message: str) -> YaraError:
        return YaraError(message, self.line)

    def skip(self) -> None:
        text = self.text
        while self.position < len(text):
            character = text[self.position]
            if character in " \t\r\n":
                self.position += 1
            elif text.startswith("//", self.position):
                end = text.find("\n", self.position)
                self.position = len(text) if end == -1 else end
            elif text.startswith("/*", self.position):
                end = text.find("*/", self.position + 2)
                if end == -1:
                    raise self.error("unterminated comment")
                self.position = end + 2
            else:
                break

    def peek(self, token: str) -> bool:
        self.skip()
        if not self.text.startswith(token, self.position):
            return False
        if token[-1].isalnum() or token[-1] == "_":
            after = self.text[self.position + len(token) : self.position + len(token) + 1]
            return not (after.isalnum() or after == "_")
        return True

    def accept(self, token: str) -> bool:
        if self.peek(token):
            self.position += len(token)
            return True
        return False

    def expect(self, token: str) -> None:
        if not self.accept(token):
            found = self.text[self.position : self.position + 20].split("\n", 1)[0]
            raise self.error(f"expected '{token}' near '{found}'")

    def identifier(self) -> str:
        self.skip()
        match = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}").match(self.text, self.position)
        if not match:
            raise self.error("expected an identifier")
        self.position = match.end()
        return match.group(0)

    def match(self, pattern: str) -> re.Match[str] | None:
        self.skip()
        found = re.compile(pattern).match(self.text, self.position)
        if found:
            self.position = found.end()
        return found

    def text_string(self) -> bytes:
        self.skip()
        if self.text[self.position : self.position + 1] != '"':
            raise self.error("expected a quoted string")
        self.position += 1
        out = bytearray()
        while True:
            if self.position >= len(self.text):
                raise self.error("unterminated string")
            character = self.text[self.position]
            if character == '"':
                self.position += 1
                return bytes(out)
            if character == "\n":
                raise self.error("newline in string")
            if character == "\\":
                following = self.text[self.position + 1 : self.position + 2]
                if following in _TEXT_ESCAPES:
                    out += _TEXT_ESCAPES[following]
                    self.position += 2
                elif following == "x" and re.fullmatch(r"[0-9A-Fa-f]{2}", self.text[self.position + 2 : self.position + 4]):
                    out.append(int(self.text[self.position + 2 : self.position + 4], 16))
                    self.position += 4
                else:
                    raise self.error(f"unknown escape '\\{following}'")
                continue
            out += character.encode("utf-8")
            self.position += 1


# ---------------------------------------------------------------------------
# String patterns


def _hex_pattern(body: str, source: _Source) -> bytes:
    tokens = re.findall(r"~?[0-9A-Fa-f?]{2}|\[[^\]]*\]|[()|]|\S", body)
    if not tokens:
        raise source.error("empty hex string")
    out: list[bytes] = []
    depth = 0
    previous = ""
    for token in tokens:
        if token == "(":
            depth += 1
            out.append(b"(?:")
        elif token == ")":
            depth -= 1
            if depth < 0:
                raise source.error("unbalanced ')' in hex string")
            out.append(b")")
        elif token == "|":
            if depth == 0:
                raise source.error("'|' outside an alternative in hex string")
            out.append(b"|")
        elif token.startswith("["):
            jump = re.fullmatch(r"\[\s*(\d*)\s*(-?)\s*(\d*)\s*\]", token)
            if not jump:
                raise source.error(f"invalid jump {token}")
            low = int(jump.group(1) or 0)
            if jump.group(2):
                if not jump.group(3):
                    raise source.error(f"unbounded jump {token}: give an upper bound up to {MAX_JUMP}")
                high = int(jump.group(3))
            else:
                high = low
            if high < low or high > MAX_JUMP:
                raise source.error(f"invalid jump {token}")
            out.append(b".{%d,%d}?" % (low, high))
        else:
            negate = token.startswith("~")
            value = token[1:] if negate else token
            if not re.fullmatch(r"[0-9A-Fa-f?]{2}", value) or (negate and value == "??"):
                raise source.error(f"invalid hex token '{token}'")
            if value == "??":
                out.append(b".")
            elif "?" not in value:
                byte = int(value, 16)
                out.append(b"[^\\x%02x]" % byte if negate else re.escape(bytes([byte])))
            else:
                if value[0] == "?":
                    choices = [int(f"{high:x}{value[1]}", 16) for high in range(16)]
                else:
                    choices = [int(f"{value[0]}{low:x}", 16) for low in range(16)]
                body_class = b"".join(b"\\x%02x" % choice for choice in choices)
                out.append(b"[^" + body_class + b"]" if negate else b"[" + body_class + b"]")
        previous = token
    if depth:
        raise source.error("unbalanced '(' in hex string")
    if tokens[0].startswith("[") or previous.startswith("["):
        raise source.error("hex strings cannot start or end with a jump")
    return b"".join(out)


def _reject_nested_repeats(pattern: bytes, flags: int, source: _Source) -> None:
    """Refuse classic catastrophic patterns such as (a+)+ or (a*)*."""
    try:
        from re import _parser as parser  # type: ignore[attr-defined]
    except ImportError:  # Python < 3.11
        import sre_parse as parser  # type: ignore[no-redef]
    try:
        tree = parser.parse(pattern, flags)
    except re.error as exc:
        raise source.error(f"invalid regular expression: {exc}") from exc
    unbounded = parser.MAXREPEAT

    def walk(items: Any, inside_unbounded: bool) -> None:
        for operation, value in items:
            name = str(operation)
            if name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
                low, high, sub = value
                is_unbounded = high == unbounded or high > 1000
                if inside_unbounded and is_unbounded:
                    raise source.error("nested unbounded repetition can take exponential time; rewrite the expression")
                walk(sub, inside_unbounded or is_unbounded)
            elif name == "SUBPATTERN":
                walk(value[-1], inside_unbounded)
            elif name == "BRANCH":
                for branch in value[1]:
                    walk(branch, inside_unbounded)
            elif name in ("ASSERT", "ASSERT_NOT"):
                walk(value[1], inside_unbounded)

    walk(tree, False)


def _string_definition(source: _Source, identifier: str) -> YaraString:
    source.skip()
    character = source.text[source.position : source.position + 1]
    modifiers: dict[str, Any] = {}
    if character == '"':
        literal = source.text_string()
        kind = "text"
    elif character == "{":
        end = source.text.find("}", source.position)
        if end == -1:
            raise source.error("unterminated hex string")
        body = source.text[source.position + 1 : end]
        source.position = end + 1
        pattern = _hex_pattern(body, source)
        kind = "hex"
    elif character == "/":
        position = source.position + 1
        while position < len(source.text) and source.text[position] != "/":
            if source.text[position] == "\n":
                raise source.error("newline in regular expression")
            position += 2 if source.text[position] == "\\" else 1
        if position >= len(source.text):
            raise source.error("unterminated regular expression")
        body = source.text[source.position + 1 : position]
        source.position = position + 1
        flag_text = source.match(r"[is]*")
        regex_flags = flag_text.group(0) if flag_text else ""
        kind = "regex"
    else:
        raise source.error("expected a text, hex or regular expression string")

    while True:
        source.skip()
        word = re.compile(r"[a-z0-9]+").match(source.text, source.position)
        if not word or word.group(0) not in {"nocase", "wide", "ascii", "fullword", "private", "xor", "base64", "base64wide"}:
            break
        source.position = word.end()
        name = word.group(0)
        if name in ("base64", "base64wide"):
            raise source.error(f"the {name} modifier is not supported")
        if name == "xor":
            low, high = 0, 255
            if source.accept("("):
                low = int(source.match(r"0x[0-9A-Fa-f]+|\d+").group(0), 0)
                high = int(source.match(r"0x[0-9A-Fa-f]+|\d+").group(0), 0) if source.accept("-") else low
                source.expect(")")
            if not 0 <= low <= high <= 255:
                raise source.error("xor range must be within 0-255")
            modifiers["xor"] = (low, high)
        else:
            modifiers[name] = True

    if kind != "text" and set(modifiers) & {"xor", "wide", "ascii", "nocase"} - ({"nocase", "ascii"} if kind == "regex" else set()):
        raise source.error(f"modifier not supported on {kind} strings in this engine")
    if "xor" in modifiers and "nocase" in modifiers:
        raise source.error("xor and nocase cannot be combined")

    flags = re.DOTALL if kind == "hex" else 0
    literal_value: bytes | None = None
    if kind == "text":
        if not literal:
            raise source.error("empty string")
        forms = []
        if modifiers.get("ascii") or not modifiers.get("wide"):
            forms.append(literal)
        if modifiers.get("wide"):
            forms.append(b"".join(bytes([byte, 0]) for byte in literal))
        variants: list[bytes] = []
        if "xor" in modifiers:
            low, high = modifiers["xor"]
            for form in forms:
                variants.extend(bytes(byte ^ key for byte in form) for key in range(low, high + 1))
        else:
            variants = forms
        variants = list(dict.fromkeys(variants))
        pattern = b"|".join(re.escape(variant) for variant in variants)
        if modifiers.get("nocase"):
            flags |= re.IGNORECASE
        elif len(variants) == 1:
            literal_value = variants[0]
    elif kind == "regex":
        pattern = body.encode("utf-8")
        if "i" in regex_flags or modifiers.get("nocase"):
            flags |= re.IGNORECASE
        if "s" in regex_flags:
            flags |= re.DOTALL
        _reject_nested_repeats(pattern, flags, source)
    try:
        compiled = re.compile(pattern, flags)
    except re.error as exc:
        raise source.error(f"invalid pattern for {identifier}: {exc}") from exc
    return YaraString(identifier, compiled, literal_value, bool(modifiers.get("fullword")), bool(modifiers.get("private")), kind)


# ---------------------------------------------------------------------------
# Condition parsing (AST as tuples)


class _ConditionParser:
    def __init__(self, source: _Source, rule_strings: list[str], known_rules: set[str]) -> None:
        self.source = source
        self.strings = rule_strings
        self.rules = known_rules
        self.variables: list[set[str]] = []
        self.in_string_loop = 0

    def parse(self) -> Any:
        return self.expression()

    def expression(self) -> Any:
        left = self.conjunction()
        while self.source.accept("or"):
            left = ("or", left, self.conjunction())
        return left

    def conjunction(self) -> Any:
        left = self.negation()
        while self.source.accept("and"):
            left = ("and", left, self.negation())
        return left

    def negation(self) -> Any:
        if self.source.accept("not"):
            return ("not", self.negation())
        if self.source.accept("defined"):
            return ("defined", self.negation())
        return self.comparison()

    def comparison(self) -> Any:
        left = self.bitwise()
        for operator in ("==", "!=", "<=", ">=", "<", ">"):
            if self.source.accept(operator):
                return ("cmp", operator, left, self.bitwise())
        for operator in ("contains", "icontains", "startswith", "istartswith", "endswith", "iendswith", "iequals", "matches"):
            if self.source.accept(operator):
                if operator == "matches":
                    self.source.skip()
                    raise self.source.error("'matches' needs module strings, which are not supported")
                return ("text", operator, left, self.bitwise())
        return left

    def bitwise(self) -> Any:
        left = self.shift()
        while True:
            for operator in ("|", "^", "&"):
                if self.source.peek(operator) and not self.source.peek("||"):
                    self.source.accept(operator)
                    left = ("bin", operator, left, self.shift())
                    break
            else:
                return left

    def shift(self) -> Any:
        left = self.additive()
        while True:
            if self.source.accept("<<"):
                left = ("bin", "<<", left, self.additive())
            elif self.source.accept(">>"):
                left = ("bin", ">>", left, self.additive())
            else:
                return left

    def additive(self) -> Any:
        left = self.term()
        while True:
            if self.source.accept("+"):
                left = ("bin", "+", left, self.term())
            elif self.source.peek("-") and not self.source.peek("--"):
                self.source.accept("-")
                left = ("bin", "-", left, self.term())
            else:
                return left

    def _percent_of(self) -> bool:
        self.source.skip()
        return bool(re.compile(r"%\s*of\b").match(self.source.text, self.source.position))

    def term(self) -> Any:
        left = self.unary()
        while True:
            for operator in ("*", "\\", "%"):
                if operator == "%" and self._percent_of():
                    continue
                if self.source.accept(operator):
                    left = ("bin", operator, left, self.unary())
                    break
            else:
                return left

    def unary(self) -> Any:
        if self.source.accept("-"):
            return ("neg", self.unary())
        if self.source.accept("~"):
            return ("inv", self.unary())
        return self.primary()

    def _string_ref(self, sigil: str) -> str:
        source = self.source
        match = re.compile(r"[A-Za-z0-9_]*").match(source.text, source.position)
        name = match.group(0) if match else ""
        source.position = match.end() if match else source.position
        if not name:
            if not self.in_string_loop:
                raise source.error(f"anonymous '{sigil}' is only valid inside 'for ... of'")
            return ""
        identifier = "$" + name
        if identifier not in self.strings:
            raise source.error(f"undefined string {sigil}{name}")
        return identifier

    def _index(self) -> Any:
        if self.source.accept("["):
            value = self.expression()
            self.source.expect("]")
            return value
        return ("int", 1)

    def _range(self) -> tuple[Any, Any]:
        self.source.expect("(")
        low = self.expression()
        self.source.expect("..")
        high = self.expression()
        self.source.expect(")")
        return low, high

    def _quantifier(self) -> Any:
        for word in ("all", "any", "none"):
            if self.source.accept(word):
                return (word,)
        value = self.additive()
        if self._percent_of():
            self.source.accept("%")
            return ("percent", value)
        return ("count", value)

    def _string_set(self) -> tuple[str, list[str]]:
        if self.source.accept("them"):
            if not self.strings:
                raise self.source.error("'them' used in a rule without strings")
            return "strings", list(self.strings)
        self.source.expect("(")
        members: list[str] = []
        kind = ""
        while True:
            self.source.skip()
            if self.source.accept("$"):
                found = self.source.match(r"[A-Za-z0-9_]*\*?")
                pattern = "$" + (found.group(0) if found else "")
                selected = [name for name in self.strings if (name.startswith(pattern[:-1]) if pattern.endswith("*") else name == pattern)]
                if not selected:
                    raise self.source.error(f"no strings match {pattern}")
                members.extend(selected)
                kind = kind or "strings"
            else:
                found = self.source.match(r"[A-Za-z_][A-Za-z0-9_]*\*?")
                if not found:
                    raise self.source.error("expected strings or rule names in the set")
                pattern = found.group(0)
                selected = [name for name in self.rules if (name.startswith(pattern[:-1]) if pattern.endswith("*") else name == pattern)]
                if not selected:
                    raise self.source.error(f"no earlier rules match {pattern}")
                members.extend(selected)
                kind = kind or "rules"
            if not self.source.accept(","):
                break
        self.source.expect(")")
        return kind, list(dict.fromkeys(members))

    def primary(self) -> Any:
        source = self.source
        source.skip()
        if source.accept("("):
            value = self.expression()
            source.expect(")")
            return value
        if source.accept("true"):
            return ("bool", True)
        if source.accept("false"):
            return ("bool", False)
        if source.accept("filesize"):
            return ("filesize",)
        if source.accept("entrypoint"):
            return ("undefined",)
        number = source.match(r"0x[0-9A-Fa-f]+|0o[0-7]+|\d+(?:KB|MB)?")
        if number:
            text = number.group(0)
            if text.endswith("KB"):
                value = int(text[:-2]) * 1024
            elif text.endswith("MB"):
                value = int(text[:-2]) * 1024 * 1024
            else:
                value = int(text, 0) if text.startswith(("0x", "0o")) else int(text)
            if self._percent_of():
                source.accept("%")
                return self._of_expression(("percent", ("int", value)))
            if source.peek("of"):
                return self._of_expression(("count", ("int", value)))
            return ("int", value)
        if source.text.startswith('"', source.position):
            return ("str", source.text_string())
        for sigil in ("$", "#", "@", "!"):
            if source.text.startswith(sigil, source.position):
                source.position += 1
                name = self._string_ref(sigil)
                if sigil == "$":
                    if source.accept("at"):
                        return ("at", name, self.unary())
                    if source.peek("in"):
                        source.accept("in")
                        return ("in", name, *self._range())
                    return ("present", name)
                if sigil == "#":
                    if source.peek("in"):
                        source.accept("in")
                        return ("count_in", name, *self._range())
                    return ("count", name)
                return ("offset" if sigil == "@" else "length", name, self._index())
        if source.peek("for"):
            source.accept("for")
            return self._for()
        for word in ("all", "any", "none"):
            if source.peek(word):
                source.accept(word)
                return self._of_expression((word,))
        if source.peek("import") or source.peek("include"):
            raise source.error("modules and includes are not supported")
        name = source.identifier()
        if name in _INT_FUNCTIONS:
            source.expect("(")
            argument = self.expression()
            source.expect(")")
            return ("read", name, argument)
        for scope in reversed(self.variables):
            if name in scope:
                return ("var", name)
        if name in self.rules:
            return ("rule", name)
        if name in _KEYWORDS:
            raise source.error(f"unexpected keyword '{name}'")
        raise source.error(f"unknown identifier '{name}' (modules are not supported)")

    def _of_expression(self, quantifier: Any) -> Any:
        self.source.expect("of")
        kind, members = self._string_set()
        if kind == "rules":
            return ("of_rules", quantifier, members)
        if self.source.peek("in"):
            self.source.accept("in")
            return ("of", quantifier, members, ("in", *self._range()))
        if self.source.accept("at"):
            return ("of", quantifier, members, ("at", self.unary()))
        return ("of", quantifier, members, None)

    def _for(self) -> Any:
        quantifier = self._quantifier()
        if self.source.accept("of"):
            kind, members = self._string_set()
            if kind != "strings":
                raise self.source.error("'for ... of' needs a string set")
            self.source.expect(":")
            self.source.expect("(")
            self.in_string_loop += 1
            body = self.expression()
            self.in_string_loop -= 1
            self.source.expect(")")
            return ("for_of", quantifier, members, body)
        names = [self.source.identifier()]
        while self.source.accept(","):
            names.append(self.source.identifier())
        if len(names) != 1:
            raise self.source.error("only one loop variable is supported")
        self.source.expect("in")
        self.source.expect("(")
        first = self.expression()
        if self.source.accept(".."):
            iterable = ("range", first, self.expression())
        else:
            items = [first]
            while self.source.accept(","):
                items.append(self.expression())
            iterable = ("list", items)
        self.source.expect(")")
        self.source.expect(":")
        self.source.expect("(")
        self.variables.append(set(names))
        body = self.expression()
        self.variables.pop()
        self.source.expect(")")
        return ("for_in", quantifier, names[0], iterable, body)


# ---------------------------------------------------------------------------
# Compilation


def compile_rules(text: str) -> RuleSet:
    if not isinstance(text, str) or not text.strip():
        raise YaraError("rule source is empty")
    if len(text.encode("utf-8")) > MAX_SOURCE:
        raise YaraError(f"rule source exceeds {MAX_SOURCE // 1024} KiB")
    source = _Source(text)
    ruleset = RuleSet()
    names: set[str] = set()
    string_total = 0
    while True:
        source.skip()
        if source.position >= len(text):
            break
        if source.peek("import") or source.peek("include"):
            raise source.error("modules and includes are not supported")
        private = is_global = False
        while True:
            if source.accept("private"):
                private = True
            elif source.accept("global"):
                is_global = True
            else:
                break
        source.expect("rule")
        name = source.identifier()
        if name in _KEYWORDS or name in _INT_FUNCTIONS:
            raise source.error(f"'{name}' is a reserved word")
        if name in names:
            raise source.error(f"duplicate rule '{name}'")
        tags: list[str] = []
        if source.accept(":"):
            while not source.peek("{"):
                tags.append(source.identifier())
        source.expect("{")
        meta: dict[str, Any] = {}
        if source.accept("meta"):
            source.expect(":")
            while not (source.peek("strings") or source.peek("condition")):
                key = source.identifier()
                source.expect("=")
                source.skip()
                if source.text.startswith('"', source.position):
                    meta[key] = source.text_string().decode("utf-8", errors="replace")
                elif source.accept("true"):
                    meta[key] = True
                elif source.accept("false"):
                    meta[key] = False
                else:
                    number = source.match(r"-?(?:0x[0-9A-Fa-f]+|\d+)")
                    if not number:
                        raise source.error(f"invalid value for meta '{key}'")
                    meta[key] = int(number.group(0), 0)
        strings: list[YaraString] = []
        if source.accept("strings"):
            source.expect(":")
            anonymous = 0
            while source.accept("$"):
                found = re.compile(r"[A-Za-z0-9_]*").match(text, source.position)
                label = found.group(0)
                source.position = found.end()
                if not label:
                    anonymous += 1
                    identifier = f"$__anonymous{anonymous}"
                else:
                    identifier = "$" + label
                if any(item.identifier == identifier for item in strings):
                    raise source.error(f"duplicate string {identifier}")
                source.expect("=")
                strings.append(_string_definition(source, identifier))
            string_total += len(strings)
            if string_total > MAX_STRINGS:
                raise source.error(f"more than {MAX_STRINGS} strings")
        source.expect("condition")
        source.expect(":")
        parser = _ConditionParser(source, [item.identifier for item in strings], set(names))
        condition = parser.parse()
        source.expect("}")
        names.add(name)
        ruleset.rules.append(YaraRule(name, tags, meta, strings, condition, private, is_global))
        if len(ruleset.rules) > MAX_RULES:
            raise source.error(f"more than {MAX_RULES} rules")
    if not ruleset.rules:
        raise YaraError("no rules defined")
    return ruleset


# ---------------------------------------------------------------------------
# Scanning


def _is_word(byte: int) -> bool:
    return 48 <= byte <= 57 or 65 <= byte <= 90 or 97 <= byte <= 122 or byte == 95


def _find_matches(string: YaraString, data: bytes) -> tuple[list[tuple[int, int]], bool]:
    matches: list[tuple[int, int]] = []
    position = 0
    while len(matches) < MAX_MATCHES_PER_STRING:
        if string.literal is not None:
            start = data.find(string.literal, position)
            if start == -1:
                break
            end = start + len(string.literal)
        else:
            found = string.pattern.search(data, position)
            if not found:
                break
            start, end = found.span()
        position = start + 1
        if string.fullword and ((start > 0 and _is_word(data[start - 1])) or (end < len(data) and _is_word(data[end]))):
            continue
        matches.append((start, end - start))
    return matches, len(matches) >= MAX_MATCHES_PER_STRING


class _Context:
    def __init__(self, data: bytes, matches: dict[str, list[tuple[int, int]]], results: dict[str, bool]) -> None:
        self.data = data
        self.matches = matches
        self.results = results
        self.variables: dict[str, Any] = {}
        self.current = ""


def _truth(value: Any) -> bool:
    return bool(value) if value is not None else False


def _quantified(quantifier: Any, outcomes: list[Any], context: _Context) -> Any:
    passed = sum(1 for value in outcomes if _truth(value))
    total = len(outcomes)
    kind = quantifier[0]
    if kind == "all":
        return passed == total
    if kind == "any":
        return passed >= 1
    if kind == "none":
        return passed == 0
    needed = _evaluate(quantifier[1], context)
    if needed is None:
        return None
    if kind == "percent":
        return passed * 100 >= needed * total
    return passed >= needed


def _evaluate(node: Any, context: _Context) -> Any:
    kind = node[0]
    if kind in ("bool", "int", "str"):
        return node[1]
    if kind == "filesize":
        return len(context.data)
    if kind == "undefined":
        return None
    if kind == "and":
        return _truth(_evaluate(node[1], context)) and _truth(_evaluate(node[2], context))
    if kind == "or":
        return _truth(_evaluate(node[1], context)) or _truth(_evaluate(node[2], context))
    if kind == "not":
        value = _evaluate(node[1], context)
        return None if value is None else not value
    if kind == "defined":
        return _evaluate(node[1], context) is not None
    if kind in ("cmp", "bin", "text"):
        left = _evaluate(node[2], context)
        right = _evaluate(node[3], context)
        if left is None or right is None:
            return None
        operator = node[1]
        if kind == "text":
            if not isinstance(left, bytes) or not isinstance(right, bytes):
                return None
            if operator.startswith("i"):
                left, right, operator = left.lower(), right.lower(), operator[1:]
            return {
                "contains": right in left,
                "startswith": left.startswith(right),
                "endswith": left.endswith(right),
                "equals": left == right,
            }[operator]
        if kind == "cmp":
            if isinstance(left, bool) or isinstance(right, bool):
                left, right = int(left), int(right)
            if type(left) is not type(right):
                return None
            return {
                "==": left == right, "!=": left != right, "<": left < right,
                "<=": left <= right, ">": left > right, ">=": left >= right,
            }[operator]
        if not isinstance(left, int) or not isinstance(right, int):
            return None
        if operator in ("\\", "%") and right == 0:
            return None
        if operator in ("<<", ">>") and right < 0:
            return None
        value = {
            "+": lambda: left + right, "-": lambda: left - right, "*": lambda: left * right,
            "\\": lambda: int(left / right), "%": lambda: left - int(left / right) * right,
            "&": lambda: left & right, "|": lambda: left | right, "^": lambda: left ^ right,
            "<<": lambda: left << right if right < 64 else 0, ">>": lambda: left >> right if right < 64 else 0,
        }[operator]()
        return ((value + 2**63) % 2**64) - 2**63
    if kind == "neg":
        value = _evaluate(node[1], context)
        return None if not isinstance(value, int) else -value
    if kind == "inv":
        value = _evaluate(node[1], context)
        return None if not isinstance(value, int) else ~value
    if kind == "read":
        offset = _evaluate(node[2], context)
        layout, size = _INT_FUNCTIONS[node[1]]
        if not isinstance(offset, int) or offset < 0 or offset + size > len(context.data):
            return None
        return struct.unpack_from(layout, context.data, offset)[0]
    if kind == "var":
        return context.variables.get(node[1])
    if kind == "rule":
        return context.results.get(node[1], False)
    name = node[1] if len(node) > 1 and isinstance(node[1], str) else ""
    if kind in ("present", "at", "in", "count", "count_in", "offset", "length"):
        hits = context.matches.get(name or context.current, [])
        if kind == "present":
            return bool(hits)
        if kind == "count":
            return len(hits)
        if kind == "at":
            where = _evaluate(node[2], context)
            return None if where is None else any(offset == where for offset, _ in hits)
        if kind in ("in", "count_in"):
            low, high = _evaluate(node[2], context), _evaluate(node[3], context)
            if low is None or high is None:
                return None
            inside = sum(1 for offset, _ in hits if low <= offset <= high)
            return inside if kind == "count_in" else inside > 0
        index = _evaluate(node[2], context)
        if not isinstance(index, int) or not 1 <= index <= len(hits):
            return None
        return hits[index - 1][0 if kind == "offset" else 1]
    if kind == "of":
        _, quantifier, members, where = node
        outcomes = []
        for member in members:
            hits = context.matches.get(member, [])
            if where is None:
                outcomes.append(bool(hits))
            elif where[0] == "at":
                position = _evaluate(where[1], context)
                outcomes.append(None if position is None else any(offset == position for offset, _ in hits))
            else:
                low, high = _evaluate(where[1], context), _evaluate(where[2], context)
                outcomes.append(None if low is None or high is None else any(low <= offset <= high for offset, _ in hits))
        return _quantified(quantifier, outcomes, context)
    if kind == "of_rules":
        return _quantified(node[1], [context.results.get(member, False) for member in node[2]], context)
    if kind == "for_of":
        _, quantifier, members, body = node
        outcomes = []
        saved = context.current
        for member in members:
            context.current = member
            outcomes.append(_evaluate(body, context))
        context.current = saved
        return _quantified(quantifier, outcomes, context)
    if kind == "for_in":
        _, quantifier, variable, iterable, body = node
        if iterable[0] == "range":
            low, high = _evaluate(iterable[1], context), _evaluate(iterable[2], context)
            if not isinstance(low, int) or not isinstance(high, int):
                return None
            if high - low > 1_000_000:
                return None
            values: list[Any] = list(range(low, high + 1))
        else:
            values = [_evaluate(item, context) for item in iterable[1]]
        saved = context.variables.get(variable)
        outcomes = []
        for value in values:
            context.variables[variable] = value
            outcomes.append(_evaluate(body, context))
        context.variables[variable] = saved
        return _quantified(quantifier, outcomes, context)
    raise YaraError(f"unsupported expression {kind}")


def _preview(data: bytes, offset: int, length: int) -> dict[str, Any]:
    chunk = data[offset : offset + min(length, 48)]
    return {
        "offset": offset,
        "length": length,
        "hex": chunk.hex(),
        "text": "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk),
    }


def scan(ruleset: RuleSet, data: bytes) -> dict[str, Any]:
    """Evaluate every rule; return the matching, non-private rules."""
    results: dict[str, bool] = {}
    matched: list[dict[str, Any]] = []
    capped: list[str] = []
    cache: dict[int, tuple[list[tuple[int, int]], bool]] = {}
    for rule in ruleset.rules:
        matches: dict[str, list[tuple[int, int]]] = {}
        for string in rule.strings:
            key = id(string)
            if key not in cache:
                cache[key] = _find_matches(string, data)
            matches[string.identifier] = cache[key][0]
            if cache[key][1]:
                capped.append(f"{rule.name}:{string.identifier}")
        outcome = _truth(_evaluate(rule.condition, _Context(data, matches, results)))
        results[rule.name] = outcome
        if not outcome or rule.private:
            continue
        matched.append(
            {
                "rule": rule.name,
                "tags": rule.tags,
                "meta": rule.meta,
                "global": rule.is_global,
                "strings": [
                    {
                        "identifier": "$" if string.identifier.startswith("$__anonymous") else string.identifier,
                        "count": len(matches[string.identifier]),
                        "matches": [_preview(data, offset, length) for offset, length in matches[string.identifier][:MAX_REPORTED_MATCHES]],
                    }
                    for string in rule.strings
                    if matches[string.identifier] and not string.private
                ],
            }
        )
    global_rules = [rule.name for rule in ruleset.rules if rule.is_global]
    if global_rules and not all(results[name] for name in global_rules):
        matched = []
    return {"matches": matched, "capped_strings": capped}


def _isolated_worker(connection: Any, sources: list[tuple[str, str, str]], data: bytes) -> None:
    output = []
    for identifier, name, text in sources:
        try:
            result = scan(compile_rules(text), data)
            output.append({"ruleset_id": identifier, "ruleset": name, **result, "error": ""})
        except YaraError as exc:
            output.append({"ruleset_id": identifier, "ruleset": name, "matches": [], "capped_strings": [], "error": str(exc)})
    connection.send(output)
    connection.close()


def run_isolated(sources: list[tuple[str, str, str]], data: bytes, timeout: float = 20.0) -> dict[str, Any]:
    """Scan in a child process so a runaway pattern cannot stall the server.

    ``sources`` holds ``(ruleset_id, name, source)`` triples."""
    if not sources:
        return {"rulesets": [], "timed_out": False}
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(target=_isolated_worker, args=(sender, sources, data), daemon=True)
    process.start()
    sender.close()
    output = None
    if receiver.poll(timeout):
        try:
            output = receiver.recv()
        except EOFError:
            output = None
    process.join(1)
    if process.is_alive():
        process.terminate()
        process.join(1)
    receiver.close()
    if output is None:
        return {
            "rulesets": [
                {"ruleset_id": identifier, "ruleset": name, "matches": [], "capped_strings": [], "error": f"scan stopped after {timeout:g} s"}
                for identifier, name, _ in sources
            ],
            "timed_out": True,
        }
    return {"rulesets": output, "timed_out": False}
