"""IDN inspector: an offline example plugin for GARBAGE.

For each punycode label (xn--) it reports the Unicode form, the scripts the
label mixes, and, when the characters are common look-alikes of Latin
letters, the ASCII spelling it imitates (a likely homograph target).
"""

import unicodedata
from urllib.parse import urlsplit

# Cyrillic and Greek letters that render like Latin ones in most fonts.
LOOKALIKES = {
    "а": "a", "в": "b", "с": "c", "е": "e", "һ": "h", "і": "i", "ј": "j", "к": "k", "м": "m", "н": "h",
    "о": "o", "р": "p", "ԛ": "q", "ѕ": "s", "т": "t", "у": "y", "х": "x", "ѡ": "w", "ӏ": "l", "ԁ": "d",
    "α": "a", "ο": "o", "ν": "v", "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "κ": "k", "ι": "i", "ε": "e",
}


def script(char):
    if char in "-0123456789":
        return None
    name = unicodedata.name(char, "")
    return name.split(" ")[0] if name else "UNKNOWN"


def run(ctx):
    host = ctx.value if ctx.type == "domain" else (urlsplit(ctx.value).hostname or "")
    labels = host.lower().rstrip(".").split(".")
    findings = []
    imitated = []
    has_idn = False
    for label in labels:
        if not label.startswith("xn--"):
            imitated.append(label)
            continue
        has_idn = True
        try:
            unicode_label = label.encode("ascii").decode("idna")
        except UnicodeError as error:
            findings.append({"result_type": "idn-invalid", "value": label, "data": {"reason": str(error)[:120]}})
            imitated.append(label)
            continue
        scripts = sorted({name for name in map(script, unicode_label) if name})
        findings.append({
            "result_type": "idn-label",
            "value": unicode_label,
            "data": {"punycode": label, "scripts": scripts, "mixed_scripts": len(scripts) > 1},
        })
        imitated.append("".join(LOOKALIKES.get(char, char) for char in unicode_label))
    if not has_idn:
        return [{"result_type": "idn-label", "value": "no internationalised labels", "data": {}}]
    candidate = ".".join(imitated)
    if candidate != host and all(ord(char) < 128 for char in candidate):
        findings.append({
            "result_type": "ascii-lookalike",
            "value": candidate,
            "data": {"meaning": "the ASCII spelling these characters imitate; a possible homograph target"},
        })
    return findings
