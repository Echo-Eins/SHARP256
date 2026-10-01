#!/usr/bin/env python3
"""What the shards of a cargo-mutants run found, together (.github/workflows/
mutants.yml, docs/MUTANTS.md).

    python3 scripts/mutants-summary.py DIR OUT

DIR holds the shards' output directories (each with caught.txt, missed.txt,
timeout.txt and unviable.txt, as cargo-mutants writes them), anywhere below
it. Writes into OUT the four lists merged, and summary.md: the counts, the
missed mutants by file, and every missed one.

A missed mutant in code the run does not compile changed nothing that ran:
code under a #[cfg] that is false on Linux x86_64 with every feature (for
Windows, macOS, another architecture, Miri, loom, or without a feature).
Those are listed apart, as "not compiled here": the #[cfg] attributes above
the blocks that hold the mutant (which rustfmt's indentation shows) are
evaluated, and only one that is false for certain counts (`test` is taken
as unknown: the library is built with it for its own tests and without it
for the others). A reading of the source, not of the compiler: the list is
to be looked through, not believed.
"""

import os
import re
import sys
from collections import Counter
from pathlib import Path

KINDS = ("caught", "missed", "timeout", "unviable")

# What holds where the run is: Linux on x86_64, every feature on.
FACTS = {
    "unix": True,
    "windows": False,
    "debug_assertions": True,
    "miri": False,
    "loom": False,
    "sharp_loom": False,
    "fuzzing": False,
}
VALUES = {
    "target_os": "linux",
    "target_family": "unix",
    "target_arch": "x86_64",
    "target_env": "gnu",
    "target_pointer_width": "64",
    "target_endian": "little",
    "target_vendor": "unknown",
}


def evaluate(pred):
    """A cfg predicate's value here: True, False or None (cannot tell)."""
    pos = 0

    def ws():
        nonlocal pos
        while pos < len(pred) and pred[pos] in " \t\n,":
            pos += 1

    def one():
        nonlocal pos
        ws()
        m = re.match(r"[A-Za-z_][A-Za-z0-9_]*", pred[pos:])
        if not m:
            raise ValueError(pred)
        name = m.group(0)
        pos += len(name)
        ws()
        if pred.startswith("(", pos):
            pos += 1
            args = []
            while True:
                ws()
                if pred.startswith(")", pos):
                    pos += 1
                    break
                args.append(one())
            if name == "not":
                return None if args[0] is None else not args[0]
            if name == "all":
                return False if False in args else (None if None in args else True)
            if name == "any":
                return True if True in args else (None if None in args else False)
            return None
        if pred.startswith("=", pos):
            m = re.match(r'=\s*"([^"]*)"', pred[pos:])
            pos += len(m.group(0))
            if name == "feature":
                return True
            return (VALUES[name] == m.group(1)) if name in VALUES else None
        return FACTS.get(name)

    return one()


def cfgs(text):
    """The predicates of the #[cfg(...)] attributes in text."""
    out = []
    for m in re.finditer(r"#\[cfg\(", text):
        depth, i = 1, m.end()
        while i < len(text) and depth:
            depth += {"(": 1, ")": -1}.get(text[i], 0)
            i += 1
        out.append(text[m.end() : i - 1])
    return out


def indent(line):
    return len(line) - len(line.lstrip(" "))


def attributes_above(lines, start):
    """The attributes and comments right above line start, as one text."""
    chunk, j = [], start - 1
    while j >= 0:
        t = lines[j].strip()
        if not t or (t.endswith((";", "{", "}")) and not t.startswith(("#[", "//"))):
            break
        chunk.append(t)
        j -= 1
    return " ".join(reversed(chunk))


def enclosing_cfg(lines, idx):
    """A #[cfg] false here above a block holding line idx, if there is one."""
    line = lines[idx]
    # A line that opens a block is inside it, for this purpose: the
    # mutant may be the whole body of the function it starts.
    if line.rstrip().endswith("{"):
        current, i = indent(line) + 1, idx + 1
    else:
        current, i = indent(line), idx
    while i > 0 and current > 0:
        i -= 1
        text = lines[i].strip()
        if not text or text.startswith("//"):
            continue
        if indent(lines[i]) >= current or not text.endswith("{"):
            continue
        current = indent(lines[i])
        # The header this brace ends may have begun lines above.
        start = i
        while start > 0:
            above = lines[start - 1]
            a = above.strip()
            if not a or a.startswith(("#[", "//")):
                break
            if indent(above) > current or not a.endswith((";", "}", "{")):
                start -= 1
                continue
            break
        for pred in cfgs(attributes_above(lines, start)):
            try:
                if evaluate(pred) is False:
                    return f"#[cfg({pred})]"
            except (ValueError, KeyError, AttributeError):
                pass
    return None


def location(mutant):
    m = re.match(r"([^:]+\.rs):(\d+):", mutant)
    return (m.group(1), int(m.group(2))) if m else (None, None)


def main():
    src, out = Path(sys.argv[1]), Path(sys.argv[2])
    out.mkdir(parents=True, exist_ok=True)
    found = {k: set() for k in KINDS}
    shards = 0
    for root, _, files in os.walk(src):
        if "missed.txt" in files or "caught.txt" in files:
            shards += 1
            for k in KINDS:
                p = Path(root) / f"{k}.txt"
                if p.exists():
                    found[k].update(l for l in p.read_text().splitlines() if l.strip())
    for k in KINDS:
        (out / f"{k}.txt").write_text("".join(f"{m}\n" for m in sorted(found[k])))

    sources = {}
    here, elsewhere = [], []
    for m in sorted(found["missed"]):
        path, line = location(m)
        cfg = None
        if path and Path(path).exists():
            lines = sources.setdefault(path, Path(path).read_text().splitlines())
            if 0 < line <= len(lines):
                cfg = enclosing_cfg(lines, line - 1)
        (elsewhere if cfg else here).append((m, cfg))

    total = sum(len(v) for v in found.values())
    tested = total - len(found["unviable"])
    caught = len(found["caught"]) + len(found["timeout"])
    r = ["# Mutation testing", ""]
    r.append(f"{shards} shards; {total} mutants, {len(found['unviable'])} of them unviable (did not build).")
    if tested:
        r.append(
            f"Of the {tested} that built: caught {len(found['caught'])}, timed out "
            f"{len(found['timeout'])} (counted as caught), missed {len(found['missed'])} — "
            f"{len(here)} in code compiled here, {len(elsewhere)} in code for other systems. "
            f"Caught: {100 * caught / tested:.1f}%."
        )
    r += ["", "## Missed, by file (compiled here)", "", "| File | Missed |", "|---|---|"]
    for f, n in Counter(location(m)[0] for m, _ in here).most_common():
        r.append(f"| `{f}` | {n} |")
    r += ["", "## Missed, compiled here", "", "```"] + [m for m, _ in here] + ["```"]
    r += ["", "## Missed in code for other systems (not compiled here)", "", "```"]
    r += [f"{m}    [{cfg}]" for m, cfg in elsewhere] + ["```", ""]
    (out / "summary.md").write_text("\n".join(r))
    print("\n".join(r[:4]))


if __name__ == "__main__":
    main()
