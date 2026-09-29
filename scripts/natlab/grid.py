#!/usr/bin/env python3
"""Turns the log of `natlab.py matrix` or `natlab.py v6` into the grids that
docs/NAT.md shows.

    scripts/natlab/grid.py docs/evidence/nat/matrix-relay-carries.log
    scripts/natlab/grid.py docs/evidence/nat/ipv6-firewalls-direct-only.log

Rows are the sender's NAT (or firewall), columns the receiver's. A cell is
D (a direct path), D↑ (began through a relay or a TURN server and moved to
a direct one), R (through the relay), T (through the TURN server), or — (no
connection).
"""
import re
import sys

V4 = ["open", "full_cone", "restricted", "port_restricted", "symmetric_seq", "symmetric_random"]
V4_SHORT = {"open": "open", "full_cone": "full", "restricted": "restr", "port_restricted": "port",
            "symmetric_seq": "seq", "symmetric_random": "rand"}
V6 = ["open6", "stateful6", "restricted6"]


def symbol(ok, path):
    if ok != "ok":
        return "—"
    if path.startswith("turn"):
        return "T"
    if path.startswith("relay"):
        return "R"
    if "(from " in path:
        return "D↑"
    return "D"


def render(cells, kinds, short, title=None):
    out = []
    if title:
        out.append(f"**{title}**\n")
    out.append("| отправитель ↓ / получатель → | " + " | ".join(short.get(k, k) for k in kinds) + " |")
    out.append("|---|" + "---|" * len(kinds))
    for a in kinds:
        out.append(f"| {short.get(a, a)} | " + " | ".join(cells.get((a, b), "?") for b in kinds) + " |")
    counts = {}
    for v in cells.values():
        counts[v] = counts.get(v, 0) + 1
    out.append("")
    out.append("Всего пар: " + str(len(cells)) + "; " + ", ".join(f"{k}: {v}" for k, v in sorted(counts.items())))
    return "\n".join(out)


def v4_grid(path):
    cells = {}
    for line in open(path):
        m = re.match(r"^(\w+)\s+(\w+)\s+(ok|FAIL)\s+(\S+(?: \(from \w+\))?)\s+([\d.]+)s", line)
        if m and m.group(1) in V4 and m.group(2) in V4:
            a, b, ok, p, _ = m.groups()
            cells[(a, b)] = symbol(ok, p)
    return render(cells, V4, V4_SHORT) if cells else None


def v6_grids(path):
    scenarios = {}
    for line in open(path):
        m = re.match(r"^(IPv6 only|dual stack, [^\n]*?)\s{2,}(open6|stateful6|restricted6)\s+(open6|stateful6|restricted6)\s+(ok|FAIL)\s+(\S+(?: \(from \w+\))?)\s+([\d.]+)s", line)
        if m:
            name, a, b, ok, p, _ = m.groups()
            scenarios.setdefault(name, {})[(a, b)] = symbol(ok, p)
    return [render(c, V6, {}, name) for name, c in scenarios.items()]


if __name__ == "__main__":
    for path in sys.argv[1:]:
        g = v4_grid(path)
        blocks = [g] if g else v6_grids(path)
        print("\n\n".join(b for b in blocks if b))
