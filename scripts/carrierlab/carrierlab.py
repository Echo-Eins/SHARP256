#!/usr/bin/env python3
"""A laboratory of networks that block UDP or hold it back, for proving what
SHARP-256 does in them: which carrier a transfer ends up on, and that the
file arrives whole — or, where something on the way opens TLS, that the
transfer is refused and says why.

      A --a-- C --b-- B
              |
              s
              |
              S

C is the network in between: a router whose nftables rules do to the
traffic of one side — the sender's (A) or the receiver's (B) — what such
networks do. A runs sharp-sender, B sharp-receiver, S sharp-relay (UDP and
TCP on 5560, TLS on 443). Every host has addresses of one family: a cell is
IPv4 or IPv6.

What C does (the "blocking"):

    open           nothing: the control
    udp_blocked    no UDP at all
    udp_cut        UDP cut in the middle of the transfer
    udp_policed    UDP towards the receiver policed to 250 kB/s; TCP is not
    tcp443_only    nothing out but TCP to port 443, nothing in but answers
    tls_inspected  the same, and TLS to port 443 opened on the way: a proxy
                   on C (mitm.py, Python's ssl, no SHARP-256 code) ends it
                   with a certificate of its own and opens its own to S

The rules are the kernel's (nftables: drop, `limit rate over`, a NAT
redirect to the proxy). The binaries are the real ones (SHARP_BIN_DIR, by
default target/debug).

Needs: unshare, nsenter, ip, nft, tc (with netem), openssl, python3; root inside a user
namespace is enough (the script re-executes itself under `unshare -rnm`).
Shares the namespace plumbing with scripts/natlab.

    scripts/carrierlab/carrierlab.py matrix [--markdown FILE] [--logs DIR] [-v]
    scripts/carrierlab/carrierlab.py one udp_policed --side receiver --family 6 -v

CARRIERLAB_LOG sets the binaries' log level; CARRIERLAB_SENDER_ARGS adds
options to the sender's command line (`--no-tcp`, to see UDP alone under a
policer).
"""

import argparse
import hashlib
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "natlab"))
from natlab import BIN, Lab, plain, sh, wait_for  # noqa: E402

# Addresses that nothing takes for a private network: the hosts are on "the
# internet", and C is all there is between them.
ADDR = {
    4: {"A": ("11.31.0.2", "11.31.0.1", 24), "B": ("11.32.0.2", "11.32.0.1", 24), "S": ("11.33.0.2", "11.33.0.1", 24)},
    6: {
        "A": ("2a0e:aa00:31::2", "2a0e:aa00:31::1", 64),
        "B": ("2a0e:aa00:32::2", "2a0e:aa00:32::1", 64),
        "S": ("2a0e:aa00:33::2", "2a0e:aa00:33::1", 64),
    },
}
RELAY_PORT, TLS_PORT, RECEIVER_PORT, MITM_PORT = 5560, 443, 5555, 8443
DELAY_MS = 10
NO_NETEM_SAID = False
BLOCKINGS = ["open", "udp_blocked", "udp_cut", "udp_policed", "tcp443_only", "tls_inspected"]
# C's interfaces towards the two sides. (Not "a" and "b": ip takes those
# for abbreviations of its keywords.)
SIDES = {"sender": "vca", "receiver": "vcb"}

# What each cell is to end in: the carrier the sender's session ends on
# (UDP, TCP to the receiver, or the relay over UDP, TCP or TLS), a mark
# for UDP left because it was held back, or the transfer refused.
EXPECTED = {
    ("sender", "open"): {"UDP"},
    ("sender", "udp_blocked"): {"TCP"},
    ("sender", "udp_cut"): {"UDP, then TCP"},
    ("sender", "udp_policed"): {"UDP, then TCP (held back)"},
    ("sender", "tcp443_only"): {"relay/TLS"},
    ("sender", "tls_inspected"): {"refused: TLS opened on the way"},
    ("receiver", "open"): {"UDP"},
    # TCP straight to the receiver: at once, when the relay has not
    # answered over UDP before the sender asks for streams; or after the
    # relay has carried for a few seconds, when it has.
    ("receiver", "udp_blocked"): {"TCP", "relay/UDP, then TCP"},
    ("receiver", "udp_cut"): {"UDP, then TCP"},
    ("receiver", "udp_policed"): {"UDP, then TCP (held back)"},
    # The receiver reaches the relay over TLS; the sender, whose network is
    # open, reaches the relay over UDP, and the relay carries between them.
    ("receiver", "tcp443_only"): {"relay/UDP, receiver over TLS"},
    ("receiver", "tls_inspected"): {"refused: TLS opened on the way"},
}

# How long each kind of cell may take, and what it sends: a size, and a
# rate cap where the cell needs the transfer to last (a cut in its middle).
PLAN = {
    "open": (4, None, 30),
    # Long enough at 2 MB/s for a session carried by the relay to move to a
    # stream straight to the receiver (a few seconds of asking UDP first).
    "udp_blocked": (16, "16M", 45),
    "udp_cut": (8, "16M", 45),
    # Long enough at 2 MB/s for the trial to finish: five seconds on UDP,
    # ten on TCP, and the rest.
    "udp_policed": (24, "16M", 60),
    "tcp443_only": (4, None, 45),
    "tls_inspected": (4, None, 25),
}
CUT_AFTER = 1.5


def censor(blocking, side):
    """C's rules for `blocking` done to the traffic of `side` (an interface
    of C's: see SIDES)."""
    i, o = f'iifname "{side}"', f'oifname "{side}"'
    # What goes towards the receiver: out of the sender's side, or into the
    # receiver's.
    towards_receiver = i if side == SIDES["sender"] else o
    rules, nat = "", ""
    if blocking == "udp_blocked":
        rules = f"{i} meta l4proto udp drop\n{o} meta l4proto udp drop"
    elif blocking == "udp_policed":
        rules = f"{towards_receiver} meta l4proto udp limit rate over 250 kbytes/second burst 64 kbytes drop"
    elif blocking in ("tcp443_only", "tls_inspected"):
        rules = f"""ct state established,related accept
meta l4proto {{ icmp, ipv6-icmp }} accept
{i} tcp dport {TLS_PORT} accept
{i} drop
{o} drop"""
        if blocking == "tls_inspected":
            nat = f"""
table inet inspect {{
    chain arriving {{
        type nat hook prerouting priority dstnat; policy accept;
        {i} tcp dport {TLS_PORT} redirect to :{MITM_PORT}
    }}
}}"""
    return f"""table inet censor {{
    chain passing {{
        type filter hook forward priority 0; policy accept;
{rules}
    }}
}}{nat}
"""


class Net:
    def __init__(self, lab, family):
        self.family = family
        for n in ("C", "A", "B", "S"):
            lab.mk(n)
        for host, c_if, h_if in (("A", "vca", "vha"), ("B", "vcb", "vhb"), ("S", "vcs", "vhs")):
            lab.link("C", c_if, host, h_if)
            ip, gw, plen = ADDR[family][host]
            if family == 4:
                lab.addr("C", c_if, f"{gw}/{plen}")
                lab.addr(host, h_if, f"{ip}/{plen}", gw)
            else:
                lab.addr6("C", c_if, f"{gw}/{plen}")
                lab.addr6(host, h_if, f"{ip}/{plen}", gw)
        # Ten milliseconds each way through C (tc's netem): round trips of
        # twenty, as across a city. On a round trip of a tenth of a
        # millisecond the smallest window a congestion control keeps is
        # already more than any policer lets through.
        # Without netem in the kernel (sch_netem), the cells still run, on
        # round trips of next to nothing: said once.
        global NO_NETEM_SAID
        for c_if in ("vca", "vcb", "vcs"):
            r = lab.x("C", "tc", "qdisc", "add", "dev", c_if, "root", "netem", "delay", f"{DELAY_MS}ms",
                      check=False)
            if r.returncode != 0 and not NO_NETEM_SAID:
                print(f"(no netem here — {r.stderr.strip()} — so no delay either)", flush=True)
                NO_NETEM_SAID = True
        lab.x("C", "sysctl", "-qw", "net.ipv4.ip_forward=1")
        lab.x("C", "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1", check=False)
        if family == 6:
            lab.settle(["C", "A", "B", "S"])
        self.ip = {h: ADDR[family][h][0] for h in ("A", "B", "S")}

    def at(self, host, port):
        ip = self.ip[host]
        return f"{ip}:{port}" if self.family == 4 else f"[{ip}]:{port}"

    def any(self, port):
        return f"0.0.0.0:{port}" if self.family == 4 else f"[::]:{port}"


def clean(text):
    """A log without the colours the binaries put in it."""
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def payload(d, mb):
    path = os.path.join(d, "payload.bin")
    with open(path, "wb") as f:
        for _ in range(mb):
            f.write(os.urandom(1 << 20))
    return path, hashlib.sha256(open(path, "rb").read()).hexdigest()


def outcome(slog, rlog, net):
    """What a cell ended in, from the logs (see EXPECTED)."""
    if "is not the relay's own" in slog or "is not the relay's own" in rlog:
        if "Completed" not in slog and "whole-file hash matches" not in slog:
            return "refused: TLS opened on the way"
    # Addresses as the logs print them, one way or the other (see `plain`).
    # Where the session went: an address proven, or a handshake answered
    # over another carrier.
    moves = [plain(proven or answered) for proven, answered in re.findall(
        r"receiver address (\S+) proven|the session runs over \w+ (?:now|again) \(\S+ -> (\S+)\)", slog
    )]
    conn = re.search(r"Connected to (\S+)", slog)
    first = plain(conn.group(1)) if conn else None
    final = moves[-1] if moves else first
    if final is None:
        return "none"
    direct = {plain(a) for a in re.findall(r"the receiver answers over TCP at \S+; carried from (\S+)", slog)}
    relayed = dict(
        (plain(shim), over)
        for over, shim in re.findall(r"will carry the transfer on its port \d+, over (TCP|TLS); carried from (\S+)", slog)
    )

    def kind(addr):
        if addr in direct:
            return "TCP"
        if addr in relayed:
            return f"relay/{relayed[addr]}"
        ip = addr.rsplit(":", 1)[0].strip("[]")
        if ip == net.ip["S"]:
            return "relay/UDP"
        return "UDP"

    end = kind(final)
    began = kind(first) if first else end
    said = end if began == end else f"{began}, then {end}"
    if "keeping to TCP" in slog:
        said += " (held back)"
    if end == "relay/UDP":
        m = re.search(r"relay reached over (TCP|TLS)", rlog)
        if m:
            said += f", receiver over {m.group(1)}"
    return said


def excerpt(text, limit=120):
    """The lines of a log that say which way things went."""
    keep = re.compile(
        r"relay|TCP|TLS|UDP|session runs|proven|claims|registered|held back|trial|refus|polic|"
        r"not the relay's own|Connected|whole-file|error|Error|failed|warn|WARN"
    )
    lines = [l for l in text.splitlines() if keep.search(l) and "progress" not in l]
    return "\n".join(lines[:limit])


def cell(side, blocking, family, verbose=False, logs=None, keep=False):
    """One transfer through C doing `blocking` to `side`'s traffic. Returns
    (as expected, what it ended in, seconds, detail)."""
    lab = Lab(keep=keep)
    try:
        net = Net(lab, family)
        d = lab.dir
        size_mb, rate, timeout = PLAN[blocking]
        if blocking != "udp_cut":
            lab.nft("C", censor(blocking, SIDES[side]))
        lab.spawn(
            "S",
            [f"{BIN}/sharp-relay", "--bind", net.any(RELAY_PORT), "--tls", net.any(TLS_PORT),
             "--stun", net.ip["S"], "--identity", f"{d}/relay.key", "--log", "info"],
            "relay.log",
        )
        m = wait_for(lab, "relay.log", r"Receivers: --relay (sh4?-\S+?)@", 15)
        if not m:
            return False, "none", 0, "the relay did not start:\n" + lab.log("relay.log")
        relay = f"{m.group(1)}@{net.at('S', RELAY_PORT)}"
        if blocking == "tls_inspected":
            sh("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
               "-keyout", f"{d}/mitm.key", "-out", f"{d}/mitm.crt", "-days", "2", "-nodes",
               "-subj", "/CN=inspected.example")
            lab.spawn("C", [sys.executable, os.path.join(HERE, "mitm.py"), str(MITM_PORT), net.ip["S"],
                            str(TLS_PORT), f"{d}/mitm.crt", f"{d}/mitm.key"], "mitm.log")
            if not wait_for(lab, "mitm.log", r"inspecting TLS", 10):
                return False, "none", 0, "the proxy did not start:\n" + lab.log("mitm.log")
        stun = ["--stun", net.at("S", 3478)]
        os.makedirs(f"{d}/out", exist_ok=True)
        lab.spawn(
            "B",
            [f"{BIN}/sharp-receiver", "--headless", "--output", f"{d}/out", "--state-dir", f"{d}/rst",
             "--identity", f"{d}/r.key", "--bind", net.any(RECEIVER_PORT), *stun, "--relay", relay,
             "--log-level", os.environ.get("CARRIERLAB_LOG", "info")],
            "receiver.log",
        )
        m = wait_for(lab, "receiver.log", r"Senders use: (sh4?-[a-z0-9]+)", 15)
        if not m:
            return False, "none", 0, "the receiver did not start:\n" + lab.log("receiver.log")
        receiver = f"{m.group(1)}@{net.at('B', RECEIVER_PORT)}"
        # Registered with the relay first, however long the receiver's own
        # network makes that take: the cell is about the transfer.
        wait_for(lab, "receiver.log", r"registered with the relay|is not the relay's own", 25)
        data, want = payload(d, size_mb)
        args = [f"{BIN}/sharp-sender", data, receiver, "--relay", relay, "--headless", *stun,
                "--identity", f"{d}/s.key", "--state-dir", f"{d}/sst", "--log-level", os.environ.get("CARRIERLAB_LOG", "info")]
        if rate:
            args += ["--max-rate", rate]
        # More of the sender's options, for a measurement of one's own
        # (`--no-tcp`, say); the expectations are the cells' as they are.
        args += os.environ.get("CARRIERLAB_SENDER_ARGS", "").split()
        start = time.time()
        sender = lab.spawn("A", args, "sender.log")
        cut = False
        end = start + timeout
        while sender.poll() is None and time.time() < end:
            if blocking == "udp_cut" and not cut and time.time() - start >= CUT_AFTER:
                lab.nft("C", censor("udp_blocked", SIDES[side]))
                cut = True
            if blocking == "tls_inspected" and re.search(r"is not the relay's own", lab.log("sender.log") + lab.log("receiver.log")):
                # Found out, and said: what the cell is for. The sender
                # would go on to its deadline.
                time.sleep(1.0)
                break
            time.sleep(0.2)
        if sender.poll() is None:
            sender.kill()
        took = time.time() - start
        slog, rlog = clean(lab.log("sender.log")), clean(lab.log("receiver.log"))
        got = None
        for name in os.listdir(f"{d}/out"):
            if not name.endswith(".sharp-part"):
                got = hashlib.sha256(open(f"{d}/out/{name}", "rb").read()).hexdigest()
        said = outcome(slog, rlog, net)
        whole = got == want
        refused = said.startswith("refused")
        ok = said in EXPECTED[(side, blocking)] and (whole or refused)
        if not whole and not refused:
            said += " — the file did not arrive"
        if logs:
            name = f"{side}-{blocking}-ipv{family}"
            with open(os.path.join(logs, name + ".log"), "w") as f:
                f.write(f"# {side}'s network: {blocking}; IPv{family}; {took:.1f} s; {said}\n")
                for who, text in (("sender", slog), ("receiver", rlog), ("relay", clean(lab.log("relay.log"))),
                                  ("proxy", lab.log("mitm.log"))):
                    if text:
                        f.write(f"\n## {who}\n{excerpt(text)}\n")
        detail = ""
        if verbose or not ok:
            detail = (
                "--- C\n" + lab.x("C", "nft", "list", "ruleset", check=False).stdout[-1500:]
                + "\n--- sender.log\n" + excerpt(slog)
                + "\n--- receiver.log\n" + excerpt(rlog)
                + "\n--- relay.log\n" + excerpt(clean(lab.log("relay.log")), 40)
                + ("\n--- mitm.log\n" + lab.log("mitm.log")[-800:] if blocking == "tls_inspected" else "")
            )
        return ok, said, took, detail
    finally:
        # C's rules go with its namespace.
        lab.close()


def cmd_one(args):
    ok, said, took, detail = cell(args.side, args.blocking, args.family, args.verbose, keep=args.keep)
    print(f"{args.side}'s network {args.blocking}, IPv{args.family}: {said} ({took:.1f} s) "
          f"{'as expected' if ok else 'NOT as expected: ' + ' or '.join(sorted(EXPECTED[(args.side, args.blocking)]))}")
    if detail:
        print(detail)
    return 0 if ok else 1


def cmd_matrix(args):
    families = [int(f) for f in args.families]
    blockings = args.blockings or BLOCKINGS
    if args.logs:
        os.makedirs(args.logs, exist_ok=True)
    rows = []
    failures = 0
    for side in SIDES:
        for blocking in blockings:
            row = [side, blocking]
            for family in families:
                ok, said, took, detail = cell(side, blocking, family, args.verbose, logs=args.logs)
                mark = "✓" if ok else "✗"
                print(f"{mark} {side:8} {blocking:14} IPv{family}: {said} ({took:.1f} s)", flush=True)
                if detail and (args.verbose or not ok):
                    print(detail, flush=True)
                failures += not ok
                row.append(f"{mark} {said} ({took:.0f} s)")
            rows.append(row)
    if args.markdown:
        with open(args.markdown, "w") as f:
            f.write("| network that does it | blocking | " + " | ".join(f"IPv{x}" for x in families) + " |\n")
            f.write("|---|---|" + "---|" * len(families) + "\n")
            for row in rows:
                f.write("| " + " | ".join(row) + " |\n")
    print(f"{failures} not as expected" if failures else "all as expected")
    return 1 if failures else 0


def main():
    if os.environ.get("CARRIERLAB_IN") != "1":
        os.execvp("unshare", ["unshare", "-rnm", "env", "CARRIERLAB_IN=1", sys.executable] + sys.argv)
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    one = sub.add_parser("one")
    one.add_argument("blocking", choices=BLOCKINGS)
    one.add_argument("--side", choices=list(SIDES), default="sender")
    one.add_argument("--family", type=int, choices=[4, 6], default=4)
    one.add_argument("--keep", action="store_true", help="keep the laboratory's directory")
    one.add_argument("-v", "--verbose", action="store_true")
    mx = sub.add_parser("matrix")
    mx.add_argument("blockings", nargs="*", help="a subset of: " + " ".join(BLOCKINGS))
    mx.add_argument("--families", nargs="*", default=["4", "6"], choices=["4", "6"])
    mx.add_argument("--markdown", help="write the matrix as a table to this file")
    mx.add_argument("--logs", help="write what each cell's logs say of its carriers to this directory")
    mx.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    sh("ip", "link", "set", "lo", "up")
    sys.exit({"one": cmd_one, "matrix": cmd_matrix}[args.cmd](args))


if __name__ == "__main__":
    main()
