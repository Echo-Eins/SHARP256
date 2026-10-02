#!/usr/bin/env python3
"""Bad networks: real transfers through the kernel's netem (ROADMAP C4).

Three network namespaces: A runs sharp-sender, B sharp-receiver, and C, the
router between them, does to each direction what a profile says with tc's
netem — delay and its jitter, loss, duplication, reordering, a bottleneck
rate and its queue. The way to the receiver (data) and the way back (ACKs)
are shaped apart, so a link can be asymmetric. Each profile is one transfer
straight from A to B over UDP (no relay, no TCP, no NAT), and says what it
must at least achieve: the file whole, within the time, at a share of the
bottleneck, and with no more than a share of it sent again.

Two profiles measure more than the transfer:

* bufferbloat — a bottleneck with seconds of queue: pings from A to B
  during the transfer say how much of that queue the sender fills;
* tcp_fair — a TCP bulk flow from A to B through the same bottleneck, at
  the same time: what share each gets.

The binaries are the real ones (SHARP_BIN_DIR, by default target/debug).
Needs: unshare, nsenter, ip, tc (with sch_netem), ping, python3; root inside
a user namespace is enough (the script re-executes itself under
`unshare -rnm`). Shares the namespace plumbing with scripts/natlab.

    scripts/netemlab/netemlab.py list
    scripts/netemlab/netemlab.py run [PROFILE ...] [--markdown FILE] [--logs DIR] [-v]

NETEMLAB_SCALE multiplies every profile's file size (default 1);
NETEMLAB_LOG sets the binaries' log level (default info).
"""

import argparse
import hashlib
import os
import re
import statistics
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "natlab"))
from natlab import BIN, Lab, sh, wait_for  # noqa: E402

A_IP, B_IP = "10.61.1.2", "10.61.2.2"
PORT = 5555
TCP_PORT = 5600

# name: (to the receiver, back to the sender, MB, seconds allowed,
#        at least this share of `rate` delivered, at most this share of the
#        file sent again, the bottleneck in Mbit/s, what it stands for)
# The shares are floors that catch a collapse, below the spread of good
# runs (docs/evidence/netem/ has what runs did), not targets.
PROFILES = {
    "clean": ("delay 10ms rate 50mbit limit 1000", "delay 10ms", 24, 60, 0.70, 0.02, 50,
              "20 ms round trip, 50 Mbit/s, a queue of a round trip and more"),
    "loss_1": ("delay 10ms rate 50mbit limit 1000 loss 1%", "delay 10ms", 24, 60, 0.60, 0.03, 50,
               "1 % random loss towards the receiver"),
    "loss_5": ("delay 10ms rate 50mbit limit 1000 loss 5%", "delay 10ms", 16, 60, 0.50, 0.08, 50,
               "5 % random loss"),
    "loss_10": ("delay 10ms rate 50mbit limit 1000 loss 10%", "delay 10ms", 12, 60, 0.35, 0.16, 50,
                "10 % random loss"),
    "loss_20": ("delay 10ms rate 50mbit limit 1000 loss 20%", "delay 10ms loss 5%", 8, 90, 0.10, 0.40, 50,
                "20 % lost towards the receiver, 5 % of the ACKs"),
    "loss_30": ("delay 10ms rate 50mbit limit 1000 loss 30%", "delay 10ms loss 10%", 6, 120, 0.08, 0.70, 50,
                "30 % lost towards the receiver, 10 % of the ACKs"),
    "burst_loss": ("delay 10ms rate 50mbit limit 1000 loss gemodel 1% 10% 70% 0.1%", "delay 10ms", 16, 60,
                   0.40, 0.10, 50, "losses in bursts (Gilbert–Elliott: 1 % into a bad state that loses 70 %)"),
    "jitter": ("delay 40ms 20ms distribution normal rate 50mbit limit 2000", "delay 40ms 20ms distribution normal",
               16, 60, 0.35, 0.05, 50, "80 ms round trip, ±20 ms each way: packets overtake each other"),
    # The bottleneck before the reordering (tbf, then netem): netem's own
    # `rate` lets the packets it reorders skip its queue, which no real
    # path does, and their round trips hide the queue from the sender.
    "reorder": ("tbf 50mbit 1000 | delay 20ms reorder 10% 50%", "delay 20ms", 16, 60, 0.45, 0.05, 50,
                "a tenth of the packets 20 ms ahead of the rest, behind a 50 Mbit/s bottleneck"),
    "duplicate": ("delay 10ms duplicate 5% rate 50mbit limit 1000", "delay 10ms duplicate 5%", 16, 60, 0.60, 0.03,
                  50, "5 % of the packets twice, both ways"),
    "satellite": ("delay 300ms rate 20mbit limit 2000 loss 0.5%", "delay 300ms", 16, 120, 0.20, 0.03, 20,
                  "600 ms round trip, 20 Mbit/s, 0.5 % loss (geostationary)"),
    "asymmetric": ("delay 15ms rate 50mbit limit 1000", "delay 15ms rate 512kbit limit 100", 16, 60, 0.40, 0.03,
                   50, "50 Mbit/s down, 0.5 Mbit/s back: the ACKs' way is narrow"),
    "bufferbloat": ("delay 10ms rate 20mbit limit 5000", "delay 10ms", 16, 60, 0.70, 0.02, 20,
                    "20 Mbit/s with 3 s of queue: what the sender fills of it"),
    "tcp_fair": ("delay 10ms rate 20mbit limit 300", "delay 10ms", 16, 90, 0.20, 0.03, 20,
                 "20 Mbit/s shared with a TCP bulk flow"),
    "mtu_1240": ("delay 10ms rate 50mbit limit 1000", "delay 10ms", 8, 90, 0.25, 0.10, 50,
                 "a path MTU of 1240 bytes: below what IPv6 promises, above what the handshake needs"),
    "mtu_1000": ("delay 10ms rate 50mbit limit 1000", "delay 10ms", 1, 40, 0.0, 1.0, 50,
                 "a path MTU of 1000 bytes: the handshake's 1200-byte datagrams do not pass (THREAT_MODEL Р7)"),
}

# The path MTU of a profile, set on the router's two links; and the
# profiles that must fail, and why.
MTU = {"mtu_1240": 1240, "mtu_1000": 1000}
MUST_FAIL = {"mtu_1000": "no handshake, as THREAT_MODEL Р7 says"}

# Profiles whose numbers are a goal, not yet reached: below it they show ◐
# and do not fail the run (ROADMAP C4 says what is behind each).
GOALS = {
    "loss_30": "30 per cent lost at random: the window is seldom large enough to keep the path full",
    "burst_loss": "netem's bursts last ten packets, not a time: at a small window they span seconds of timeouts",
    "reorder": "reordering behind a queue: the spread from run to run is wide",
    "bufferbloat": "the sender stops the queue growing but does not drain what slow start put in it",
}

# What the measured profiles must also keep to.
BLOAT_MAX_MS = 150.0  # the median ping under the transfer, over the base
FAIR_SHARE = (0.20, 0.80)  # the sender's share of what the two moved


def build(lab, fwd, rev, mtu=None):
    """A — C — B, with `fwd` on C's way to B and `rev` on its way to A."""
    for n in ("A", "B", "C"):
        lab.mk(n)
    lab.link("C", "vca", "A", "vha")
    lab.link("C", "vcb", "B", "vhb")
    lab.addr("C", "vca", "10.61.1.1/24")
    lab.addr("A", "vha", f"{A_IP}/24", "10.61.1.1")
    lab.addr("C", "vcb", "10.61.2.1/24")
    lab.addr("B", "vhb", f"{B_IP}/24", "10.61.2.1")
    lab.x("C", "sysctl", "-qw", "net.ipv4.ip_forward=1")
    for dev, spec in (("vcb", fwd), ("vca", rev)):
        if not spec:
            continue
        if spec.startswith("tbf "):
            # "tbf RATE PACKETS | NETEM": a token-bucket bottleneck with a
            # queue of PACKETS full-size packets, and netem behind it.
            shaper, rest = spec.split("|", 1)
            _, rate, packets = shaper.split()
            lab.x("C", "tc", "qdisc", "add", "dev", dev, "root", "handle", "1:", "tbf", "rate", rate,
                  "burst", "32kbit", "limit", str(int(packets) * 1514))
            lab.x("C", "tc", "qdisc", "add", "dev", dev, "parent", "1:1", "handle", "10:", "netem",
                  *rest.split())
        else:
            lab.x("C", "tc", "qdisc", "add", "dev", dev, "root", "netem", *spec.split())
    if mtu:
        # On the router in the middle only: the ends find out from what
        # gets through, not from their own interfaces.
        for dev in ("vca", "vcb"):
            lab.x("C", "ip", "link", "set", "dev", dev, "mtu", str(mtu))


UNITS = {"B": 1, "KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30}


def done_line(log):
    """(seconds, bytes sent again, loss events) from the sender's last line."""
    m = re.search(r"Done: \S+ \S+ in ([\d.]+)(m?s) \(.*?\), ([\d.]+) (B|KiB|MiB|GiB) retransmitted, (\d+) loss events",
                  log)
    if not m:
        return None
    secs = float(m.group(1)) / (1000.0 if m.group(2) == "ms" else 1.0)
    return secs, float(m.group(3)) * UNITS[m.group(4)], int(m.group(5))


def payload(d, mb):
    path = os.path.join(d, "payload.bin")
    with open(path, "wb") as f:
        for _ in range(mb):
            f.write(os.urandom(1 << 20))
    return path, hashlib.sha256(open(path, "rb").read()).hexdigest()


TCP_SINK = """
import socket, sys, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", int(sys.argv[1]))); s.listen(1)
c, _ = s.accept(); n = 0; t0 = time.time()
while True:
    b = c.recv(1 << 16)
    if not b: break
    n += len(b)
print(f"tcp received {n} in {time.time() - t0:.2f}", flush=True)
"""

TCP_SOURCE = """
import socket, sys, time
c = socket.create_connection((sys.argv[1], int(sys.argv[2])))
buf = b"\\0" * (1 << 16); end = time.time() + float(sys.argv[3]); n = 0
while time.time() < end:
    n += c.send(buf)
c.close(); print(f"tcp sent {n}", flush=True)
"""


def run(name, verbose=False, logs=None):
    """One profile. Returns (as required, a line saying what happened)."""
    fwd, rev, mb, timeout, share, resend, mbit, _ = PROFILES[name]
    mb = max(1, int(mb * float(os.environ.get("NETEMLAB_SCALE", "1"))))
    lab = Lab()
    try:
        build(lab, fwd, rev, MTU.get(name))
        d = lab.dir
        os.makedirs(f"{d}/out", exist_ok=True)
        lab.spawn("B", [f"{BIN}/sharp-receiver", "--headless", "--output", f"{d}/out", "--state-dir", f"{d}/rst",
                        "--identity", f"{d}/r.key", "--bind", f"0.0.0.0:{PORT}", "--no-nat", "--no-tcp",
                        "--no-lan-addresses", "--log-level", os.environ.get("NETEMLAB_LOG", "info")], "receiver.log")
        m = wait_for(lab, "receiver.log", r"Senders use: (sh4?-[a-z0-9]+)", 15)
        if not m:
            return False, "the receiver did not start:\n" + lab.log("receiver.log")
        data, want = payload(d, mb)
        base_ping = None
        pinger = tcp = None
        if name == "bufferbloat":
            r = lab.x("A", "ping", "-c", "5", "-i", "0.2", "-q", B_IP, check=False)
            m2 = re.search(r"= [\d.]+/([\d.]+)/", r.stdout)
            base_ping = float(m2.group(1)) if m2 else None
            pinger = lab.spawn("A", ["ping", "-i", "0.1", B_IP], "ping.log")
        if name == "tcp_fair":
            lab.spawn("B", [sys.executable, "-c", TCP_SINK, str(TCP_PORT)], "tcp-sink.log")
            time.sleep(0.5)
        start = time.time()
        sender = lab.spawn("A", [f"{BIN}/sharp-sender", data, f"{m.group(1)}@{B_IP}:{PORT}", "--headless",
                                 "--no-nat", "--no-tcp", "--identity", f"{d}/s.key", "--state-dir", f"{d}/sst",
                                 "--log-level", os.environ.get("NETEMLAB_LOG", "info")], "sender.log")
        if name == "tcp_fair":
            # Running for as long as the transfer would alone at half the
            # bottleneck: the two share it all the way.
            secs = mb * 8.0 / (mbit / 2.0)
            tcp = lab.spawn("A", [sys.executable, "-c", TCP_SOURCE, B_IP, str(TCP_PORT), f"{secs:.1f}"],
                            "tcp-source.log")
        end = start + timeout
        while sender.poll() is None and time.time() < end:
            time.sleep(0.2)
        if sender.poll() is None:
            sender.kill()
        took = time.time() - start
        if pinger:
            pinger.terminate()
            pinger.wait(timeout=3)
        tcp_bytes = None
        if tcp:
            tcp.wait(timeout=timeout)
            time.sleep(1.0)
            m3 = re.search(r"tcp received (\d+) in ([\d.]+)", lab.log("tcp-sink.log"))
            tcp_bytes = (int(m3.group(1)), float(m3.group(2))) if m3 else None
        slog = lab.log("sender.log")
        got = None
        for f in os.listdir(f"{d}/out"):
            if not f.endswith(".sharp-part"):
                got = hashlib.sha256(open(f"{d}/out/{f}", "rb").read()).hexdigest()
        stats = done_line(slog)
        problems = []
        if name in MUST_FAIL:
            ok = got != want and not stats
            said = (f"not delivered within {timeout} s — {MUST_FAIL[name]}" if ok
                    else "delivered, which it cannot have been: the profile is wrong")
            return ok, said
        if got != want:
            problems.append("the file did not arrive whole")
        if not stats:
            problems.append(f"no summary within {timeout} s")
            said = f"{took:.1f} s, unfinished"
        else:
            secs, resent_b, losses = stats
            size = mb << 20
            rate = size * 8.0 / secs / 1e6
            resent_share = resent_b / size
            said = f"{rate:.1f} Mbit/s of {mbit} ({rate / mbit:.0%}), {resent_share:.1%} sent again, {secs:.1f} s"
            if name == "tcp_fair":
                # The sender's share is of the time both ran; TCP's as well.
                if tcp_bytes:
                    tcp_rate = tcp_bytes[0] * 8.0 / tcp_bytes[1] / 1e6
                    mine = rate / (rate + tcp_rate)
                    said += f"; TCP {tcp_rate:.1f} Mbit/s alongside: the sender's share {mine:.0%}"
                    if not FAIR_SHARE[0] <= mine <= FAIR_SHARE[1]:
                        problems.append(f"share {mine:.0%} outside {FAIR_SHARE[0]:.0%}–{FAIR_SHARE[1]:.0%}")
                else:
                    problems.append("the TCP flow said nothing")
            elif rate < share * mbit:
                problems.append(f"below {share:.0%} of the bottleneck")
            if resent_share > resend:
                problems.append(f"more than {resend:.0%} sent again")
        if name == "bufferbloat":
            rtts = [float(x) for x in re.findall(r"time=([\d.]+) ms", lab.log("ping.log"))]
            if rtts and base_ping is not None:
                med = statistics.median(rtts)
                said += f"; ping {base_ping:.0f} ms idle, median {med:.0f} ms and top {max(rtts):.0f} ms under it"
                if med - base_ping > BLOAT_MAX_MS:
                    problems.append(f"the queue adds {med - base_ping:.0f} ms (at most {BLOAT_MAX_MS:.0f})")
            else:
                problems.append("no pings")
        ok = not problems
        if problems:
            said += " — " + "; ".join(problems)
        if logs:
            with open(os.path.join(logs, f"{name}.log"), "w") as f:
                f.write(f"# {name}: {PROFILES[name][7]}\n# to the receiver: {fwd}\n# back: {rev}\n# {said}\n")
                keep = re.compile(r"Done|Connected|polic|MTU|chunk|stall|error|warn|WARN|failed|probe|progress|congestive")
                f.write("\n## sender\n" + "\n".join(l for l in slog.splitlines() if keep.search(l))[:6000] + "\n")
        if verbose or not ok:
            said += "\n--- sender.log\n" + slog[-3000:] + "\n--- receiver.log\n" + lab.log("receiver.log")[-1500:]
        return ok, said
    finally:
        lab.close()


def cmd_list(_args):
    for name, p in PROFILES.items():
        print(f"{name:12} {p[7]}\n{'':12} to the receiver: {p[0]}\n{'':12} back: {p[1]}")
    return 0


def cmd_run(args):
    names = args.profiles or list(PROFILES)
    for n in names:
        if n not in PROFILES:
            print(f"no profile {n}; `list` names them", file=sys.stderr)
            return 2
    if args.logs:
        os.makedirs(args.logs, exist_ok=True)
    rows, failures = [], 0
    for n in names:
        try:
            ok, said = run(n, args.verbose, args.logs)
        except Exception as e:  # one profile's network that cannot be made is that profile's failure
            ok, said = False, f"not run: {e}"
        first = said.splitlines()[0]
        # Only speed and latency can fall short of a goal: a file that did
        # not arrive whole, or in time, fails whatever the profile.
        goal = (not ok and n in GOALS and not said.startswith(("not run", "the receiver"))
                and "did not arrive" not in said and "no summary" not in said)
        mark = "✓" if ok else ("◐" if goal else "✗")
        print(f"{mark} {n:12} {said}" + (f" (a goal: {GOALS[n]})" if goal else ""), flush=True)
        failures += not ok and not goal
        rows.append((n, PROFILES[n][7], f"{mark} " + first))
    if args.markdown:
        with open(args.markdown, "w") as f:
            f.write("| profile | the network | result |\n|---|---|---|\n")
            for row in rows:
                f.write("| " + " | ".join(row) + " |\n")
    print(f"{failures} not as required" if failures else "all as required")
    return 1 if failures else 0


def main():
    if os.environ.get("NETEMLAB_IN") != "1":
        os.execvp("unshare", ["unshare", "-rnm", "env", "NETEMLAB_IN=1", sys.executable] + sys.argv)
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    r = sub.add_parser("run")
    r.add_argument("profiles", nargs="*")
    r.add_argument("--markdown", help="write the results as a table to this file")
    r.add_argument("--logs", help="write what each profile's sender said to this directory")
    r.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    sh("ip", "link", "set", "lo", "up")
    # netem's delay distributions are where the distribution put them:
    # /usr/lib/tc on most, /usr/lib64/tc on some (Gentoo, Fedora).
    if not os.path.isdir("/usr/lib/tc") and os.path.isdir("/usr/lib64/tc"):
        os.environ.setdefault("TC_LIB_DIR", "/usr/lib64/tc")
    sys.exit({"list": cmd_list, "run": cmd_run}[args.cmd](args))


if __name__ == "__main__":
    main()
