#!/usr/bin/env python3
"""A laboratory of real NATs, for proving what SHARP-256 does behind them.

Everything here is the Linux kernel's: network namespaces joined by veth
pairs, conntrack and nftables doing the address translation. The NAT kinds
are the ones RFC 4787 tells apart, made with rules the kernel really
enforces, and each is first checked by an independent probe written for
this file (the "oracle") that never touches SHARP-256 code — so what the
protocol is later measured against is not what the protocol believes.

      A --lan-- RA --wan-- I(core) --wan-- RB --lan-- B
                            |
                            S  (relay, STUN, a second address for it)

RA and RB are the gateways: each runs one NAT kind (or none). With
`cgn=True` a carrier-grade NAT (C) sits behind RA as well. A and B run the
real sharp-sender and sharp-receiver binaries.

Needs: unshare, nsenter, ip and nft from the distribution, python3. Root
inside a user namespace is enough: the script re-executes itself under
`unshare -rnm`.

    scripts/natlab/natlab.py oracle                 # check the NAT kinds themselves
    scripts/natlab/natlab.py matrix                 # every pair, real transfers
    scripts/natlab/natlab.py pair port_restricted symmetric_random
"""

import argparse
import hashlib
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BIN = os.environ.get("SHARP_BIN_DIR", os.path.join(ROOT, "target", "debug"))

# What a NAT can do, in RFC 4787 terms: how it maps (endpoint-independent =
# the same external port whatever the destination) and whom it lets in.
NAT_KINDS = {
    #                     mapping                       filtering
    "open": ("none", "none"),
    "full_cone": ("endpoint-independent", "endpoint-independent"),
    "restricted": ("endpoint-independent", "address-dependent"),
    "port_restricted": ("endpoint-independent", "address-and-port-dependent"),
    "symmetric_seq": ("address-and-port-dependent, sequential", "address-and-port-dependent"),
    "symmetric_random": ("address-and-port-dependent, random", "address-and-port-dependent"),
}


def sh(*cmd, check=True, **kw):
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)}: {r.stderr.strip() or r.stdout.strip()}")
    return r


class Lab:
    def __init__(self, keep=False):
        self.dir = tempfile.mkdtemp(prefix="natlab.")
        self.keep = keep
        self.pid = {}
        self.children = []
        self.core_ns = os.readlink("/proc/self/ns/net")

    # ----- namespaces -----------------------------------------------------

    def mk(self, name):
        p = subprocess.Popen(
            ["unshare", "-n", "sleep", "100000"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.children.append(p)
        self.pid[name] = p.pid
        # Until unshare has run, the process is still in our namespace.
        for _ in range(200):
            try:
                if os.readlink(f"/proc/{p.pid}/ns/net") != self.core_ns:
                    break
            except OSError:
                pass
            time.sleep(0.01)
        self.x(name, "ip", "link", "set", "lo", "up")

    def prefix(self, ns):
        return [] if ns == "I" else ["nsenter", "-t", str(self.pid[ns]), "-n"]

    def x(self, ns, *cmd, check=True):
        return sh(*self.prefix(ns), *cmd, check=check)

    def link(self, ns1, if1, ns2, if2):
        sh("ip", "link", "add", if1, "type", "veth", "peer", "name", if2)
        for ns, ifn in ((ns1, if1), (ns2, if2)):
            if ns != "I":
                sh("ip", "link", "set", ifn, "netns", str(self.pid[ns]))

    def addr(self, ns, ifn, cidr, gw=None):
        self.x(ns, "ip", "addr", "add", cidr, "dev", ifn)
        self.x(ns, "ip", "link", "set", ifn, "up")
        if gw:
            self.x(ns, "ip", "route", "add", "default", "via", gw)

    def nft(self, ns, ruleset):
        r = subprocess.run(
            self.prefix(ns) + ["nft", "-f", "-"], input=ruleset, capture_output=True, text=True
        )
        if r.returncode != 0:
            raise RuntimeError(f"nft in {ns}: {r.stderr.strip()}\n{ruleset[:600]}")

    # ----- processes ------------------------------------------------------

    def spawn(self, ns, args, log, env=None, stdin=None):
        f = open(os.path.join(self.dir, log), "w")
        e = dict(os.environ)
        e.update(env or {})
        p = subprocess.Popen(
            self.prefix(ns) + args,
            stdout=f,
            stderr=subprocess.STDOUT,
            stdin=stdin if stdin is not None else subprocess.DEVNULL,
            env=e,
            start_new_session=True,
        )
        self.children.append(p)
        return p

    def log(self, name):
        try:
            return open(os.path.join(self.dir, name)).read()
        except OSError:
            return ""

    def close(self):
        for p in reversed(self.children):
            try:
                os.killpg(p.pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                try:
                    p.terminate()
                except Exception:
                    pass
        for p in self.children:
            try:
                p.wait(timeout=3)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass
        if not self.keep:
            shutil.rmtree(self.dir, ignore_errors=True)


# ----- the NAT kinds, as nftables -------------------------------------------


def nat_rules(kind, inside, lan="lan", wan="wan"):
    """The nftables ruleset that makes a gateway behave as `kind`.

    Linux conntrack, left alone, keeps the source port when it can and
    admits a reply only from the exact address and port the inside host
    sent to: an endpoint-independent mapping with address-and-port-dependent
    filtering, which is what most home routers are. The other kinds change
    one of the two."""
    post = f'oifname "{wan}" masquerade'
    pre = ""
    extra = ""
    if kind == "open":
        return ""
    if kind == "port_restricted":
        pass
    elif kind == "full_cone":
        # Anything that arrives at any port goes to the inside host.
        pre = f'iifname "{wan}" udp dport 1024-65535 dnat to {inside}'
    elif kind == "restricted":
        extra = f"""
  set contacted {{
    type ipv4_addr . inet_service
    flags dynamic,timeout
    timeout 3m
  }}
  chain fw {{
    type filter hook forward priority filter;
    iifname "{lan}" meta l4proto udp update @contacted {{ ip daddr . udp sport }}
  }}"""
        # Per mapping, as a real address-restricted NAT keeps it: the
        # external port is the inside port (it is preserved), so the pair
        # "who wrote to it, at which port" is the mapping.
        pre = f'iifname "{wan}" udp dport 1024-65535 ip saddr . udp dport @contacted dnat to {inside}'
    elif kind == "symmetric_random":
        post = f'oifname "{wan}" masquerade fully-random'
    elif kind == "symmetric_seq":
        # A new external port for every new destination, one higher than the
        # last one handed out: the "sequential" allocators of older NATs.
        n = 2000
        table = ", ".join(f"{i} : {40000 + i}" for i in range(n))
        post = (
            f'oifname "{wan}" ip protocol udp snat to $WANIP : numgen inc mod {n} map {{ {table} }}'
        )
    else:
        raise ValueError(kind)
    prerouting = (
        f"""
  chain pre {{
    type nat hook prerouting priority dstnat;
    {pre}
  }}"""
        if pre
        else ""
    )
    return f"""table ip nat {{{extra}{prerouting}
  chain post {{
    type nat hook postrouting priority srcnat;
    {post}
  }}
}}
"""


def gateway_input(wan="wan"):
    """What every real home gateway does for packets addressed to itself
    from outside: nothing, unless they answer something it sent. Without
    this the router accepts a stray packet, replies "port unreachable" and
    keeps a confirmed conntrack entry for it — which then collides with the
    outgoing packet that would have opened the port for the peer. A router
    that drops it keeps no entry."""
    return f"""table inet gw {{
  chain input {{
    type filter hook input priority filter;
    iifname "{wan}" ct state established,related accept
    iifname "{wan}" drop
  }}
}}
"""


# ----- the topology ----------------------------------------------------------

S1, S2 = "11.9.0.10", "11.9.0.11"


class Topo:
    """One instance of the picture at the top of this file."""

    def __init__(self, lab, a_nat, b_nat, a_cgn=None, b_cgn=None):
        self.lab = lab
        self.a_nat, self.b_nat, self.a_cgn, self.b_cgn = a_nat, b_nat, a_cgn, b_cgn
        lab.mk("RA")
        lab.mk("RB")
        lab.mk("A")
        lab.mk("B")
        lab.mk("S")
        sides = (
            ("A", "RA", "iA", a_nat, a_cgn, 1),
            ("B", "RB", "iB", b_nat, b_cgn, 2),
        )
        self.wan_ip = {}
        self.inside_ip = {}
        for host, gw, iface, kind, cgn, n in sides:
            public = kind == "open"
            lan_net = f"11.{n}.1" if public else f"10.{n}.0"
            wan_net = f"11.{n}.0"
            lab.link(host, "eth0", gw, "lan")
            lab.addr(host, "eth0", f"{lan_net}.2/24", f"{lan_net}.1")
            lab.addr(gw, "lan", f"{lan_net}.1/24")
            self.inside_ip[host] = f"{lan_net}.2"
            if cgn:
                cg = f"C{host}"
                lab.mk(cg)
                lab.link(gw, "wan", cg, "cl")
                lab.link(cg, "cw", "I", iface)
                lab.addr(gw, "wan", "100.64.0.1/24", "100.64.0.254")
                lab.addr(cg, "cl", "100.64.0.254/24")
                lab.addr(cg, "cw", f"{wan_net}.1/24", f"{wan_net}.254")
                lab.addr("I", iface, f"{wan_net}.254/24")
                lab.x(cg, "sysctl", "-qw", "net.ipv4.ip_forward=1")
                lab.nft(cg, gateway_input("cw"))
                lab.nft(cg, nat_rules(cgn, "100.64.0.1", lan="cl", wan="cw").replace("$WANIP", f"{wan_net}.1"))
                self.wan_ip[host] = f"{wan_net}.1"
            else:
                lab.link(gw, "wan", "I", iface)
                lab.addr(gw, "wan", f"{wan_net}.1/24", f"{wan_net}.254")
                lab.addr("I", iface, f"{wan_net}.254/24")
                self.wan_ip[host] = f"{wan_net}.1"
            if public:
                # A public host: its network is routed to, not translated.
                lab.x("I", "ip", "route", "add", f"{lan_net}.0/24", "via", f"{wan_net}.1")
            lab.x(gw, "sysctl", "-qw", "net.ipv4.ip_forward=1")
            lab.nft(gw, gateway_input())
            rules = nat_rules(kind, f"{lan_net}.2")
            if rules:
                lab.nft(gw, rules.replace("$WANIP", f"{wan_net}.1"))
        lab.link("S", "s0", "I", "iS")
        lab.addr("S", "s0", f"{S1}/24", "11.9.0.254")
        lab.x("S", "ip", "addr", "add", f"{S2}/24", "dev", "s0")
        lab.addr("I", "iS", "11.9.0.254/24")
        lab.x("I", "sysctl", "-qw", "net.ipv4.ip_forward=1")


# ----- the oracle: does each kind do what it says? --------------------------

ECHO = r"""
import socket, sys, threading
def serve(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((ip, port))
    while True:
        d, a = s.recvfrom(100)
        s.sendto(("%s:%d" % a).encode(), a)
for ip in sys.argv[1].split(","):
    for port in (9000, 9001):
        threading.Thread(target=serve, args=(ip, port), daemon=True).start()
threading.Event().wait()
"""

CLIENT = r"""
import socket, sys, time
targets = [(a.split(":")[0], int(a.split(":")[1])) for a in sys.argv[1].split(",")]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 4000)); s.settimeout(1.5)
mapped = []
for t in targets:
    s.sendto(b"hi", t)
    try:
        mapped.append(s.recvfrom(100)[0].decode())
    except socket.timeout:
        mapped.append("none")
print("MAPPED " + " ".join(mapped), flush=True)
# A second socket that has talked to exactly one endpoint, for the filtering
# test: the first has talked to all of them.
f = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
f.bind(("0.0.0.0", 4001)); f.settimeout(1.5)
f.sendto(b"hi", targets[0])
try:
    print("FILTER " + f.recvfrom(100)[0].decode(), flush=True)
except socket.timeout:
    print("FILTER none", flush=True)
end = time.time() + float(sys.argv[2])
got = []
while time.time() < end:
    f.settimeout(max(0.05, end - time.time()))
    try:
        d, a = f.recvfrom(100)
        got.append("%s:%d" % a)
    except socket.timeout:
        break
print("GOT " + " ".join(got), flush=True)
"""

POKE = r"""
import socket, sys
target = sys.argv[1].split(":"); target = (target[0], int(target[1]))
for src in sys.argv[2].split(","):
    ip, port = src.split(":")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((ip, int(port)))
    s.sendto(src.encode(), target)
    s.close()
"""


def oracle(kind):
    """What one NAT does, measured from outside SHARP-256 entirely."""
    lab = Lab()
    try:
        # One gateway is enough: A behind `kind`, B irrelevant but present.
        Topo(lab, kind, "port_restricted")
        for f, code in (("echo.py", ECHO), ("client.py", CLIENT), ("poke.py", POKE)):
            open(os.path.join(lab.dir, f), "w").write(code)
        lab.spawn("S", ["python3", os.path.join(lab.dir, "echo.py"), f"{S1},{S2}"], "echo.log")
        time.sleep(0.5)
        # Mapping: one socket, four destinations.
        dests = f"{S1}:9000,{S1}:9001,{S2}:9000,{S2}:9001"
        client = subprocess.Popen(
            lab.prefix("A") + ["python3", os.path.join(lab.dir, "client.py"), dests, "4"],
            stdout=subprocess.PIPE,
            text=True,
        )
        line = client.stdout.readline().split()
        mapped = line[1:]
        ports = [m.split(":")[1] if m != "none" else None for m in mapped]
        ips = {m.split(":")[0] for m in mapped if m != "none"}
        # Filtering: from endpoints the second socket never wrote to, after
        # it wrote to (S1, 9000): the same address on another port, and
        # another address.
        target = client.stdout.readline().split()[1]
        lab.x("S", "python3", os.path.join(lab.dir, "poke.py"), target, f"{S1}:9101,{S2}:9100")
        got = client.stdout.readline().split()[1:]
        client.wait(timeout=10)
        if kind == "open":
            mapping = "none"
        elif len(set(ports)) == 1:
            mapping = "endpoint-independent"
        elif ports[0] == ports[1] and ports[2] == ports[3]:
            mapping = "address-dependent"
        else:
            mapping = "address-and-port-dependent"
        seq = None
        if mapping.startswith("address-and-port") and None not in ports:
            deltas = [int(b) - int(a) for a, b in zip(ports, ports[1:])]
            seq = "sequential" if deltas and all(d == deltas[0] for d in deltas) and abs(deltas[0]) < 50 else "random"
        got_from = set(got)
        if kind == "open":
            filtering = "none"
        elif f"{S2}:9100" in got_from and f"{S1}:9101" in got_from:
            filtering = "endpoint-independent"
        elif f"{S1}:9101" in got_from and f"{S2}:9100" not in got_from:
            filtering = "address-dependent"
        elif not got_from:
            filtering = "address-and-port-dependent"
        else:
            filtering = f"odd: {sorted(got_from)}"
        return mapping + (f", {seq}" if seq else ""), filtering, ports
    finally:
        lab.close()


# ----- real transfers -------------------------------------------------------


def wait_for(lab, log, pattern, seconds):
    """The first match of `pattern` in a process's log, waiting up to `seconds`."""
    end = time.time() + seconds
    while time.time() < end:
        m = re.search(pattern, lab.log(log))
        if m:
            return m
        time.sleep(0.2)
    return None


def classify(connected, topo, relay_port):
    """Which kind of path a session ended up on, from the address it uses."""
    if connected is None:
        return "none"
    ip, port = connected.rsplit(":", 1)
    if ip == S1 and int(port) != relay_port:
        return "relay"
    if ip in topo.wan_ip.values():
        return "direct-via-nat"
    if ip.startswith(("10.", "100.64.")):
        return "lan"
    return f"direct({ip})"


def transfer(a_nat, b_nat, a_cgn=None, b_cgn=None, carry=True, timeout=45, keep=False, verbose=False,
             via="relay", human_delay=2.0):
    """One real transfer, sender behind `a_nat`, receiver behind `b_nat`.

    `via` is how the two find each other: "relay" (a relay introduces them)
    or "card" (no relay: the receiver's card is given to the sender, and —
    `human_delay` seconds later, the time a person takes to paste it — the
    sender's card is given to the receiver; only a STUN server is shared).
    Returns (ok, path, seconds, detail)."""
    lab = Lab(keep=keep)
    try:
        topo = Topo(lab, a_nat, b_nat, a_cgn, b_cgn)
        d = lab.dir
        if not carry:
            # The relay may introduce the two, and tell them what each looks
            # like from outside — but it cannot carry anything: only what a
            # direct path could do is left.
            lab.nft("S", f"""table ip filter {{
  chain in {{
    type filter hook input priority filter;
    udp dport {{ 5560, 3478, 3479 }} accept
    ip protocol udp drop
  }}
}}
""")
        relay = lab.spawn(
            "S",
            [f"{BIN}/sharp-relay", "--bind", "0.0.0.0:5560", "--stun", S1, "--stun", S2,
             "--identity", f"{d}/relay.key", "--log", "info"],
            "relay.log",
        )
        m = wait_for(lab, "relay.log", r"Receivers: --relay (sh-\S+?)@", 10)
        if not m:
            return False, "none", 0, "the relay did not start:\n" + lab.log("relay.log")
        rid = m.group(1)
        if via == "card":
            return transfer_by_cards(lab, topo, d, human_delay, timeout, verbose)
        data = os.path.join(d, "payload.bin")
        with open(data, "wb") as f:
            f.write(os.urandom(1 << 20))
        want = hashlib.sha256(open(data, "rb").read()).hexdigest()
        os.makedirs(f"{d}/out", exist_ok=True)
        recv_args = [
            f"{BIN}/sharp-receiver", "--headless", "--output", f"{d}/out", "--state-dir", f"{d}/rst",
            "--identity", f"{d}/r.key", "--bind", "0.0.0.0:5555", "--stun", f"{S1}:3478",
            "--relay", f"{rid}@{S1}:5560", "--log-level", "info",
        ]
        lab.spawn("B", recv_args, "receiver.log")
        m = wait_for(lab, "receiver.log", r"Senders use: (sh-\S+)", 15)
        if not m:
            return False, "none", 0, "the receiver did not start:\n" + lab.log("receiver.log")
        # Its address once the NAT tests are done: the same line again, now
        # with addresses in place of "<this host>".
        m = wait_for(lab, "receiver.log", r"Senders use: (sh-\S+@\d+\.\d+\.\d+\.\d+:\d+\S*)", 30)
        if m:
            address = m.group(1)
        else:
            # Nothing was published (a NAT that gives no address worth
            # publishing): a sender has only the relay to go by.
            address = f"{re.search(r'Senders use: (sh-[a-z0-9]+)', lab.log('receiver.log')).group(1)}@{S1}:9"
        start = time.time()
        send_args = [
            f"{BIN}/sharp-sender", data, address, "--relay", f"{S1}:5560", "--headless",
            "--stun", f"{S1}:3478",
            "--identity", f"{d}/s.key", "--state-dir", f"{d}/sst", "--log-level", "info",
        ]
        sender = lab.spawn("A", send_args, "sender.log")
        try:
            sender.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            sender.kill()
        took = time.time() - start
        log = lab.log("sender.log")
        conn = re.search(r"Connected to (\S+)", log)
        path = classify(conn.group(1) if conn else None, topo, 5560)
        got = None
        for name in os.listdir(f"{d}/out"):
            if not name.endswith(".sharp-part"):
                got = hashlib.sha256(open(f"{d}/out/{name}", "rb").read()).hexdigest()
        ok = got == want
        detail = f"receiver published {address}"
        if verbose or not ok:
            for gw in ("RA", "RB"):
                ct = lab.x(gw, "cat", "/proc/net/nf_conntrack", check=False).stdout
                detail += f"\n--- conntrack in {gw}\n" + "\n".join(
                    l[:170] for l in ct.splitlines() if "udp" in l
                )
            detail += "\n--- sender.log\n" + log[-1500:] + "\n--- receiver.log\n" + lab.log("receiver.log")[-1500:]
        return ok, path, took, detail
    finally:
        lab.close()


def transfer_by_cards(lab, topo, d, human_delay, timeout, verbose):
    """The part of `transfer` that needs no relay: two people, two cards."""
    data = os.path.join(d, "payload.bin")
    with open(data, "wb") as f:
        f.write(os.urandom(1 << 20))
    want = hashlib.sha256(open(data, "rb").read()).hexdigest()
    os.makedirs(f"{d}/out", exist_ok=True)
    recv = lab.spawn(
        "B",
        [f"{BIN}/sharp-receiver", "--headless", "--output", f"{d}/out", "--state-dir", f"{d}/rst",
         "--identity", f"{d}/r.key", "--bind", "0.0.0.0:5555", "--stun", f"{S1}:3478",
         "--log-level", "info"],
        "receiver.log",
        stdin=subprocess.PIPE,
    )
    m = wait_for(lab, "receiver.log", r"Your card:\s+(shc1-\S+)", 30)
    if not m:
        return False, "none", 0, "the receiver printed no card:\n" + lab.log("receiver.log")
    rcard = m.group(1)
    start = time.time()
    sender = lab.spawn(
        "A",
        [f"{BIN}/sharp-sender", data, rcard, "--headless", "--stun", f"{S1}:3478",
         "--identity", f"{d}/s.key", "--state-dir", f"{d}/sst", "--log-level", "info"],
        "sender.log",
    )
    # The sender may be done before it has a card to give: a receiver that
    # can be reached as it stands needs nothing from the sender.
    m = None
    end = time.time() + 30
    while time.time() < end and sender.poll() is None:
        m = re.search(r"Your card: (shc1-\S+)", lab.log("sender.log"))
        if m:
            break
        time.sleep(0.2)
    if m and sender.poll() is None:
        # A person carries it across.
        time.sleep(human_delay)
        recv.stdin.write((m.group(1) + "\n").encode())
        recv.stdin.flush()
    elif sender.poll() is None:
        sender.kill()
        return False, "none", 0, "the sender printed no card:\n" + lab.log("sender.log")
    try:
        sender.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        sender.kill()
    took = time.time() - start
    log = lab.log("sender.log")
    conn = re.search(r"Connected to (\S+)", log)
    path = classify(conn.group(1) if conn else None, topo, 5560)
    got = None
    for name in os.listdir(f"{d}/out"):
        if not name.endswith(".sharp-part"):
            got = hashlib.sha256(open(f"{d}/out/{name}", "rb").read()).hexdigest()
    ok = got == want
    detail = f"cards exchanged by hand after {human_delay:.0f}s"
    if verbose or not ok:
        for gw in ("RA", "RB"):
            ct = lab.x(gw, "cat", "/proc/net/nf_conntrack", check=False).stdout
            detail += f"\n--- conntrack in {gw}\n" + "\n".join(l[:170] for l in ct.splitlines() if "udp" in l)
        detail += "\n--- sender.log\n" + log[-2500:] + "\n--- receiver.log\n" + lab.log("receiver.log")[-2500:]
    return ok, path, took, detail


def cmd_probe(args):
    """`sharp-probe` on both hosts of a pair: each prints what it sees and
    its card, the cards are swapped by hand (through standard input), and
    each says whether a packet from the other arrived."""
    lab = Lab(keep=False)
    try:
        topo = Topo(lab, args.a, args.b, None, None)
        d = lab.dir
        lab.spawn(
            "S",
            [f"{BIN}/sharp-relay", "--bind", "0.0.0.0:5560", "--stun", S1, "--stun", S2,
             "--identity", f"{d}/relay.key", "--log", "info"],
            "relay.log",
        )
        if not wait_for(lab, "relay.log", r"Receivers: --relay", 10):
            print("the relay (and its STUN server) did not start")
            return 1
        procs, cards = {}, {}
        for ns, name, extra in (("A", "a", []), ("B", "b", ["--receiver"])):
            procs[name] = lab.spawn(
                ns,
                [f"{BIN}/sharp-probe", "--stun", f"{S1}:3478", "--no-port-mapping", "--stdin",
                 "--identity", f"{d}/{name}.key", "--wait", str(args.wait), "--log-level", "info", *extra],
                f"probe_{name}.log",
                stdin=subprocess.PIPE,
            )
        for name in ("a", "b"):
            m = wait_for(lab, f"probe_{name}.log", r"^(shc1-\S+)$", 40) if False else None
            end = time.time() + 40
            while time.time() < end and not m:
                m = re.search(r"^(shc1-\S+)$", lab.log(f"probe_{name}.log"), re.M)
                time.sleep(0.2)
            if not m:
                print(f"host {name.upper()} printed no card:\n" + lab.log(f"probe_{name}.log")[-1500:])
                return 1
            cards[name] = m.group(1)
            report = lab.log(f"probe_{name}.log").split("Your card")[0]
            print(f"--- host {name.upper()} behind {args.a if name == 'a' else args.b}\n{report.split('Measuring')[-1]}")
        # Each is handed the other's card, one after the other, as two people would.
        for name, other in (("a", "b"), ("b", "a")):
            procs[name].stdin.write((cards[other] + "\n").encode())
            procs[name].stdin.flush()
        for p in procs.values():
            try:
                p.wait(timeout=args.wait + 30)
            except subprocess.TimeoutExpired:
                p.kill()
        codes = [procs[n].returncode for n in ("a", "b")]
        for name in ("a", "b"):
            tail = lab.log(f"probe_{name}.log").split("Sending at")[-1]
            print(f"--- punch test, host {name.upper()}\nSending at{tail[-700:]}")
        want_ok, _ = expected(args.a, args.b, False, "card")
        ok = all(c == 0 for c in codes)
        print(f"punch test: {'a packet got through both ways' if ok else 'nothing got through'} "
              f"({'as expected' if ok == want_ok else 'UNEXPECTED'})")
        return 0 if ok == want_ok else 1
    finally:
        lab.close()


def cmd_pair(args):
    ok, path, took, detail = transfer(args.a, args.b, args.a_cgn, args.b_cgn, carry=not args.direct_only,
                                      verbose=args.verbose, keep=args.keep, via=args.via)
    print(f"sender behind {args.a}{'+cgn:' + args.a_cgn if args.a_cgn else ''}, receiver behind {args.b}: "
          f"{'OK' if ok else 'FAILED'} via {path} in {took:.1f}s")
    print(detail)
    return 0 if ok else 1


# Two NATs that both number their ports per destination cannot be punched
# through by anything that is worth sending (see src/nat/punch.rs): the
# ports each end would need to hit are the product of two unknowns. Every
# other pair is expected to open a direct path.
HARD = {"symmetric_seq", "symmetric_random"}


def expected(a, b, carry, via="relay"):
    """(connects, path) as the engine is meant to behave for this pair.
    Cards name no relay (unless the receiver was started with one), so two
    hard NATs have nothing to fall back on there."""
    if a in HARD and b in HARD:
        return (True, "relay") if carry and via == "relay" else (False, "none")
    return True, "direct"


def is_direct(path):
    return path.startswith("direct") or path == "lan"


def cmd_matrix(args):
    kinds = args.kinds or list(NAT_KINDS)
    for k in kinds:
        if k not in NAT_KINDS:
            raise SystemExit(f"unknown NAT kind {k}; choose from {' '.join(NAT_KINDS)}")
    rows = []
    carry = not args.direct_only
    print(f"{'sender behind':18} {'receiver behind':18} {'result':30} verdict")
    for a in kinds:
        for b in kinds:
            ok, path, took, detail = transfer(a, b, carry=carry, timeout=args.timeout, via=args.via)
            want_ok, want_path = expected(a, b, carry, args.via)
            met = ok == want_ok and (
                not ok or (path == "relay") == (want_path == "relay") and (want_path == "relay" or is_direct(path))
            )
            rows.append((a, b, ok, path, took, met))
            result = f"{'ok  ' if ok else 'FAIL'} {path:16} {took:5.1f}s"
            print(f"{a:18} {b:18} {result:30} {'as expected' if met else 'UNEXPECTED (wanted ' + want_path + ')'}", flush=True)
    failed = [r for r in rows if not r[2]]
    unexpected = [r for r in rows if not r[5]]
    direct = [r for r in rows if r[2] and is_direct(r[3])]
    relayed = [r for r in rows if r[2] and r[3] == "relay"]
    print(f"\n{len(rows) - len(failed)} of {len(rows)} pairs connected: {len(direct)} directly, {len(relayed)} through the relay")
    print(f"{len(rows) - len(unexpected)} of {len(rows)} as the theory says they must")
    if args.markdown:
        with open(args.markdown, "w") as f:
            f.write("| sender behind | receiver behind | result | path | seconds | as expected |\n|---|---|---|---|---|---|\n")
            for a, b, ok, path, took, met in rows:
                f.write(f"| {a} | {b} | {'connected' if ok else 'not connected'} | {path} | {took:.1f} | {'yes' if met else '**NO**'} |\n")
    if args.allow_failures:
        return 0
    return 1 if unexpected else 0


def cmd_oracle(args):
    bad = 0
    print(f"{'kind':18} {'measured mapping':44} {'measured filtering':30} verdict")
    for kind in NAT_KINDS:
        want_map, want_filter = NAT_KINDS[kind]
        try:
            m, f, ports = oracle(kind)
        except Exception as e:
            print(f"{kind:18} ERROR {e}")
            bad += 1
            continue
        ok = m == want_map and f == want_filter
        bad += 0 if ok else 1
        print(f"{kind:18} {m:44} {f:30} {'ok' if ok else 'WRONG, wanted ' + want_map + ' / ' + want_filter}  {ports}")
    return 1 if bad else 0


def main():
    if os.environ.get("NATLAB_IN") != "1":
        os.execvp(
            "unshare",
            ["unshare", "-rnm", "env", "NATLAB_IN=1", sys.executable] + sys.argv,
        )
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("oracle")
    pair = sub.add_parser("pair")
    pair.add_argument("a", choices=list(NAT_KINDS))
    pair.add_argument("b", choices=list(NAT_KINDS))
    pair.add_argument("--a-cgn", choices=list(NAT_KINDS), default=None)
    pair.add_argument("--b-cgn", choices=list(NAT_KINDS), default=None)
    pair.add_argument("-v", "--verbose", action="store_true")
    pair.add_argument("--keep", action="store_true")
    pair.add_argument("--direct-only", action="store_true", help="the relay may introduce but not carry")
    pair.add_argument("--via", choices=["relay", "card"], default="relay",
                      help="how the two find each other: a relay, or cards handed over by hand")
    probe = sub.add_parser("probe")
    probe.add_argument("a", choices=list(NAT_KINDS))
    probe.add_argument("b", choices=list(NAT_KINDS))
    probe.add_argument("--wait", type=int, default=20)
    matrix = sub.add_parser("matrix")
    matrix.add_argument("kinds", nargs="*", help="a subset of: " + " ".join(NAT_KINDS))
    matrix.add_argument("--markdown", help="write the results as a table to this file")
    matrix.add_argument("--allow-failures", action="store_true")
    matrix.add_argument("--direct-only", action="store_true", help="the relay may introduce but not carry")
    matrix.add_argument("--via", choices=["relay", "card"], default="relay",
                        help="how the two find each other: a relay, or cards handed over by hand")
    matrix.add_argument("--timeout", type=int, default=30)
    args = ap.parse_args()
    sh("ip", "link", "set", "lo", "up")
    sys.exit({"oracle": cmd_oracle, "pair": cmd_pair, "probe": cmd_probe, "matrix": cmd_matrix}[args.cmd](args))


if __name__ == "__main__":
    main()
