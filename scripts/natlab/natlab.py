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

    def spawn(self, ns, args, log, env=None):
        f = open(os.path.join(self.dir, log), "w")
        e = dict(os.environ)
        e.update(env or {})
        p = subprocess.Popen(
            self.prefix(ns) + args,
            stdout=f,
            stderr=subprocess.STDOUT,
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
    args = ap.parse_args()
    sh("ip", "link", "set", "lo", "up")
    sys.exit({"oracle": cmd_oracle}[args.cmd](args))


if __name__ == "__main__":
    main()
