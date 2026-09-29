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
`unshare -rnm`. The port-mapping scenarios also need miniupnpd (its nftables
build), the TURN ones coturn; the IPv6 ones a kernel with IPv6 (the
distribution's own, if the machine running this has it disabled: see
docs/NAT.md for how they were run in a virtual machine).

The things the protocol is measured against are not written by the same
hand as the protocol: the kernel does the translation, miniupnpd answers
UPnP, NAT-PMP and PCP, coturn is the TURN server, and the DHT node is a
script of about a hundred lines (dht_node.py) that shares no code with the
client.

    scripts/natlab/natlab.py oracle                 # check the NAT kinds themselves
    scripts/natlab/natlab.py matrix                 # every pair, real transfers, through a relay
    scripts/natlab/natlab.py matrix --via card      # ... with two contact cards handed over by "hand"
    scripts/natlab/natlab.py matrix --via turn      # ... and a TURN server (NATLAB_SIZE_MB=100: long
                                                    #     enough for a session to move to a direct path)
    scripts/natlab/natlab.py matrix --via dht       # ... and the DHT alone: the sender knows only an ID
    scripts/natlab/natlab.py pair port_restricted symmetric_random
    scripts/natlab/natlab.py portmap                # PCP, NAT-PMP, UPnP against miniupnpd
    scripts/natlab/natlab.py portmap6               # IPv6 pinholes (PCP, UPnP IGD2), with a control
    scripts/natlab/natlab.py lan                    # multicast DNS on one network
    scripts/natlab/natlab.py v6                     # IPv6 firewalls, and both families together
    scripts/natlab/natlab.py probe port_restricted symmetric_random   # sharp-probe on both hosts
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

    def addr6(self, ns, ifn, cidr, gw=None):
        """An IPv6 address, up at once: the kernel would otherwise hold it as
        tentative while it checks for a duplicate, and the first packets
        would leave from the wrong source."""
        self.x(ns, "sysctl", "-qw", f"net.ipv6.conf.{ifn}.accept_dad=0", check=False)
        self.x(ns, "ip", "-6", "addr", "add", cidr, "dev", ifn, "nodad")
        self.x(ns, "ip", "link", "set", ifn, "up")
        if gw:
            self.x(ns, "ip", "-6", "route", "add", "default", "via", gw)

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
    # IPv4 only: an "inet" table would drop IPv6 neighbour discovery too,
    # and with it the link (`v6_input` does the IPv6 half).
    return f"""table ip gw {{
  chain input {{
    type filter hook input priority filter;
    iifname "{wan}" ct state established,related accept
    iifname "{wan}" drop
  }}
}}
"""


# ----- the topology ----------------------------------------------------------

S1, S2 = "11.9.0.10", "11.9.0.11"
# IPv6: the same picture with a routed prefix per network and no translation.
# The prefixes are ordinary global unicast space (unallocated), so that the
# program treats them the way it would treat a real network's.
S61, S62 = "2a0e:aa00:f::10", "2a0e:aa00:f::11"

# What an IPv6 gateway does about packets that nobody inside asked for.
FW6_KINDS = {
    # nothing: every host is reachable (a router with no firewall)
    "open6": "no filtering",
    # RFC 6092's "simple security" as Linux conntrack does it: a packet is
    # let in only if it belongs to a flow that began inside — the same
    # address, port and port as the one the inside host sent to
    "stateful6": "address-and-port-dependent filtering",
    # the more permissive reading: from any port of a host that was sent to
    "restricted6": "address-dependent filtering",
}


def fw6_rules(kind, lan="lan", wan="wan"):
    """The ip6 forwarding rules that make a gateway's firewall `kind`."""
    if kind == "open6":
        return ""
    extra = ""
    allow = ""
    if kind == "restricted6":
        extra = """
  set contacted {
    type ipv6_addr . inet_service
    flags dynamic,timeout
    timeout 3m
  }"""
        # Address-dependent: the host, at whatever port, once it was sent
        # to. Keyed by the inside host's port, as the NAT kinds are.
        allow = f'iifname "{wan}" meta l4proto udp ip6 saddr . udp dport @contacted accept'
        record = f'iifname "{lan}" meta l4proto udp update @contacted {{ ip6 daddr . udp sport }}'
    else:
        record = ""
    return f"""table ip6 fw6 {{{extra}
  chain fw {{
    type filter hook forward priority filter; policy drop;
    ct state established,related accept
    {record}
    iifname "{lan}" accept
    {allow}
    icmpv6 type {{ destination-unreachable, packet-too-big, time-exceeded, parameter-problem }} accept
  }}
}}
"""


def v6_input(wan="wan"):
    """The v6 counterpart of `gateway_input`: nothing from outside is
    accepted by the router itself unless it answers something it sent (and
    neighbour discovery, which it needs to be reachable at all)."""
    return f"""table ip6 gw6 {{
  chain input {{
    type filter hook input priority filter;
    iifname "{wan}" ct state established,related accept
    iifname "{wan}" icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert, echo-request }} accept
    iifname "{wan}" drop
  }}
}}
"""


class Topo:
    """One instance of the picture at the top of this file."""

    def __init__(self, lab, a_nat, b_nat, a_cgn=None, b_cgn=None, v6=None, v4=True, isolate=False):
        """`v6` is a pair of firewall kinds (`FW6_KINDS`) for the two
        networks, or None for a network with no IPv6; `v4=False` leaves the
        hosts with no IPv4 at all."""
        self.lab = lab
        self.a_nat, self.b_nat, self.a_cgn, self.b_cgn = a_nat, b_nat, a_cgn, b_cgn
        self.v6 = v6
        self.v4 = v4
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
            if v4:
                lab.addr(host, "eth0", f"{lan_net}.2/24", f"{lan_net}.1")
            else:
                lab.x(host, "ip", "link", "set", "eth0", "up")
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
        if v6:
            self.wire_v6(v6, sides)
        if isolate:
            # The two networks cannot reach each other at all — as behind a
            # firewall that lets nothing peer-to-peer through — while both can
            # still reach the server. Whatever gets the transfer across is
            # the server's doing.
            lab.nft("I", """table inet isolate {
  chain cut {
    type filter hook forward priority filter - 1; policy accept;
    ip saddr 11.1.0.0/16 ip daddr 11.2.0.0/16 drop
    ip saddr 11.2.0.0/16 ip daddr 11.1.0.0/16 drop
    ip6 saddr 2a0e:aa00:1::/48 ip6 daddr 2a0e:aa00:2::/48 drop
    ip6 saddr 2a0e:aa00:2::/48 ip6 daddr 2a0e:aa00:1::/48 drop
  }
}
""")

    def wire_v6(self, kinds, sides):
        lab = self.lab
        self.v6_ip = {}
        for (host, gw, iface, _kind, _cgn, n), fw in zip(sides, kinds):
            lan, wan = f"2a0e:aa00:{n}:1", f"2a0e:aa00:{n}:e"
            lab.addr6(host, "eth0", f"{lan}::2/64")
            lab.addr6(gw, "lan", f"{lan}::1/64")
            # The default route of the host is the router's link-local
            # address in real life; a global one does as well here.
            lab.x(host, "ip", "-6", "route", "add", "default", "via", f"{lan}::1")
            # The network, and — as a real ISP delegates — routed to the
            # router's WAN address. A carrier-grade NAT is an IPv4 thing:
            # its namespace sits in the v4 path only.
            assert not (self.a_cgn if host == "A" else self.b_cgn), "no IPv6 behind a CGN here"
            lab.addr6(gw, "wan", f"{wan}::1/64")
            lab.addr6("I", iface, f"{wan}::254/64")
            lab.x(gw, "ip", "-6", "route", "add", "default", "via", f"{wan}::254")
            lab.x("I", "ip", "-6", "route", "add", f"{lan}::/64", "via", f"{wan}::1")
            lab.x(gw, "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1")
            lab.nft(gw, v6_input())
            rules = fw6_rules(fw)
            if rules:
                lab.nft(gw, rules)
            self.v6_ip[host] = f"{lan}::2"
        lab.addr6("S", "s0", f"{S61}/64")
        lab.x("S", "ip", "-6", "addr", "add", f"{S62}/64", "dev", "s0", "nodad")
        lab.x("S", "ip", "-6", "route", "add", "default", "via", "2a0e:aa00:f::254")
        lab.addr6("I", "iS", "2a0e:aa00:f::254/64")
        lab.x("I", "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1")


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


TURN_PORT = 3480
TURN_USER, TURN_PASSWORD = "alice", "s3cret"


def classify(connected, topo, relay_port, turn=False):
    """Which kind of path a session ended up on, from the address it uses."""
    if connected is None:
        return "none"
    ip, port = connected.rsplit(":", 1)
    ip = ip.strip("[]")
    if ip.startswith("::ffff:"):
        ip = ip[len("::ffff:"):]
    if turn and (ip == "127.0.0.1" or (ip in (S1, S61) and int(port) != relay_port)):
        # A TURN server's relayed address, or the address on this host that
        # stands for the receiver through the sender's own allocation.
        return "turn"
    if ip in (S1, S61) and int(port) != relay_port:
        return "relay"
    if ":" in ip:
        # An IPv6 address of one of the hosts: no NAT to go through.
        return "direct-v6"
    if ip in topo.wan_ip.values():
        return "direct-via-nat"
    if ip.startswith(("10.", "100.64.")):
        return "lan"
    return f"direct({ip})"


def server_arg(topo):
    """How the hosts name the server: its IPv6 address where they have no IPv4."""
    return f"[{S61}]" if not topo.v4 else S1


def stun_args(topo):
    out = []
    if topo.v4:
        out += ["--stun", f"{S1}:3478"]
    if topo.v6:
        out += ["--stun", f"[{S61}]:3478"]
    return out


def start_coturn(lab, v4=True, v6=False):
    """coturn — an independent implementation of TURN (RFC 8656, RFC 6156) —
    on the server host, with long-term credentials, on the families the
    laboratory has."""
    ips = ([S1] if v4 else []) + ([S61] if v6 else [])
    listening = "\n".join(f"listening-ip={ip}" for ip in ips)
    relaying = "\n".join(f"relay-ip={ip}" for ip in ips)
    conf = f"""{listening}
listening-port={TURN_PORT}
{relaying}
min-port=49152
max-port=49600
realm=sharp.lab
lt-cred-mech
user={TURN_USER}:{TURN_PASSWORD}
no-tls
no-dtls
no-cli
fingerprint
simple-log
log-file=stdout
pidfile={lab.dir}/turnserver.pid
"""
    path = os.path.join(lab.dir, "turnserver.conf")
    with open(path, "w") as f:
        f.write(conf)
    p = lab.spawn("S", ["turnserver", "-c", path], "coturn.log")
    time.sleep(1.0)
    return p


def transfer(a_nat, b_nat, a_cgn=None, b_cgn=None, carry=True, timeout=45, keep=False, verbose=False,
             via="relay", human_delay=2.0, v6=None, v4=True, isolate=False):
    """One real transfer, sender behind `a_nat`, receiver behind `b_nat`.

    `via` is how the two find each other: "relay" (a relay introduces them),
    "card" (no relay: the receiver's card is given to the sender, and —
    `human_delay` seconds later, the time a person takes to paste it — the
    sender's card is given to the receiver; only a STUN server is shared),
    "turn" (the same, and both are also given a TURN server to be
    reached through: coturn on the server host), or "dht" (no cards: both
    announce in a DHT — a one-node one on the server host, written
    independently of the client — and the sender is given the receiver's ID
    alone).
    Returns (ok, path, seconds, detail)."""
    lab = Lab(keep=keep)
    try:
        topo = Topo(lab, a_nat, b_nat, a_cgn, b_cgn, v6=v6, v4=v4, isolate=isolate)
        d = lab.dir
        srv = server_arg(topo)
        if v6 and os.environ.get("NATLAB_DIAG"):
            for ns in ("A", "RA", "I", "S"):
                print(f"--- {ns}: ip -6 addr / route")
                print(lab.x(ns, "ip", "-6", "addr", check=False).stdout[-900:])
                print(lab.x(ns, "ip", "-6", "route", check=False).stdout[-500:])
            for src, dst in (("A", "2a0e:aa00:1:1::1"), ("RA", "2a0e:aa00:1:e::254"), ("I", S61),
                             ("A", "2a0e:aa00:1:e::254"), ("A", "2a0e:aa00:f::254")):
                r = lab.x(src, "ping", "-6", "-c", "1", "-W", "2", dst, check=False)
                print(f"--- {src} ping {dst}:", (r.stdout.strip().splitlines() or ["?"])[-2:], r.stderr.strip()[-200:])
            for ns in ("RA", "I"):
                print(f"--- {ns}: forwarding =", lab.x(ns, "sysctl", "-n", "net.ipv6.conf.all.forwarding", check=False).stdout.strip())
                print(lab.x(ns, "nft", "list", "ruleset", check=False).stdout[-700:])
            r = lab.x("A", "ping", "-6", "-c", "2", "-W", "2", S61, check=False)
            print("--- A ping S:", r.stdout[-400:], r.stderr[-300:])
            r = lab.x("A", "ping", "-6", "-c", "2", "-W", "2", "2a0e:aa00:2:1::2", check=False)
            print("--- A ping B:", r.stdout[-400:], r.stderr[-300:])
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
            if v6:
                lab.nft("S", f"""table ip6 filter6 {{
  chain in {{
    type filter hook input priority filter;
    ct state established,related accept
    udp dport {{ 5560, 3478, 3479 }} accept
    icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert }} accept
    meta l4proto udp drop
  }}
}}
""")
        relay_stun = ["--stun", S1, "--stun", S2] + (["--stun", S61, "--stun", S62] if v6 else [])
        relay = lab.spawn(
            "S",
            [f"{BIN}/sharp-relay", "--bind", "[::]:5560" if v6 else "0.0.0.0:5560", *relay_stun,
             "--identity", f"{d}/relay.key", "--log", "info"],
            "relay.log",
        )
        m = wait_for(lab, "relay.log", r"Receivers: --relay (sh-\S+?)@", 10)
        if not m:
            return False, "none", 0, "the relay did not start:\n" + lab.log("relay.log")
        rid = m.group(1)
        if via in ("card", "turn"):
            return transfer_by_cards(lab, topo, d, human_delay, timeout, verbose, turn=(via == "turn"))
        if via == "dht":
            return transfer_by_dht(lab, topo, d, timeout, verbose)
        data = os.path.join(d, "payload.bin")
        with open(data, "wb") as f:
            f.write(os.urandom(1 << 20))
        want = hashlib.sha256(open(data, "rb").read()).hexdigest()
        os.makedirs(f"{d}/out", exist_ok=True)
        recv_args = [
            f"{BIN}/sharp-receiver", "--headless", "--output", f"{d}/out", "--state-dir", f"{d}/rst",
            "--identity", f"{d}/r.key", "--bind", "[::]:5555" if v6 else "0.0.0.0:5555", *stun_args(topo),
            "--relay", f"{rid}@{srv}:5560", "--log-level", "info",
        ]
        lab.spawn("B", recv_args, "receiver.log")
        m = wait_for(lab, "receiver.log", r"Senders use: (sh-\S+)", 15)
        if not m:
            return False, "none", 0, "the receiver did not start:\n" + lab.log("receiver.log")
        # Its address once the NAT tests are done: the same line again, now
        # with addresses in place of "<this host>".
        m = wait_for(lab, "receiver.log", r"Senders use: (sh-\S+@[\[\d]\S*)", 30)
        if m:
            address = m.group(1)
        else:
            # Nothing was published (a NAT that gives no address worth
            # publishing): a sender has only the relay to go by.
            address = f"{re.search(r'Senders use: (sh-[a-z0-9]+)', lab.log('receiver.log')).group(1)}@{srv}:9"
        start = time.time()
        send_args = [
            f"{BIN}/sharp-sender", data, address, "--relay", f"{srv}:5560", "--headless",
            *stun_args(topo),
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


def last_card(lab, log, pattern):
    """The most recent card a process printed."""
    found = re.findall(pattern, lab.log(log))
    return found[-1] if found else None


def transfer_by_cards(lab, topo, d, human_delay, timeout, verbose, turn=False):
    """The part of `transfer` that needs no relay: two people, two cards.
    With `turn`, both hosts also hold an allocation on a TURN server, whose
    address is on their cards."""
    turn_args = []
    if turn:
        start_coturn(lab, v4=topo.v4, v6=bool(topo.v6))
        turn_args = ["--turn", f"{TURN_USER}:{TURN_PASSWORD}@{server_arg(topo)}:{TURN_PORT}"]
    data = os.path.join(d, "payload.bin")
    # Small unless asked otherwise: a session carried by a relay is only moved
    # to a direct path if it lasts long enough for the path to open.
    size_mb = int(os.environ.get("NATLAB_SIZE_MB", "1"))
    with open(data, "wb") as f:
        for _ in range(size_mb):
            f.write(os.urandom(1 << 20))
    want = hashlib.sha256(open(data, "rb").read()).hexdigest()
    os.makedirs(f"{d}/out", exist_ok=True)
    recv = lab.spawn(
        "B",
        [f"{BIN}/sharp-receiver", "--headless", "--output", f"{d}/out", "--state-dir", f"{d}/rst",
         "--identity", f"{d}/r.key", "--bind", "[::]:5555" if topo.v6 else "0.0.0.0:5555",
         *stun_args(topo), *turn_args, "--log-level", "info"],
        "receiver.log",
        stdin=subprocess.PIPE,
    )
    m = wait_for(lab, "receiver.log", r"Your card:\s+(shc1-\S+)", 30)
    if not m:
        return False, "none", 0, "the receiver printed no card:\n" + lab.log("receiver.log")
    rcard = m.group(1)
    if turn:
        # The card that names the server's address is the one the sender
        # needs: wait for the allocation, and take the card printed after it.
        if not wait_for(lab, "receiver.log", r"relaying at", 20):
            return False, "none", 0, "the receiver got no TURN allocation:\n" + lab.log("receiver.log")
        time.sleep(0.5)
        rcard = last_card(lab, "receiver.log", r"Your card:\s+(shc1-\S+)") or rcard
    start = time.time()
    sender = lab.spawn(
        "A",
        [f"{BIN}/sharp-sender", data, rcard, "--headless", *stun_args(topo), *turn_args,
         "--identity", f"{d}/s.key", "--state-dir", f"{d}/sst", "--log-level", "info"],
        "sender.log",
    )
    if turn:
        wait_for(lab, "sender.log", r"relaying at", 20)
        time.sleep(0.5)
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
        # A person carries it across (the last one printed: with a TURN
        # server it is the one that names its address).
        time.sleep(human_delay)
        scard = last_card(lab, "sender.log", r"Your card: (shc1-\S+)") or m.group(1)
        recv.stdin.write((scard + "\n").encode())
        recv.stdin.flush()
    elif sender.poll() is None:
        sender.kill()
        return False, "none", 0, "the sender printed no card:\n" + lab.log("sender.log")
    samples = []
    end = time.time() + timeout
    while sender.poll() is None and time.time() < end:
        if os.environ.get("NATLAB_SAMPLE"):
            ct = lab.x("RA", "cat", "/proc/net/nf_conntrack", check=False).stdout
            n = sum(1 for l in ct.splitlines() if "dst=11.2.0.1" in l.split("src=")[1] if "udp" in l)
            samples.append(f"{time.time() - start:.0f}s:{n}")
        time.sleep(2)
    if sender.poll() is None:
        sender.kill()
    took = time.time() - start
    log = lab.log("sender.log")
    conn = re.search(r"Connected to (\S+)", log)
    # A session carried by a relay moves to a direct path once one opens: the
    # path it ended on is the last one it was moved to.
    proven = re.findall(r"receiver address (\S+) proven", log)
    path = classify(proven[-1] if proven else (conn.group(1) if conn else None), topo, 5560, turn=turn)
    if proven and conn:
        started = classify(conn.group(1), topo, 5560, turn=turn)
        if started != path:
            path += f" (from {started})"
    got = None
    for name in os.listdir(f"{d}/out"):
        if not name.endswith(".sharp-part"):
            got = hashlib.sha256(open(f"{d}/out/{name}", "rb").read()).hexdigest()
    ok = got == want
    detail = f"cards exchanged by hand after {human_delay:.0f}s" + (f"\nflows at the sender's NAT towards the receiver: {' '.join(samples)}" if samples else "")
    if verbose or not ok:
        for gw in ("RA", "RB"):
            ct = lab.x(gw, "cat", "/proc/net/nf_conntrack", check=False).stdout
            detail += f"\n--- conntrack in {gw}\n" + "\n".join(l[:170] for l in ct.splitlines() if "udp" in l)
        detail += "\n--- sender.log\n" + log[-2500:] + "\n--- receiver.log\n" + lab.log("receiver.log")[-2500:]
    return ok, path, took, detail


def transfer_by_dht(lab, topo, d, timeout, verbose):
    """Two hosts that know nothing of each other but the receiver's ID: both
    announce in a DHT and look for the other there."""
    node = server_arg(topo)
    dht = lab.spawn("S", ["python3", os.path.join(os.path.dirname(os.path.abspath(__file__)), "dht_node.py"),
                          "--bind", f"{node}:6881"], "dht.log")
    if not wait_for(lab, "dht.log", r"dht node", 10):
        return False, "none", 0, "the DHT node did not start:\n" + lab.log("dht.log")
    data = os.path.join(d, "payload.bin")
    with open(data, "wb") as f:
        f.write(os.urandom(1 << 20))
    want = hashlib.sha256(open(data, "rb").read()).hexdigest()
    os.makedirs(f"{d}/out", exist_ok=True)
    dht_args = ["--dht", "--dht-bootstrap", f"{node}:6881"]
    lab.spawn(
        "B",
        [f"{BIN}/sharp-receiver", "--headless", "--output", f"{d}/out", "--state-dir", f"{d}/rst",
         "--identity", f"{d}/r.key", "--bind", "[::]:5555" if topo.v6 else "0.0.0.0:5555",
         *stun_args(topo), *dht_args, "--log-level", "info"],
        "receiver.log",
    )
    m = wait_for(lab, "receiver.log", r"Receiver ID: (sh-\S+)", 15)
    if not m:
        return False, "none", 0, "the receiver did not start:\n" + lab.log("receiver.log")
    rid = m.group(1)
    start = time.time()
    sender = lab.spawn(
        "A",
        [f"{BIN}/sharp-sender", data, rid, "--headless", *stun_args(topo), *dht_args,
         "--identity", f"{d}/s.key", "--state-dir", f"{d}/sst", "--log-level", "info"],
        "sender.log",
    )
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
    detail = "found each other through the DHT node"
    if verbose or not ok:
        detail += "\n--- dht.log\n" + lab.log("dht.log")[-1500:]
        detail += "\n--- sender.log\n" + log[-2000:] + "\n--- receiver.log\n" + lab.log("receiver.log")[-2000:]
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
                                      verbose=args.verbose, keep=args.keep, via=args.via, isolate=args.isolate)
    print(f"sender behind {args.a}{'+cgn:' + args.a_cgn if args.a_cgn else ''}, receiver behind {args.b}: "
          f"{'OK' if ok else 'FAILED'} via {path} in {took:.1f}s")
    print(detail)
    return 0 if ok else 1


# Two NATs that both number their ports per destination cannot be punched
# through by anything that is worth sending (see src/nat/punch.rs): the
# ports each end would need to hit are the product of two unknowns. Every
# other pair is expected to open a direct path.
HARD = {"symmetric_seq", "symmetric_random"}


def expected(a, b, carry, via="relay", isolate=False):
    """(connects, path) as the engine is meant to behave for this pair.
    Cards name no relay (unless the receiver was started with one), so two
    hard NATs have nothing to fall back on there. With the networks isolated
    from each other nothing is direct: only a server that carries gets
    anything across."""
    if isolate:
        if via == "turn":
            return True, "turn"
        return (True, "relay") if carry and via == "relay" else (False, "none")
    if via == "dht":
        # A DHT says where the other end is and nothing of what its NAT
        # does, so the first punch cannot be aimed; the ones after it try
        # what each harder kind of NAT would need (see `punch::schedule`),
        # which takes a few passes. Two NATs that both draw ports at random
        # are out of reach, as they are for every method but a relay.
        if a in HARD and b in HARD:
            return False, "none"
        return True, "direct"
    if a in HARD and b in HARD:
        if via == "turn":
            # A TURN server carries, whatever the relay is allowed to do.
            return True, "turn"
        return (True, "relay") if carry and via == "relay" else (False, "none")
    return True, "direct"


def is_direct(path):
    return path.startswith("direct") or path == "lan"


def is_carried(path):
    return path in ("relay", "turn")


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
            ok, path, took, detail = transfer(a, b, carry=carry, timeout=args.timeout, via=args.via, isolate=args.isolate)
            want_ok, want_path = expected(a, b, carry, args.via, args.isolate)
            met = ok == want_ok and (
                not ok or is_carried(path) == is_carried(want_path) and (is_carried(want_path) or is_direct(path))
            )
            rows.append((a, b, ok, path, took, met))
            result = f"{'ok  ' if ok else 'FAIL'} {path:16} {took:5.1f}s"
            print(f"{a:18} {b:18} {result:30} {'as expected' if met else 'UNEXPECTED (wanted ' + want_path + ')'}", flush=True)
    failed = [r for r in rows if not r[2]]
    unexpected = [r for r in rows if not r[5]]
    direct = [r for r in rows if r[2] and is_direct(r[3])]
    relayed = [r for r in rows if r[2] and is_carried(r[3])]
    print(f"\n{len(rows) - len(failed)} of {len(rows)} pairs connected: {len(direct)} directly, {len(relayed)} through a relay or TURN server")
    print(f"{len(rows) - len(unexpected)} of {len(rows)} as the theory says they must")
    if args.markdown:
        with open(args.markdown, "w") as f:
            f.write("| sender behind | receiver behind | result | path | seconds | as expected |\n|---|---|---|---|---|---|\n")
            for a, b, ok, path, took, met in rows:
                f.write(f"| {a} | {b} | {'connected' if ok else 'not connected'} | {path} | {took:.1f} | {'yes' if met else '**NO**'} |\n")
    if args.allow_failures:
        return 0
    return 1 if unexpected else 0


def cmd_v6(args):
    """IPv6, and the two families together. Two networks, each with a
    firewall in front of it (`FW6_KINDS`); without IPv4 at all, and — the
    interesting one — with IPv4 NATs that could only meet through a relay,
    where the IPv6 path has to make the relay unnecessary."""
    rows = []
    kinds = list(FW6_KINDS)
    scenarios = [
        ("IPv6 only", "open", "open", False),
        ("dual stack, both IPv4 NATs symmetric-random", "symmetric_random", "symmetric_random", True),
    ]
    if args.scenario:
        scenarios = [sc for sc in scenarios if args.scenario in sc[0]]
    print(f"{'scenario':46} {'A firewall':12} {'B firewall':12} result")
    for name, an, bn, has_v4 in scenarios:
        for fa in kinds:
            for fb in kinds:
                if args.cell and args.cell != f"{fa},{fb}":
                    continue
                ok, path, took, detail = transfer(
                    an, bn, carry=not args.direct_only, timeout=args.timeout, via=args.via,
                    v6=(fa, fb), v4=has_v4, isolate=args.isolate,
                )
                # Both ends have a global IPv6 address and, at worst, a
                # stateful firewall: a direct path has to open in all nine
                # combinations, and it has to be the IPv6 one.
                met = ok and path == "direct-v6"
                rows.append((name, fa, fb, ok, path, took, met))
                print(f"{name:46} {fa:12} {fb:12} {'ok  ' if ok else 'FAIL'} {path:12} {took:5.1f}s "
                      f"{'as expected' if met else 'UNEXPECTED'}", flush=True)
                if not met and args.verbose:
                    print(detail)
    bad = [r for r in rows if not r[6]]
    print(f"\n{len(rows) - len(bad)} of {len(rows)} as they must be")
    if args.markdown:
        with open(args.markdown, "w") as f:
            f.write("| scenario | A firewall | B firewall | path | seconds | as expected |\n|---|---|---|---|---|---|\n")
            for name, fa, fb, ok, path, took, met in rows:
                f.write(f"| {name} | {fa} | {fb} | {path if ok else 'not connected'} | {took:.1f} | {'yes' if met else '**NO**'} |\n")
    return 0 if not bad or args.allow_failures else 1


def cmd_lan(args):
    """Two hosts on one network, no address given: the receiver announces
    itself with multicast DNS, the sender asks for it by ID. And the other
    way about: a receiver that does not announce is not found, and a
    sender that does not ask finds nothing — nobody is discoverable by
    default."""
    lab = Lab()
    try:
        lab.mk("A")
        lab.mk("B")
        # Both ends are made in this namespace first, so they cannot share a
        # name until each has moved to its own.
        lab.link("A", "lanA", "B", "lanB")
        for ns, old in (("A", "lanA"), ("B", "lanB")):
            lab.x(ns, "ip", "link", "set", old, "name", "eth0")
        lab.addr("A", "eth0", "10.9.0.1/24")
        lab.addr("B", "eth0", "10.9.0.2/24")
        for ns in ("A", "B"):
            lab.x(ns, "ip", "link", "set", "eth0", "multicast", "on")
        d = lab.dir
        data = os.path.join(d, "payload.bin")
        with open(data, "wb") as f:
            f.write(os.urandom(1 << 20))
        want = hashlib.sha256(open(data, "rb").read()).hexdigest()
        results = []

        def case(name, announce, ask, expect_ok, timeout):
            out = f"{d}/out-{name}"
            os.makedirs(out, exist_ok=True)
            receiver = lab.spawn(
                "B",
                [f"{BIN}/sharp-receiver", "--headless", "--output", out, "--state-dir", f"{d}/rst-{name}",
                 "--identity", f"{d}/r-{name}.key", "--bind", "0.0.0.0:5555", "--no-nat"]
                + (["--announce-lan"] if announce else [])
                + ["--log-level", "info"],
                f"receiver-{name}.log",
            )
            m = wait_for(lab, f"receiver-{name}.log", r"Receiver ID: (sh-\S+)", 15)
            if not m or (announce and not wait_for(lab, f"receiver-{name}.log", r"announced on the local network", 10)):
                print(f"{name}: the receiver did not start:\n" + lab.log(f"receiver-{name}.log")[-1500:])
                results.append(False)
                return
            start = time.time()
            sender = lab.spawn(
                "A",
                [f"{BIN}/sharp-sender", data, m.group(1), "--headless", "--no-nat"]
                + (["--lan"] if ask else [])
                + ["--identity", f"{d}/s-{name}.key", "--state-dir", f"{d}/sst-{name}", "--log-level", "info"],
                f"sender-{name}.log",
            )
            try:
                sender.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                sender.kill()
            took = time.time() - start
            got = None
            for f in os.listdir(out):
                if not f.endswith(".sharp-part"):
                    got = hashlib.sha256(open(f"{out}/{f}", "rb").read()).hexdigest()
            conn = re.search(r"Connected to (\S+)", lab.log(f"sender-{name}.log"))
            transferred = got == want and conn is not None and conn.group(1).startswith("10.9.0.2:")
            ok = transferred == expect_ok
            results.append(ok)
            what = f"via {conn.group(1)}" if conn else "found nobody"
            print(f"{name}: {'ok' if ok else 'FAILED'} - {what} in {took:.1f}s, as {'wanted' if ok else 'NOT wanted'}")
            if not ok:
                print(lab.log(f"sender-{name}.log")[-1500:])
                print(lab.log(f"receiver-{name}.log")[-1500:])
            receiver.terminate()

        case("announced and asked for", True, True, True, args.timeout)
        case("announced but not asked for", True, False, False, 12)
        case("asked for but not announced", False, True, False, 12)
        return 0 if all(results) else 1
    finally:
        lab.close()


MINIUPNPD_TABLE = """table inet miniupnpd {
  chain forward {
    type filter hook forward priority filter; policy accept;
    jump miniupnpd
  }
  chain miniupnpd {
  }
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    jump prerouting_miniupnpd
  }
  chain prerouting_miniupnpd {
  }
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    jump postrouting_miniupnpd
  }
  chain postrouting_miniupnpd {
  }
}
"""


def start_miniupnpd(lab, gw, ext_if, lan_ip, protocols, ext_ip):
    """miniupnpd — an independent implementation of UPnP-IGD, NAT-PMP and
    PCP — as the router's daemon, with the nftables backend and only the
    protocols in `protocols` switched on."""
    lab.nft(gw, MINIUPNPD_TABLE)
    conf = f"""ext_ifname={ext_if}
listening_ip={lan_ip}/24
ipv6_disable=yes
enable_pcp_pmp={'yes' if ('pcp' in protocols or 'natpmp' in protocols) else 'no'}
enable_upnp={'yes' if 'upnp' in protocols else 'no'}
secure_mode=no
system_uptime=yes
uuid=6d5c1a3e-1f3a-4c7e-9a52-3c1f7f0e2b11
min_lifetime=30
max_lifetime=86400
lease_file={lab.dir}/upnp.leases
upnp_table_name=miniupnpd
upnp_nat_table_name=miniupnpd
upnp_forward_chain=miniupnpd
upnp_nat_chain=prerouting_miniupnpd
upnp_nat_postrouting_chain=postrouting_miniupnpd
allow 1024-65535 0.0.0.0/0 1024-65535
"""
    path = os.path.join(lab.dir, "miniupnpd.conf")
    with open(path, "w") as f:
        f.write(conf)
    # `-o` names the router's external address, which a router behind
    # nothing else needs no help to find.
    return lab.spawn(gw, ["miniupnpd", "-d", "-f", path, "-o", ext_ip, "-P", os.path.join(lab.dir, "miniupnpd.pid")], "miniupnpd.log")


def cmd_portmap(args):
    """A receiver behind a router that runs miniupnpd asks it for a forward,
    publishes the address the router granted, and a sender behind *any* kind
    of NAT reaches it there — with no relay, no card and no punching from the
    receiver's side. That is what a port forward is worth: it turns the
    hardest receiver into a public one."""
    ok_all = True
    protos = args.protocols or ["pcp", "natpmp", "upnp"]
    kinds = args.senders or list(NAT_KINDS)
    print(f"{'receiver asks by':18} {'receiver NAT':18} {'sender behind':18} result")
    for proto in protos:
        for b_nat in args.receivers:
            for a_nat in kinds:
                lab = Lab()
                try:
                    topo = Topo(lab, a_nat, b_nat)
                    d = lab.dir
                    lab.spawn(
                        "S",
                        [f"{BIN}/sharp-relay", "--bind", "0.0.0.0:5560", "--stun", S1, "--stun", S2,
                         "--identity", f"{d}/relay.key", "--log", "info"],
                        "relay.log",
                    )
                    start_miniupnpd(lab, "RB", "wan", "11.2.0.0" if False else "10.2.0.1", [proto], topo.wan_ip["B"])
                    time.sleep(1.0)
                    data = os.path.join(d, "payload.bin")
                    with open(data, "wb") as f:
                        f.write(os.urandom(1 << 20))
                    want = hashlib.sha256(open(data, "rb").read()).hexdigest()
                    os.makedirs(f"{d}/out", exist_ok=True)
                    lab.spawn(
                        "B",
                        [f"{BIN}/sharp-receiver", "--headless", "--output", f"{d}/out", "--state-dir", f"{d}/rst",
                         "--identity", f"{d}/r.key", "--bind", "0.0.0.0:5555", "--stun", f"{S1}:3478",
                         "--log-level", "info"],
                        "receiver.log",
                    )
                    m = wait_for(lab, "receiver.log", r"reachable from outside at (\S+) \(port forward\)", 25)
                    log = lab.log("receiver.log")
                    if not m:
                        print(f"{proto:18} {b_nat:18} {a_nat:18} FAIL the receiver was granted no forward\n"
                              + "\n".join(l[:200] for l in log.splitlines()[-12:]))
                        ok_all = False
                        continue
                    forwarded = m.group(1)
                    rid = re.search(r"Receiver ID: (sh-\S+)", log).group(1)
                    start = time.time()
                    sender = lab.spawn(
                        "A",
                        [f"{BIN}/sharp-sender", data, f"{rid}@{forwarded}", "--headless", "--no-nat",
                         "--identity", f"{d}/s.key", "--state-dir", f"{d}/sst", "--log-level", "info"],
                        "sender.log",
                    )
                    try:
                        sender.wait(timeout=args.timeout)
                    except subprocess.TimeoutExpired:
                        sender.kill()
                    took = time.time() - start
                    got = None
                    for name in os.listdir(f"{d}/out"):
                        if not name.endswith(".sharp-part"):
                            got = hashlib.sha256(open(f"{d}/out/{name}", "rb").read()).hexdigest()
                    conn = re.search(r"Connected to (\S+)", lab.log("sender.log"))
                    ok = got == want and conn is not None and conn.group(1) == forwarded
                    ok_all &= ok
                    print(f"{proto:18} {b_nat:18} {a_nat:18} {'ok  ' if ok else 'FAIL'} via {forwarded} in {took:.1f}s", flush=True)
                    if not ok:
                        print(lab.log("miniupnpd.log")[-800:])
                        print(lab.log("sender.log")[-800:])
                finally:
                    lab.close()
    return 0 if ok_all else 1


MINIUPNPD6_TABLE = """table inet miniupnpd {
  chain forward {
    type filter hook forward priority filter; policy drop;
    ct state established,related accept
    iifname "lan" accept
    jump miniupnpd
    icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem } accept
  }
  chain miniupnpd {
  }
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    jump prerouting_miniupnpd
  }
  chain prerouting_miniupnpd {
  }
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    jump postrouting_miniupnpd
  }
  chain postrouting_miniupnpd {
  }
}
"""


def start_miniupnpd6(lab, gw, protocols, lan_v4, lan_v6):
    """miniupnpd on a router whose IPv6 firewall drops everything unasked: the
    UPnP IGD2 WANIPv6FirewallControl service (AddPinhole) and PCP (a MAP
    request over IPv6 opens the firewall for the host it names) are what
    open a way in, and only the protocols in `protocols` are switched on."""
    lab.nft(gw, MINIUPNPD6_TABLE)
    conf = f"""ext_ifname=wan
ext_ifname6=wan
listening_ip={lan_v4}/24
listening_ip={lan_v6}
ipv6_disable=no
enable_pcp_pmp={'yes' if 'pcp' in protocols else 'no'}
enable_upnp={'yes' if 'upnp' in protocols else 'no'}
secure_mode=no
system_uptime=yes
uuid=6d5c1a3e-1f3a-4c7e-9a52-3c1f7f0e2b12
min_lifetime=30
max_lifetime=86400
lease_file={lab.dir}/upnp.leases
upnp_table_name=miniupnpd
upnp_nat_table_name=miniupnpd
upnp_forward_chain=miniupnpd
upnp_nat_chain=prerouting_miniupnpd
upnp_nat_postrouting_chain=postrouting_miniupnpd
allow 1024-65535 0.0.0.0/0 1024-65535
allow 1024-65535 ::/0 1024-65535
"""
    path = os.path.join(lab.dir, "miniupnpd6.conf")
    with open(path, "w") as f:
        f.write(conf)
    return lab.spawn(gw, ["miniupnpd", "-d", "-f", path, "-P", os.path.join(lab.dir, "miniupnpd.pid")], "miniupnpd.log")


def cmd_portmap6(args):
    """IPv6: the receiver's router has a firewall that drops everything
    unasked, and runs miniupnpd. The receiver asks it to open a pinhole (PCP
    or UPnP IGD2), publishes its IPv6 address and port, and a sender that
    knows only that — no relay, no card, nothing to punch with from the
    receiver's side — gets in. The same without the router's daemon is the
    control: the firewall must stop the sender, or the test proves nothing."""
    ok_all = True
    protos = args.protocols or ["pcp", "upnp"]
    print(f"{'receiver asks by':18} {'daemon':8} result")
    for proto in protos + [None]:
        lab = Lab()
        try:
            # Both IPv4 NATs are hard, so no IPv4 path could carry the test.
            topo = Topo(lab, "port_restricted", "symmetric_random", v6=("open6", "open6"), v4=True)
            d = lab.dir
            lab.spawn(
                "S",
                [f"{BIN}/sharp-relay", "--bind", "[::]:5560", "--stun", S1, "--stun", S2, "--stun", S61, "--stun", S62,
                 "--identity", f"{d}/relay.key", "--log", "info"],
                "relay.log",
            )
            if proto:
                start_miniupnpd6(lab, "RB", [proto], "10.2.0.1", "2a0e:aa00:2:1::1")
            else:
                # The control: the same firewall, and no daemon to open it.
                lab.nft("RB", MINIUPNPD6_TABLE)
            time.sleep(1.5)
            data = os.path.join(d, "payload.bin")
            with open(data, "wb") as f:
                f.write(os.urandom(1 << 20))
            want = hashlib.sha256(open(data, "rb").read()).hexdigest()
            os.makedirs(f"{d}/out", exist_ok=True)
            lab.spawn(
                "B",
                [f"{BIN}/sharp-receiver", "--headless", "--output", f"{d}/out", "--state-dir", f"{d}/rst",
                 "--identity", f"{d}/r.key", "--bind", "[::]:5555", *stun_args(topo), "--log-level", "info"],
                "receiver.log",
            )
            rid = wait_for(lab, "receiver.log", r"Receiver ID: (sh-\S+)", 15)
            if not rid:
                print("the receiver did not start:\n" + lab.log("receiver.log")[-1200:])
                ok_all = False
                continue
            # What it publishes once its tests and the router have answered.
            time.sleep(12 if proto else 8)
            log = lab.log("receiver.log")
            forwards = re.findall(r"(?:IPv6 firewall|pinhole)[^\n]*", log)
            published = re.findall(r"Senders use: (sh-\S+)", log)
            address = published[-1] if published else rid.group(1)
            # Only its IPv6 addresses: the sender is not to have another way.
            v6 = [a for a in address.split("@", 1)[1].split(",") if a.startswith("[")] if "@" in address else []
            start = time.time()
            if not v6:
                print(f"{proto or 'nothing':18} {'yes' if proto else 'none':8} "
                      f"{'ok   (no IPv6 address was published, so nothing could get in)' if not proto else 'FAIL no IPv6 address was published'}")
                if proto:
                    ok_all = False
                    print("\n".join(l[:200] for l in log.splitlines()[-14:]))
                    print(lab.log("miniupnpd.log")[-1500:])
                continue
            target = f"{rid.group(1)}@{','.join(v6)}"
            sender = lab.spawn(
                "A",
                [f"{BIN}/sharp-sender", data, target, "--headless", "--no-nat",
                 "--identity", f"{d}/s.key", "--state-dir", f"{d}/sst", "--log-level", "info"],
                "sender.log",
            )
            try:
                sender.wait(timeout=args.timeout)
            except subprocess.TimeoutExpired:
                sender.kill()
            took = time.time() - start
            got = None
            for name in os.listdir(f"{d}/out"):
                if not name.endswith(".sharp-part"):
                    got = hashlib.sha256(open(f"{d}/out/{name}", "rb").read()).hexdigest()
            transferred = got == want
            ok = transferred == bool(proto)
            ok_all &= ok
            what = "got in" if transferred else "was stopped by the firewall"
            print(f"{proto or 'nothing':18} {'yes' if proto else 'none':8} "
                  f"{'ok  ' if ok else 'FAIL'} the sender {what} (via {', '.join(v6)}) in {took:.1f}s", flush=True)
            if not ok:
                print("\n".join(l[:200] for l in log.splitlines()[-14:]))
                print(lab.log("miniupnpd.log")[-1500:] if proto else "")
                print(lab.log("sender.log")[-1200:])
        finally:
            lab.close()
    return 0 if ok_all else 1


def cmd_samenat(args):
    """Two hosts behind one NAT — which is not a NAT that loops packets back
    (RFC 4787 REQ-9): a Linux one does not for the ports it hands out
    dynamically. The public address a relay tells the sender is then the
    router itself. What is expected: the receiver's own address on the
    network is worth having, and where it is kept back only a relay gets
    the transfer across."""
    ok_all = True
    print(f"{'case':56} result")
    for name, extra, carry, want in (
        ("the receiver publishes its address on the network", [], True, "lan"),
        ("...keeps it back, and the relay carries", ["--no-lan-addresses"], True, "relay"),
        ("...keeps it back, and the relay only introduces", ["--no-lan-addresses"], False, "none"),
    ):
        lab = Lab()
        try:
            lab.mk("RA")
            lab.mk("A")
            lab.mk("A2")
            lab.mk("I")
            lab.mk("S")
            # A bridge inside the router joins the two hosts.
            sh("ip", "link", "add", "vA", "type", "veth", "peer", "name", "pA")
            sh("ip", "link", "add", "vA2", "type", "veth", "peer", "name", "pA2")
            sh("ip", "link", "add", "wan0", "type", "veth", "peer", "name", "iA")
            sh("ip", "link", "add", "s0", "type", "veth", "peer", "name", "iS")
            for ns, ifn in (("A", "vA"), ("A2", "vA2"), ("RA", "pA"), ("RA", "pA2"), ("RA", "wan0"), ("S", "s0")):
                sh("ip", "link", "set", ifn, "netns", str(lab.pid[ns]))
            sh("ip", "link", "set", "iA", "up")
            sh("ip", "link", "set", "iS", "up")
            lab.x("RA", "ip", "link", "set", "wan0", "name", "wan")
            lab.x("A", "ip", "link", "set", "vA", "name", "eth0")
            lab.x("A2", "ip", "link", "set", "vA2", "name", "eth0")
            lab.x("RA", "ip", "link", "add", "lan", "type", "bridge")
            for ifn in ("pA", "pA2"):
                lab.x("RA", "ip", "link", "set", ifn, "master", "lan")
                lab.x("RA", "ip", "link", "set", ifn, "up")
            lab.addr("RA", "lan", "10.1.0.1/24")
            lab.addr("A", "eth0", "10.1.0.2/24", "10.1.0.1")
            lab.addr("A2", "eth0", "10.1.0.3/24", "10.1.0.1")
            lab.addr("RA", "wan", "11.1.0.1/24", "11.1.0.254")
            lab.addr("I", "iA", "11.1.0.254/24")
            lab.addr("S", "s0", f"{S1}/24", "11.9.0.254")
            lab.x("S", "ip", "addr", "add", f"{S2}/24", "dev", "s0")
            lab.addr("I", "iS", "11.9.0.254/24")
            lab.x("I", "sysctl", "-qw", "net.ipv4.ip_forward=1")
            lab.x("RA", "sysctl", "-qw", "net.ipv4.ip_forward=1")
            lab.nft("RA", nat_rules("port_restricted", "10.1.0.0/24").replace("$WANIP", "11.1.0.1"))
            lab.nft("RA", gateway_input())
            d = lab.dir
            if not carry:
                lab.nft("S", """table ip filter {
  chain in {
    type filter hook input priority filter;
    udp dport { 5560, 3478, 3479 } accept
    ip protocol udp drop
  }
}
""")
            lab.spawn(
                "S",
                [f"{BIN}/sharp-relay", "--bind", "0.0.0.0:5560", "--stun", S1, "--stun", S2,
                 "--identity", f"{d}/relay.key", "--log", "info"],
                "relay.log",
            )
            rid_m = wait_for(lab, "relay.log", r"Receivers: --relay (sh-\S+?)@", 10)
            data = os.path.join(d, "payload.bin")
            with open(data, "wb") as f:
                f.write(os.urandom(1 << 20))
            want_hash = hashlib.sha256(open(data, "rb").read()).hexdigest()
            os.makedirs(f"{d}/out", exist_ok=True)
            lab.spawn(
                "A2",
                [f"{BIN}/sharp-receiver", "--headless", "--output", f"{d}/out", "--state-dir", f"{d}/rst",
                 "--identity", f"{d}/r.key", "--bind", "0.0.0.0:5555", "--stun", f"{S1}:3478",
                 "--relay", f"{rid_m.group(1)}@{S1}:5560", *extra, "--log-level", "info"],
                "receiver.log",
            )
            m = wait_for(lab, "receiver.log", r"Senders use: (sh-\S+@[\d\[]\S*)", 30)
            log = lab.log("receiver.log")
            hairpin = "no hairpinning" if "no hairpinning" in log else ("hairpinning works" if "hairpinning works" in log else "unmeasured")
            rid = re.search(r"Receiver ID: (sh-\S+)", log).group(1)
            address = m.group(1) if m else f"{rid}@{S1}:9"
            start = time.time()
            sender = lab.spawn(
                "A",
                [f"{BIN}/sharp-sender", data, address, "--relay", f"{S1}:5560", "--headless", "--stun", f"{S1}:3478",
                 "--identity", f"{d}/s.key", "--state-dir", f"{d}/sst", "--log-level", "info"],
                "sender.log",
            )
            try:
                sender.wait(timeout=30)
            except subprocess.TimeoutExpired:
                sender.kill()
            took = time.time() - start
            got = None
            for f in os.listdir(f"{d}/out"):
                if not f.endswith(".sharp-part"):
                    got = hashlib.sha256(open(f"{d}/out/{f}", "rb").read()).hexdigest()
            conn = re.search(r"Connected to (\S+)", lab.log("sender.log"))
            topo = type("Topo", (), {"wan_ip": {"A": "11.1.0.1"}})()
            path = classify(conn.group(1) if conn else None, topo, 5560) if got == want_hash else "none"
            ok = path == want
            ok_all &= ok
            print(f"{name:56} {'ok  ' if ok else 'FAIL'} {path} in {took:.1f}s (the NAT says: {hairpin})", flush=True)
            if not ok:
                print(lab.log("sender.log")[-1500:])
                print(log[-1500:])
        finally:
            lab.close()
    return 0 if ok_all else 1


def cmd_timeout(args):
    """A NAT that forgets a UDP flow after a few seconds: the receiver's
    mapping towards its relay has to be kept alive by what it sends (see
    `nat::keepalive`), and shortened when the NAT is seen to have forgotten
    it anyway. After a wait many times the NAT's memory, a sender is put
    through."""
    lab = Lab()
    try:
        topo = Topo(lab, "port_restricted", "port_restricted")
        d = lab.dir
        # The NAT in front of the receiver keeps a flow for `args.memory`
        # seconds — and a reply to it as long.
        for key in ("nf_conntrack_udp_timeout", "nf_conntrack_udp_timeout_stream"):
            lab.x("RB", "sysctl", "-qw", f"net.netfilter.{key}={args.memory}")
        lab.spawn(
            "S",
            [f"{BIN}/sharp-relay", "--bind", "0.0.0.0:5560", "--stun", S1, "--stun", S2,
             "--identity", f"{d}/relay.key", "--log", "info"],
            "relay.log",
        )
        rid_m = wait_for(lab, "relay.log", r"Receivers: --relay (sh-\S+?)@", 10)
        data = os.path.join(d, "payload.bin")
        with open(data, "wb") as f:
            f.write(os.urandom(1 << 20))
        want = hashlib.sha256(open(data, "rb").read()).hexdigest()
        os.makedirs(f"{d}/out", exist_ok=True)
        lab.spawn(
            "B",
            [f"{BIN}/sharp-receiver", "--headless", "--output", f"{d}/out", "--state-dir", f"{d}/rst",
             "--identity", f"{d}/r.key", "--bind", "0.0.0.0:5555", "--stun", f"{S1}:3478",
             "--relay", f"{rid_m.group(1)}@{S1}:5560", "--log-level", "info"],
            "receiver.log",
        )
        m = wait_for(lab, "receiver.log", r"Senders use: (sh-\S+@[\d\[]\S*)", 30)
        rid = re.search(r"Receiver ID: (sh-\S+)", lab.log("receiver.log")).group(1)
        address = m.group(1) if m else f"{rid}@{S1}:9"
        print(f"the NAT in front of the receiver forgets a UDP flow after {args.memory} s; waiting {args.wait} s idle")
        end = time.time() + args.wait
        alive = []
        adapted_at = None
        while time.time() < end:
            time.sleep(max(1, args.wait // 12))
            ct = lab.x("RB", "cat", "/proc/net/nf_conntrack", check=False).stdout
            flows = [l for l in ct.splitlines() if "udp" in l and "dst=11.9.0.10" in l.split("src=")[1] and "dport=5560" in l]
            alive.append(len(flows))
            # Until the receiver has found out how short the NAT's memory is
            # its refreshes may be too far apart: the mapping is allowed to
            # lapse then, and what is asked is that it does not afterwards.
            if adapted_at is None and re.search(r"an idle mapping lasts", lab.log("receiver.log")):
                adapted_at = len(alive)
        log = lab.log("receiver.log")
        shortened = re.findall(r"keeping ours alive every ([\d.]+\w*)", log)
        print(f"flows towards the relay at the receiver's NAT, sampled while idle: {alive}")
        print(f"the receiver measured how long the NAT remembers a flow and now refreshes every: "
              f"{shortened[-1] if shortened else 'it did not measure it'}")
        sender = lab.spawn(
            "A",
            [f"{BIN}/sharp-sender", data, address, "--relay", f"{S1}:5560", "--headless", "--stun", f"{S1}:3478",
             "--identity", f"{d}/s.key", "--state-dir", f"{d}/sst", "--log-level", "info"],
            "sender.log",
        )
        try:
            sender.wait(timeout=40)
        except subprocess.TimeoutExpired:
            sender.kill()
        got = None
        for f in os.listdir(f"{d}/out"):
            if not f.endswith(".sharp-part"):
                got = hashlib.sha256(open(f"{d}/out/{f}", "rb").read()).hexdigest()
        conn = re.search(r"Connected to (\S+)", lab.log("sender.log"))
        # The last few samples: the interval takes effect at the refresh after
        # the one it was measured in.
        after = alive[-4:]
        kept = bool(shortened) and bool(after) and all(n > 0 for n in after)
        ok = got == want and kept
        print(f"a sender put through after the wait: {'ok' if got == want else 'FAILED'} via {conn.group(1) if conn else 'nothing'}; "
              f"mapping kept alive at the end of the wait: {'yes' if kept else 'NO'}")
        if not ok:
            print(log[-1500:])
            print(lab.log("sender.log")[-1500:])
        return 0 if ok else 1
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
    pair = sub.add_parser("pair")
    pair.add_argument("a", choices=list(NAT_KINDS))
    pair.add_argument("b", choices=list(NAT_KINDS))
    pair.add_argument("--a-cgn", choices=list(NAT_KINDS), default=None)
    pair.add_argument("--b-cgn", choices=list(NAT_KINDS), default=None)
    pair.add_argument("-v", "--verbose", action="store_true")
    pair.add_argument("--keep", action="store_true")
    pair.add_argument("--direct-only", action="store_true", help="the relay may introduce but not carry")
    pair.add_argument("--isolate", action="store_true", help="the two networks cannot reach each other, only the server")
    pair.add_argument("--via", choices=["relay", "card", "turn", "dht"], default="relay",
                      help="how the two find each other: a relay, or cards handed over by hand")
    probe = sub.add_parser("probe")
    probe.add_argument("a", choices=list(NAT_KINDS))
    probe.add_argument("b", choices=list(NAT_KINDS))
    probe.add_argument("--wait", type=int, default=20)
    v6 = sub.add_parser("v6")
    v6.add_argument("--scenario", default=None, help="only the scenarios whose name has this in it")
    v6.add_argument("--direct-only", action="store_true")
    v6.add_argument("--isolate", action="store_true", help="the two networks cannot reach each other, only the server")
    v6.add_argument("--via", choices=["relay", "card", "turn", "dht"], default="relay")
    v6.add_argument("--timeout", type=int, default=30)
    v6.add_argument("--markdown")
    v6.add_argument("--cell", default=None, help="only this pair of firewalls, e.g. stateful6,open6")
    v6.add_argument("--allow-failures", action="store_true")
    v6.add_argument("-v", "--verbose", action="store_true")
    lan = sub.add_parser("lan")
    lan.add_argument("--timeout", type=int, default=25)
    sub.add_parser("samenat")
    to = sub.add_parser("timeout")
    to.add_argument("--memory", type=int, default=8, help="seconds the NAT keeps a UDP flow")
    to.add_argument("--wait", type=int, default=60, help="seconds the receiver is left idle")
    pm6 = sub.add_parser("portmap6")
    pm6.add_argument("--protocols", nargs="*", choices=["pcp", "upnp"])
    pm6.add_argument("--timeout", type=int, default=25)
    pm = sub.add_parser("portmap")
    pm.add_argument("--protocols", nargs="*", choices=["pcp", "natpmp", "upnp"])
    pm.add_argument("--receivers", nargs="*", default=["port_restricted", "symmetric_random"], choices=list(NAT_KINDS))
    pm.add_argument("--senders", nargs="*", choices=list(NAT_KINDS))
    pm.add_argument("--timeout", type=int, default=25)
    matrix = sub.add_parser("matrix")
    matrix.add_argument("kinds", nargs="*", help="a subset of: " + " ".join(NAT_KINDS))
    matrix.add_argument("--markdown", help="write the results as a table to this file")
    matrix.add_argument("--allow-failures", action="store_true")
    matrix.add_argument("--direct-only", action="store_true", help="the relay may introduce but not carry")
    matrix.add_argument("--isolate", action="store_true", help="the two networks cannot reach each other, only the server")
    matrix.add_argument("--via", choices=["relay", "card", "turn", "dht"], default="relay",
                        help="how the two find each other: a relay, or cards handed over by hand")
    matrix.add_argument("--timeout", type=int, default=30)
    args = ap.parse_args()
    sh("ip", "link", "set", "lo", "up")
    sys.exit({"oracle": cmd_oracle, "pair": cmd_pair, "probe": cmd_probe, "matrix": cmd_matrix, "v6": cmd_v6, "portmap": cmd_portmap, "portmap6": cmd_portmap6, "samenat": cmd_samenat, "timeout": cmd_timeout, "lan": cmd_lan}[args.cmd](args))


if __name__ == "__main__":
    main()
