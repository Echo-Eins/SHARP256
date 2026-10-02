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

RA and RB are the gateways: each runs one NAT kind (or none). Either can
also sit behind a carrier-grade NAT of a kind of its own (CA, CB: `a_cgn`,
`b_cgn`), and a gateway of the kind "route" behind one translates nothing,
as a DS-Lite home router does not. A and B run the real sharp-sender and
sharp-receiver binaries.

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
    scripts/natlab/natlab.py matrix --via turn      # ... and a TURN server (NATLAB_SIZE_MB=30 NATLAB_MAX_RATE=20M:
                                                    #     long enough for a session to move to a direct path)
    scripts/natlab/natlab.py matrix --via dht       # ... and the DHT alone: the sender knows only an ID
    scripts/natlab/natlab.py matrix --via addr      # ... and no cards, no server: two addresses read off two screens
    scripts/natlab/natlab.py pair port_restricted symmetric_random
    scripts/natlab/natlab.py portmap                # PCP, NAT-PMP, UPnP against miniupnpd
    scripts/natlab/natlab.py portmap --taken        # ... with the port asked for already forwarded to another
    scripts/natlab/natlab.py portmap6               # IPv6 pinholes (PCP, UPnP IGD2), with a control
    scripts/natlab/natlab.py lan [--v6]             # multicast DNS on one network (with IPv6 only)
    scripts/natlab/natlab.py samenat                # two hosts behind one NAT, with and without hairpinning
    scripts/natlab/natlab.py samecgn                # two subscribers behind one carrier-grade NAT, with and without
    scripts/natlab/natlab.py nat66                  # NAT on IPv6: unique local addresses inside
    scripts/natlab/natlab.py dslite                 # the receiver's IPv4 in a DS-Lite tunnel to the carrier's NAT
    scripts/natlab/natlab.py dhtplant               # a DHT node that plants an address: what reaches it
    scripts/natlab/natlab.py early                  # a sender that starts before its receiver has registered
    scripts/natlab/natlab.py fallback               # a direct path that dies: back to the relay or TURN server
    scripts/natlab/natlab.py cgn                    # a carrier-grade NAT in front of the home router: two NATs in a row
    scripts/natlab/natlab.py mobility               # one end or both change networks mid-transfer: back to a direct path
    scripts/natlab/natlab.py speed [--mb 100]       # how fast directly, through a relay, through TURN
    scripts/natlab/natlab.py v6                     # IPv6 firewalls, and both families together
    scripts/natlab/natlab.py probe port_restricted symmetric_random   # sharp-probe on both hosts
    scripts/natlab/natlab.py probe --all --wait 12  # ... for every pair: does its verdict match what a transfer does,
                                                    #     and is what each host says of its own NAT true?
    scripts/natlab/natlab.py probe --v6 --wait 12   # ... over IPv6, for every pair of firewalls
    scripts/natlab/natlab.py probe --all --addr --wait 45   # ... with addresses swapped instead of cards

NATLAB_LOG sets the binaries' log level (default info); NATLAB_KEEP keeps a
mobility case's laboratory directory, logs and all.
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


# No duplicate address detection anywhere in a laboratory: nothing in it can
# have a duplicate, and while an interface's link-local address is still
# being checked — a second or two after the interface comes up — Linux will
# not solicit a neighbour for a packet it forwards. Every router of the
# laboratory would hold every IPv6 packet it routes for that long, and a
# program that measures its network the moment it starts (a host with IPv6
# alone has nothing else to measure first) finds no answer on a fast machine
# and a full one on a slow one. Real routers have been up for longer than
# that. Set in a namespace before any link comes into it: an interface takes
# the "default" of the namespace it is moved to, and DAD is skipped only if
# "all" says so too. (Where the kernel has no IPv6 the settings do not
# exist, and nothing needs them.)
NO_DAD = ("net.ipv6.conf.all.accept_dad=0", "net.ipv6.conf.default.accept_dad=0")


class Lab:
    def __init__(self, keep=False):
        self.dir = tempfile.mkdtemp(prefix="natlab.")
        self.keep = keep
        self.pid = {}
        self.children = []
        self.core_ns = os.readlink("/proc/self/ns/net")
        # Link ends made in this process's own namespace (the core, "I"):
        # see `close`.
        self.core_links = []
        for setting in NO_DAD:
            sh("sysctl", "-qw", setting, check=False)

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
        for setting in NO_DAD:
            self.x(name, "sysctl", "-qw", setting, check=False)
        self.x(name, "ip", "link", "set", "lo", "up")

    def settle(self, names, within=5.0):
        """Waits, `within` seconds at most, until no IPv6 address in the
        namespaces `names` is still being checked for duplicates (`NO_DAD`
        should have seen to that: this is for a kernel that ignored it)."""
        end = time.time() + within
        while time.time() < end:
            if not any(self.x(n, "ip", "-6", "addr", "show", "tentative", check=False).stdout.strip() for n in names):
                return True
            time.sleep(0.1)
        return False

    def prefix(self, ns):
        return [] if ns == "I" else ["nsenter", "-t", str(self.pid[ns]), "-n"]

    def x(self, ns, *cmd, check=True):
        return sh(*self.prefix(ns), *cmd, check=check)

    def link(self, ns1, if1, ns2, if2):
        sh("ip", "link", "add", if1, "type", "veth", "peer", "name", if2)
        for ns, ifn in ((ns1, if1), (ns2, if2)):
            if ns != "I":
                sh("ip", "link", "set", ifn, "netns", str(self.pid[ns]))
            else:
                self.core_links.append(ifn)

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
        # The core ("I") is this process's own namespace and outlives every
        # laboratory made in it: what a scenario put there must not be
        # there for the next one (a cut direct path, an isolation).
        for table in ("cut", "isolate"):
            sh("nft", "delete", "table", "inet", table, check=False)
        # So are the ends of links made here, which would otherwise go only
        # when the kernel gets round to destroying the namespaces their
        # peers were moved to — possibly after the next laboratory has tried
        # to make links of the same names ("File exists": `samenat` met it).
        # Deleting an end deletes the pair, at once.
        for ifn in self.core_links:
            sh("ip", "link", "del", ifn, check=False)
        self.core_links = []
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
            assert not (public and cgn), "a public network behind a carrier's NAT is not public"
            # "route": a router that translates nothing, in front of a
            # carrier's NAT that translates for it — DS-Lite's picture (RFC
            # 6333: the home router tunnels, the carrier's AFTR translates),
            # without the tunnel.
            routed = kind == "route"
            assert cgn or not routed, "a router that translates nothing needs a carrier's NAT"
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
                inside = f"{lan_net}.2" if routed else "100.64.0.1"
                lab.nft(cg, nat_rules(cgn, inside, lan="cl", wan="cw").replace("$WANIP", f"{wan_net}.1"))
                if routed:
                    lab.x(cg, "ip", "route", "add", f"{lan_net}.0/24", "via", "100.64.0.1")
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
            rules = "" if routed else nat_rules(kind, f"{lan_net}.2")
            if rules:
                # The router's own address: behind a carrier's NAT, one of
                # the carrier's.
                lab.nft(gw, rules.replace("$WANIP", "100.64.0.1" if cgn else f"{wan_net}.1"))
        lab.link("S", "s0", "I", "iS")
        lab.addr("S", "s0", f"{S1}/24", "11.9.0.254")
        lab.x("S", "ip", "addr", "add", f"{S2}/24", "dev", "s0")
        lab.addr("I", "iS", "11.9.0.254/24")
        lab.x("I", "sysctl", "-qw", "net.ipv4.ip_forward=1")
        if v6:
            self.wire_v6(v6, sides)
            lab.settle(["I", *lab.pid])
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
            # Behind NAT66 (`nat66`): a unique local prefix inside, which
            # nobody outside has a route to, and the router's own global
            # address on everything that leaves.
            if fw == "nat66":
                lan = f"fd00:aa00:{n}:1"
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
            if fw != "nat66":
                lab.x("I", "ip", "-6", "route", "add", f"{lan}::/64", "via", f"{wan}::1")
            lab.x(gw, "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1")
            lab.nft(gw, v6_input())
            rules = fw6_rules("stateful6" if fw == "nat66" else fw)
            if rules:
                lab.nft(gw, rules)
            if fw == "nat66":
                lab.nft(gw, """table ip6 nat66 {
  chain post {
    type nat hook postrouting priority srcnat;
    oifname "wan" masquerade
  }
}
""")
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


def conntrack(lab, ns):
    """The connection-tracking table of namespace `ns`, as text: the kernel's
    /proc/net/nf_conntrack where it has one (newer configurations leave it
    out), else what `conntrack -L` reads through netlink."""
    r = lab.x(ns, "cat", "/proc/net/nf_conntrack", check=False)
    if r.returncode == 0 and r.stdout.strip():
        return r.stdout
    return lab.x(ns, "conntrack", "-L", "-p", "udp", check=False).stdout


def plain(addr):
    """`addr` (ip:port, as a program prints it) with an IPv4 address that a
    dual-stack socket shows in its mapped form, [::ffff:a.b.c.d]:port,
    written the plain way: which of the two a program prints depends on the
    kernel it runs on, and what happened does not."""
    ip, port = addr.rsplit(":", 1)
    ip = ip.strip("[]")
    if ip.lower().startswith("::ffff:") and "." in ip:
        ip = ip[len("::ffff:"):]
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def make_payload(d):
    """The file every transfer sends: NATLAB_SIZE_MB megabytes (default one) of
    random data. Returns its path and SHA-256."""
    data = os.path.join(d, "payload.bin")
    with open(data, "wb") as f:
        for _ in range(int(os.environ.get("NATLAB_SIZE_MB", "1"))):
            f.write(os.urandom(1 << 20))
    return data, hashlib.sha256(open(data, "rb").read()).hexdigest()


def rate_args():
    """How long a transfer lasts is its size over its rate (NATLAB_MAX_RATE,
    as sharp-sender's --max-rate takes it), not how fast the machine is:
    a session that began through a server moves to a direct path in seconds,
    and a transfer that is over sooner has nothing to show of it."""
    return ["--max-rate", os.environ["NATLAB_MAX_RATE"]] if os.environ.get("NATLAB_MAX_RATE") else []


def long_transfers():
    """Whether the transfers last long enough for a move off a server: ten
    seconds at least, at the rate they are held to (a move takes a few)."""
    rate = os.environ.get("NATLAB_MAX_RATE", "").strip()
    if not rate:
        return False
    mult = {"k": 1e3, "m": 1e6, "g": 1e9}.get(rate[-1].lower())
    bits_per_second = float(rate[:-1] if mult else rate) * (mult or 1.0)
    size = int(os.environ.get("NATLAB_SIZE_MB", "1")) * (1 << 20) * 8
    return size / bits_per_second >= 10


def session_path(log, topo, turn=False):
    """The path a sender's session ended on, from its log: a session carried by
    a relay or a TURN server moves to a direct path once one opens, so it is
    the last address proven, and where it began is said next to it."""
    conn = re.search(r"Connected to (\S+)", log)
    proven = re.findall(r"receiver address (\S+) proven", log)

    def kind(addr):
        return stream_kind(addr, log) or classify(addr, topo, 5560, turn=turn)

    path = kind(proven[-1]) if proven else (kind(conn.group(1)) if conn else "none")
    if proven and conn:
        started = kind(conn.group(1))
        if started != path:
            path += f" (from {started})"
    return path


def stream_kind(addr, log):
    """What a loopback address a sender's session runs on stands for: the
    shim of a TCP stream (see `transport::carrier`), to a relay or straight
    to the receiver, as the sender's log says when the stream comes up.
    None for any other address."""
    a = plain(addr)
    if not a.startswith("127.0.0.1:"):
        return None
    if re.search(r"will carry the transfer on its port \d+, over \w+; carried from " + re.escape(a) + r"\b", log):
        return "relay-tcp"
    if re.search(r"the receiver answers over TCP at \S+; carried from " + re.escape(a) + r"\b", log):
        return "direct-tcp"
    return None


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


def relay_may_only_introduce(lab, v6):
    """The relay may introduce two hosts and tell each what the other looks
    like from outside — but it cannot carry anything: only what a direct path
    could do is left."""
    lab.nft("S", """table ip filter {
  chain in {
    type filter hook input priority filter;
    udp dport { 5560, 3478, 3479 } accept
    ip protocol udp drop
  }
}
""")
    if v6:
        lab.nft("S", """table ip6 filter6 {
  chain in {
    type filter hook input priority filter;
    ct state established,related accept
    udp dport { 5560, 3478, 3479 } accept
    icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } accept
    meta l4proto udp drop
  }
}
""")


def transfer(a_nat, b_nat, a_cgn=None, b_cgn=None, carry=True, timeout=45, keep=False, verbose=False,
             via="relay", human_delay=2.0, v6=None, v4=True, isolate=False, during=None, prepare=None):
    """One real transfer, sender behind `a_nat`, receiver behind `b_nat`.

    `via` is how the two find each other: "relay" (a relay introduces them),
    "card" (no relay: the receiver's card is given to the sender, and —
    `human_delay` seconds later, the time a person takes to paste it — the
    sender's card is given to the receiver; only a STUN server is shared),
    "addr" (the same with no cards: the sender is given the receiver's ID and
    the addresses the receiver printed, and the receiver, later, the addresses
    the sender printed — what two people read off their screens),
    "turn" (cards, and both are also given a TURN server to be
    reached through: coturn on the server host), or "dht" (no cards: both
    announce in a DHT — two nodes per family on the server host, written
    independently of the client — and the sender is given the receiver's ID
    alone).
    `during(lab, topo)`, if given, is called every fifth of a second while
    the transfer runs: what a scenario does to the network in the middle of
    one.
    Returns (ok, path, seconds, detail)."""
    lab = Lab(keep=keep)
    try:
        topo = Topo(lab, a_nat, b_nat, a_cgn, b_cgn, v6=v6, v4=v4, isolate=isolate)
        if prepare:
            prepare(lab, topo)
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
            relay_may_only_introduce(lab, v6)
        relay_stun = ["--stun", S1, "--stun", S2] + (["--stun", S61, "--stun", S62] if v6 else [])
        relay = lab.spawn(
            "S",
            [f"{BIN}/sharp-relay", "--bind", "[::]:5560" if v6 else "0.0.0.0:5560", *relay_stun,
             "--identity", f"{d}/relay.key", "--log", "info"],
            "relay.log",
        )
        m = wait_for(lab, "relay.log", r"Receivers: --relay (sh4?-\S+?)@", 10)
        if not m:
            return False, "none", 0, "the relay did not start:\n" + lab.log("relay.log")
        rid = m.group(1)
        if via in ("card", "turn", "addr"):
            return transfer_by_cards(lab, topo, d, human_delay, timeout, verbose,
                                     turn=(via == "turn"), plain=(via == "addr"), during=during)
        if via == "dht":
            return transfer_by_dht(lab, topo, d, timeout, verbose)
        data, want = make_payload(d)
        os.makedirs(f"{d}/out", exist_ok=True)
        recv_args = [
            f"{BIN}/sharp-receiver", "--headless", "--output", f"{d}/out", "--state-dir", f"{d}/rst",
            "--identity", f"{d}/r.key", "--bind", "[::]:5555" if v6 else "0.0.0.0:5555", *stun_args(topo),
            "--relay", f"{rid}@{srv}:5560", "--log-level", os.environ.get("NATLAB_LOG", "info"),
        ]
        lab.spawn("B", recv_args, "receiver.log")
        m = wait_for(lab, "receiver.log", r"Senders use: (sh4?-\S+)", 15)
        if not m:
            return False, "none", 0, "the receiver did not start:\n" + lab.log("receiver.log")
        # Its address once the NAT tests are done: the same line again, now
        # with addresses in place of "<this host>".
        m = wait_for(lab, "receiver.log", r"Senders use: (sh4?-\S+@[\[\d]\S*)", 30)
        if m:
            address = m.group(1)
        else:
            # Nothing was published (a NAT that gives no address worth
            # publishing): a sender has only the relay to go by.
            address = f"{re.search(r'Senders use: (sh4?-[a-z0-9]+)', lab.log('receiver.log')).group(1)}@{srv}:9"
        start = time.time()
        send_args = [
            f"{BIN}/sharp-sender", data, address, "--relay", f"{srv}:5560", "--headless",
            *stun_args(topo), *rate_args(),
            "--identity", f"{d}/s.key", "--state-dir", f"{d}/sst", "--log-level", os.environ.get("NATLAB_LOG", "info"),
        ]
        sender = lab.spawn("A", send_args, "sender.log")
        end = time.time() + timeout
        while sender.poll() is None and time.time() < end:
            if during:
                during(lab, topo)
            time.sleep(0.2)
        if sender.poll() is None:
            sender.kill()
        took = time.time() - start
        log = lab.log("sender.log")
        path = session_path(log, topo)
        got = None
        for name in os.listdir(f"{d}/out"):
            if not name.endswith(".sharp-part"):
                got = hashlib.sha256(open(f"{d}/out/{name}", "rb").read()).hexdigest()
        ok = got == want
        detail = f"receiver published {address}"
        if verbose or not ok:
            for gw in ("RA", "RB"):
                ct = conntrack(lab, gw)
                detail += f"\n--- conntrack in {gw}\n" + "\n".join(
                    l[:170] for l in ct.splitlines() if "udp" in l
                )
            detail += (
                "\n--- sender.log\n" + log[-3500:]
                + "\n--- receiver.log\n" + lab.log("receiver.log")[-3500:]
                + "\n--- relay.log\n" + lab.log("relay.log")[-2000:]
            )
        return ok, path, took, detail
    finally:
        lab.close()


def last_card(lab, log, pattern):
    """The most recent card a process printed."""
    found = re.findall(pattern, lab.log(log))
    return found[-1] if found else None


def transfer_by_cards(lab, topo, d, human_delay, timeout, verbose, turn=False, plain=False, during=None):
    """The part of `transfer` that needs no relay: two people, two cards.
    With `turn`, both hosts also hold an allocation on a TURN server, whose
    address is on their cards. With `plain`, no cards: two addresses each way,
    as printed."""
    turn_args = []
    if turn:
        start_coturn(lab, v4=topo.v4, v6=bool(topo.v6))
        turn_args = ["--turn", f"{TURN_USER}:{TURN_PASSWORD}@{server_arg(topo)}:{TURN_PORT}"]
    data = os.path.join(d, "payload.bin")
    data, want = make_payload(d)
    os.makedirs(f"{d}/out", exist_ok=True)
    recv = lab.spawn(
        "B",
        [f"{BIN}/sharp-receiver", "--headless", "--output", f"{d}/out", "--state-dir", f"{d}/rst",
         "--identity", f"{d}/r.key", "--bind", "[::]:5555" if topo.v6 else "0.0.0.0:5555",
         *stun_args(topo), *turn_args, "--log-level", os.environ.get("NATLAB_LOG", "info")],
        "receiver.log",
        stdin=subprocess.PIPE,
    )
    if plain:
        # What the receiver prints for a sender: its ID and its addresses,
        # once its tests are done (the line before that has none yet).
        m = wait_for(lab, "receiver.log", r"Senders use: (sh4?-\S+@[\[\d]\S*)", 30)
        if not m:
            return False, "none", 0, "the receiver printed no address:\n" + lab.log("receiver.log")
        rcard = m.group(1)
    else:
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
         # With only an address to go by the sender says nothing of itself
         # unless asked: this is how a person is told what to type.
         *(["--card"] if plain else []), *rate_args(),
         "--identity", f"{d}/s.key", "--state-dir", f"{d}/sst", "--log-level", os.environ.get("NATLAB_LOG", "info")],
        "sender.log",
    )
    if turn:
        wait_for(lab, "sender.log", r"relaying at", 20)
        time.sleep(0.5)
    # The sender may be done before it has a card to give: a receiver that
    # can be reached as it stands needs nothing from the sender.
    given = r"Addresses:\s+(\S.*)" if plain else r"Your card: (shc1-\S+)"
    m = None
    end = time.time() + 30
    while time.time() < end and sender.poll() is None:
        m = re.search(given, lab.log("sender.log"))
        if m:
            break
        time.sleep(0.2)
    if m and sender.poll() is None:
        # A person carries it across (the last one printed: with a TURN
        # server it is the one that names its address).
        time.sleep(human_delay)
        scard = last_card(lab, "sender.log", given) or m.group(1)
        # One address to a line, as they are pasted.
        for line in (scard.split() if plain else [scard]):
            recv.stdin.write((line + "\n").encode())
        recv.stdin.flush()
    elif sender.poll() is None:
        sender.kill()
        return False, "none", 0, "the sender printed no " + ("address" if plain else "card") + ":\n" + lab.log("sender.log")
    samples = []
    end = time.time() + timeout
    sampled = 0.0
    while sender.poll() is None and time.time() < end:
        if os.environ.get("NATLAB_SAMPLE") and time.time() - sampled >= 2:
            sampled = time.time()
            ct = conntrack(lab, "RA")
            n = sum(1 for l in ct.splitlines() if "dst=11.2.0.1" in l.split("src=")[1] if "udp" in l)
            samples.append(f"{time.time() - start:.0f}s:{n}")
        if during:
            during(lab, topo)
        time.sleep(0.2)
    if sender.poll() is None:
        sender.kill()
    took = time.time() - start
    log = lab.log("sender.log")
    path = session_path(log, topo, turn=turn)
    got = None
    for name in os.listdir(f"{d}/out"):
        if not name.endswith(".sharp-part"):
            got = hashlib.sha256(open(f"{d}/out/{name}", "rb").read()).hexdigest()
    ok = got == want
    detail = (f"{'addresses' if plain else 'cards'} exchanged by hand after {human_delay:.0f}s"
              + (f"\nflows at the sender's NAT towards the receiver: {' '.join(samples)}" if samples else ""))
    if verbose or not ok:
        for gw in ("RA", "RB"):
            ct = conntrack(lab, gw)
            detail += f"\n--- conntrack in {gw}\n" + "\n".join(l[:170] for l in ct.splitlines() if "udp" in l)
        detail += "\n--- sender.log\n" + log[-2500:] + "\n--- receiver.log\n" + lab.log("receiver.log")[-2500:]
    return ok, path, took, detail


def transfer_by_dht(lab, topo, d, timeout, verbose):
    """Two hosts that know nothing of each other but the receiver's ID: both
    announce in a DHT and look for the other there."""
    # A DHT is one network per address family (BEP 32) and a host with both
    # takes part in both: two nodes here on each family's two addresses, and
    # the hosts start from all of them. Two, because an address is punched
    # at in earnest only once two nodes at addresses of their own name it
    # (nat::dht::VOUCHERS): an announcement is stored on every node it goes
    # to, and one node alone could have made it up.
    binds = ([f"{S1}:6881", f"{S2}:6881"] if topo.v4 else []) + (
        [f"[{S61}]:6881", f"[{S62}]:6881"] if topo.v6 else [])
    dht = lab.spawn("S", ["python3", os.path.join(os.path.dirname(os.path.abspath(__file__)), "dht_node.py"),
                          *[a for b in binds for a in ("--bind", b)]], "dht.log")
    if not wait_for(lab, "dht.log", r"dht node", 10):
        return False, "none", 0, "the DHT node did not start:\n" + lab.log("dht.log")
    data, want = make_payload(d)
    os.makedirs(f"{d}/out", exist_ok=True)
    dht_args = ["--dht"] + [a for b in binds for a in ("--dht-bootstrap", b)]
    lab.spawn(
        "B",
        [f"{BIN}/sharp-receiver", "--headless", "--output", f"{d}/out", "--state-dir", f"{d}/rst",
         "--identity", f"{d}/r.key", "--bind", "[::]:5555" if topo.v6 else "0.0.0.0:5555",
         *stun_args(topo), *dht_args, "--log-level", os.environ.get("NATLAB_LOG", "info")],
        "receiver.log",
    )
    m = wait_for(lab, "receiver.log", r"Receiver ID: (sh4?-\S+)", 15)
    if not m:
        return False, "none", 0, "the receiver did not start:\n" + lab.log("receiver.log")
    rid = m.group(1)
    start = time.time()
    sender = lab.spawn(
        "A",
        [f"{BIN}/sharp-sender", data, rid, "--headless", *stun_args(topo), *dht_args, *rate_args(),
         "--identity", f"{d}/s.key", "--state-dir", f"{d}/sst", "--log-level", os.environ.get("NATLAB_LOG", "info")],
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


# What `sharp-probe` has to say of each kind of NAT, in its own words
# (`describe_family`, src/nat/probe.rs): how the NAT maps, whom it lets in,
# how it numbers the ports of new mappings. No NAT here sends back in what
# an inside host addresses to the outside address (whatever lets packets in
# is on the outside interface alone): the ones that keep one mapping for
# every destination have to report no hairpinning, and a symmetric one is
# not asked (its mapping for the test would be a new one, `behaviour.rs`)
# — none may claim that hairpinning works (`PROBE_NEVER`).
PROBE_SAYS = {
    "open": ["no NAT", "lets in packets from anyone"],
    "full_cone": ["one port for every destination", "lets in packets from anyone", "no hairpinning"],
    "restricted": ["one port for every destination", "lets in packets from hosts it was sent to", "no hairpinning"],
    "port_restricted": ["one port for every destination",
                        "lets in only packets from the exact address and port it was sent to", "no hairpinning"],
    "symmetric_seq": ["the port depends on destination host and port (symmetric)",
                      "lets in only packets from the exact address and port it was sent to",
                      "new ports count up"],
    "symmetric_random": ["the port depends on destination host and port (symmetric)",
                         "lets in only packets from the exact address and port it was sent to",
                         "new ports are random"],
}
# Nothing in these laboratories loops back, and nothing has a carrier's NAT
# in front of the router.
PROBE_NEVER = ["hairpinning works", "another NAT in front"]
# And of each IPv6 firewall: nothing translated, and whom it lets in.
PROBE_SAYS6 = {
    "open6": ["no address translation", "lets in packets from anyone"],
    "stateful6": ["no address translation", "lets in only packets from the exact address and port it was sent to"],
    "restricted6": ["no address translation", "lets in packets from hosts it was sent to"],
}


def probe_report_wrong(report, topo, host, kind, fw6, v4):
    """What is wrong in what `sharp-probe` on `host` reported of its own
    network, measured against the laboratory as it was built: the address
    the internet sees the host at, and what `PROBE_SAYS` (IPv4, behind
    `kind`) and `PROBE_SAYS6` (IPv6, behind the firewall `fw6`) say it must
    report. Nothing, if it is right."""
    checks = []
    if v4:
        checks.append(("IPv4", topo.inside_ip[host] if kind == "open" else topo.wan_ip[host], PROBE_SAYS[kind]))
    if fw6:
        checks.append(("IPv6", topo.v6_ip[host], PROBE_SAYS6[fw6]))
    wrong = []
    for family, ip, says in checks:
        m = re.search(rf"^{family}:\s+(.*)$", report, re.M)
        if not m:
            wrong.append(f"no {family} line")
            continue
        parts = [p.strip() for p in m.group(1).split("; ")]
        seen = re.match(r"your address as the internet sees it: (\S+)$", parts[0])
        seen_ip = plain(seen.group(1)).rsplit(":", 1)[0].strip("[]") if seen else None
        missing = [w for w in says if not any(p.startswith(w) for p in parts)]
        said = [n for n in PROBE_NEVER if any(p.startswith(n) for p in parts)]
        if seen_ip != ip or missing or said:
            wrong.append(f"{family}" + (f", not at {ip}" if seen_ip != ip else "")
                         + (f", no word of {missing}" if missing else "") + (f", said {said}" if said else "")
                         + f": \"{m.group(1)[:400]}\"")
    return wrong


def cmd_probe(args):
    """`sharp-probe` on both hosts of a pair: each prints what it sees and
    its card, the cards are swapped by hand (through standard input), and
    each says whether a packet from the other arrived. With `--all`, every
    pair of NAT kinds, one line each. With `--addr`, what is swapped is the
    `Addresses:` line instead of the card: nothing is known then of the
    other side's NAT, and the passes that try each kind in turn take longer
    (give `--wait` 45 s or so)."""
    by = "addr" if args.addr else "card"
    if args.v6:
        print(f"{'scenario':46} {'A firewall':12} {'B firewall':12} {'punch test':44} what each host said of its network")
        bad = total = wrong = 0
        for name, an, bn, has_v4 in V6_SCENARIOS:
            for fa in FW6_KINDS:
                for fb in FW6_KINDS:
                    ok, want_ok, said = probe_pair(an, bn, args.wait, quiet=True, v6=(fa, fb), v4=has_v4, by=by)
                    total += 1
                    bad += ok != want_ok
                    wrong += sum(1 for w in said.values() if w)
                    print(f"{name:46} {fa:12} {fb:12} {'a packet got through both ways' if ok else 'nothing got through':32} "
                          f"{'as expected' if ok == want_ok else 'UNEXPECTED':11} {reports_line(said)}", flush=True)
        print(f"\n{total - bad} of {total} as they must be")
        print(f"{2 * total - wrong} of {2 * total} reports of a host's own network true to the laboratory")
        return 1 if bad or wrong else 0
    if not args.all:
        if not (args.a and args.b):
            raise SystemExit("name two NAT kinds, or --all")
        ok, want_ok, said = probe_pair(args.a, args.b, args.wait, by=by)
        print(f"what each host said of its network: {reports_line(said)}")
        return 0 if ok == want_ok and not any(said.values()) else 1
    print(f"{'host A behind':18} {'host B behind':18} {'punch test':44} what each host said of its network")
    bad = wrong = 0
    for a in NAT_KINDS:
        for b in NAT_KINDS:
            ok, want_ok, said = probe_pair(a, b, args.wait, quiet=True, by=by)
            bad += ok != want_ok
            wrong += sum(1 for w in said.values() if w)
            print(f"{a:18} {b:18} {'a packet got through both ways' if ok else 'nothing got through':32} "
                  f"{'as expected' if ok == want_ok else 'UNEXPECTED':11} {reports_line(said)}", flush=True)
    print(f"\n{len(NAT_KINDS) ** 2 - bad} of {len(NAT_KINDS) ** 2} as the theory says they must")
    print(f"{2 * len(NAT_KINDS) ** 2 - wrong} of {2 * len(NAT_KINDS) ** 2} reports of a host's own network true to the laboratory")
    return 1 if bad or wrong else 0


def reports_line(said):
    """`probe_pair`'s verdict on what the two hosts reported, in a line."""
    if not any(said.values()):
        return "both true"
    return "; ".join(f"host {h} WRONG: {' / '.join(w)}" for h, w in said.items() if w)


def probe_pair(a_nat, b_nat, wait, quiet=False, v6=None, v4=True, by="card"):
    """One pair; (did a packet get through both ways, did it have to, what
    was wrong in each host's report of its own network — see
    `probe_report_wrong`). With `v6`, a pair of IPv6 firewall kinds: every
    such pair has to get through. `by` is what the two swap: "card", or
    "addr" — the `Addresses:` line."""
    args = argparse.Namespace(a=a_nat, b=b_nat, wait=wait)
    lab = Lab(keep=False)
    try:
        topo = Topo(lab, args.a, args.b, None, None, v6=v6, v4=v4)
        d = lab.dir
        relay_stun = ["--stun", S1, "--stun", S2] + (["--stun", S61, "--stun", S62] if v6 else [])
        lab.spawn(
            "S",
            [f"{BIN}/sharp-relay", "--bind", "[::]:5560" if v6 else "0.0.0.0:5560", *relay_stun,
             "--identity", f"{d}/relay.key", "--log", "info"],
            "relay.log",
        )
        if not wait_for(lab, "relay.log", r"Receivers: --relay", 10):
            print("the relay (and its STUN server) did not start")
            return False, True, {"A": ["not run"], "B": ["not run"]}
        procs, cards, said = {}, {}, {}
        for ns, name, extra in (("A", "a", []), ("B", "b", ["--receiver"])):
            procs[name] = lab.spawn(
                ns,
                [f"{BIN}/sharp-probe", *stun_args(topo), "--no-port-mapping", "--stdin",
                 "--identity", f"{d}/{name}.key", "--wait", str(args.wait), "--log-level", os.environ.get("NATLAB_LOG", "info"), *extra],
                f"probe_{name}.log",
                stdin=subprocess.PIPE,
            )
        given = r"^(shc1-\S+)$" if by == "card" else r"^Addresses:\s+(\S.*)$"
        for name in ("a", "b"):
            m = None
            end = time.time() + 40
            while time.time() < end and not m:
                m = re.search(given, lab.log(f"probe_{name}.log"), re.M)
                time.sleep(0.2)
            if not m:
                print(f"host {name.upper()} printed no {'card' if by == 'card' else 'addresses'}:\n"
                      + lab.log(f"probe_{name}.log")[-1500:])
                return False, True, {"A": ["not run"], "B": ["not run"]}
            cards[name] = m.group(1).strip()
            report = lab.log(f"probe_{name}.log").split("Your card")[0]
            host = name.upper()
            said[host] = probe_report_wrong(report, topo, host, args.a if name == "a" else args.b,
                                            (v6[0] if name == "a" else v6[1]) if v6 else None, v4)
            if not quiet:
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
        want_ok = True if v6 else expected(args.a, args.b, False, by)[0]
        ok = all(c == 0 for c in codes)
        if not quiet:
            for name in ("a", "b"):
                tail = lab.log(f"probe_{name}.log").split("Sending at")[-1]
                print(f"--- punch test, host {name.upper()}\nSending at{tail[-700:]}")
            print(f"punch test: {'a packet got through both ways' if ok else 'nothing got through'} "
                  f"({'as expected' if ok == want_ok else 'UNEXPECTED'})")
        return ok, want_ok, said
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
    if via in ("dht", "addr"):
        # An address (from a DHT, or typed in) says where the other end is
        # and nothing of what its NAT
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
    if (carry and via == "relay") or via == "turn":
        # Whoever answers first carries a short transfer, and a server's
        # answer may beat a direct path that needs a meeting of many sockets
        # (about half a second): only one that lasts is expected to have
        # moved off it.
        return True, "direct" if long_transfers() else "either"
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
            ok, path, took, detail = transfer(a, b, carry=carry, timeout=args.timeout, via=args.via, isolate=args.isolate,
                                              verbose=args.verbose)
            want_ok, want_path = expected(a, b, carry, args.via, args.isolate)
            met = ok == want_ok and (
                not ok
                or want_path == "either"
                or is_carried(path.split(" ")[0]) == is_carried(want_path) and (is_carried(want_path) or is_direct(path))
            )
            rows.append((a, b, ok, path, took, met))
            result = f"{'ok  ' if ok else 'FAIL'} {path:16} {took:5.1f}s"
            print(f"{a:18} {b:18} {result:30} {'as expected' if met else 'UNEXPECTED (wanted ' + want_path + ')'}", flush=True)
            if not met and args.verbose:
                print(detail, flush=True)
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


# The two networks the IPv6 scenarios run on: no IPv4 at all, and IPv4 that
# cannot help (both NATs draw ports at random), so that IPv6 has to.
V6_SCENARIOS = [
    ("IPv6 only", "open", "open", False),
    ("dual stack, both IPv4 NATs symmetric-random", "symmetric_random", "symmetric_random", True),
]


def cmd_v6(args):
    """IPv6, and the two families together. Two networks, each with a
    firewall in front of it (`FW6_KINDS`); without IPv4 at all, and — the
    interesting one — with IPv4 NATs that could only meet through a relay,
    where the IPv6 path has to make the relay unnecessary."""
    rows = []
    kinds = list(FW6_KINDS)
    scenarios = list(V6_SCENARIOS)
    if args.scenario:
        scenarios = [sc for sc in scenarios if args.scenario in sc[0]]
    print(f"{'scenario':46} {'A firewall':12} {'B firewall':12} result")
    for name, an, bn, has_v4 in scenarios:
        for fa in kinds:
            for fb in kinds:
                if args.cell and args.cell != f"{fa},{fb}":
                    continue
                for _ in range(args.repeat):
                    ok, path, took, detail = transfer(
                        an, bn, carry=not args.direct_only, timeout=args.timeout, via=args.via,
                        v6=(fa, fb), v4=has_v4, isolate=args.isolate, verbose=args.verbose,
                    )
                    # Both ends have a global IPv6 address and, at worst, a
                    # stateful firewall: a direct path has to open in all nine
                    # combinations, and it has to be the IPv6 one (possibly
                    # after starting through a TURN server). With the two
                    # networks cut off from each other only a server that
                    # carries gets anything across.
                    if args.isolate:
                        met = ok and path.split(" ")[0] in ("relay", "turn")
                    else:
                        met = ok and path.startswith("direct-v6")
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


# A network behind NAT66 (RFC 6296's stateful cousin, which RFC 5902 counts
# against): its hosts have unique local addresses, and what leaves has the
# router's. (scenario, sender's IPv4 NAT, receiver's, IPv4 at all, the two
# IPv6 networks, what the session has to end on)
NAT66_CASES = [
    ("IPv6 only, the receiver behind NAT66", "open", "open", False, ("stateful6", "nat66"), "direct-v6"),
    ("IPv6 only, both behind NAT66", "open", "open", False, ("nat66", "nat66"), "direct-v6"),
    ("dual stack, the receiver behind NAT66 and a port-restricted NAT", "port_restricted", "port_restricted",
     True, ("stateful6", "nat66"), "direct"),
]


def cmd_nat66(args):
    """NAT on IPv6 (THREAT_MODEL Р16): an address of the host's own that
    leads nowhere from outside, the router's in what leaves. Nothing
    measures it — the NAT tests over IPv6 run only where a host has a global
    address — but a relay sees where a registration comes from, introduces
    each end to the other at that address, and the two punch at it as they
    would through an IPv4 NAT."""
    ok_all = True
    print(f"{'case':66} result")
    for name, an, bn, has_v4, v6, want in NAT66_CASES:
        ok, path, took, detail = transfer(an, bn, timeout=args.timeout, v6=v6, v4=has_v4, verbose=args.verbose)
        good = ok and path.startswith(want)
        ok_all &= good
        print(f"{name:66} {'ok  ' if good else 'FAIL'} {path} in {took:.1f}s", flush=True)
        if args.verbose or not good:
            print(detail, flush=True)
    return 0 if ok_all else 1


def dslite(lab, topo):
    """The receiver's carrier link as DS-Lite (RFC 6333) looks to the two
    ends: the home router translates nothing, the carrier's AFTR does
    (`Topo`'s "route" kind behind a carrier NAT), and the IPv4-in-IPv6
    tunnel between them takes 40 bytes of every packet — a path MTU of
    1460 for IPv4. The tunnel itself is not built: where the kernel's
    ip6_tunnel module is loaded, `ip -6 tunnel add ... mode ipip6` would
    carry it, but a user namespace cannot load a module, and what the two
    ends see of it is its MTU."""
    for ns, ifn in (("RB", "wan"), ("CB", "cl")):
        lab.x(ns, "ip", "link", "set", "dev", ifn, "mtu", "1460")


def cmd_dslite(args):
    """The receiver behind DS-Lite: its IPv4 in a tunnel to the carrier's
    NAT. Expected: the transfer as through any carrier NAT of that kind,
    and the sender's chunk the size that fits the tunnel (1387), not the
    one below it (1187)."""
    ok_all = True
    print(f"{'sender behind':18} {'receiver: DS-Lite to':22} result")
    for a, cgn, want in (("port_restricted", "port_restricted", "direct"), ("symmetric_random", "port_restricted", "direct")):
        ok, path, took, detail = transfer(a, "route", b_cgn=cgn, timeout=args.timeout, verbose=True, prepare=dslite)
        m = re.search(r"chunk (\d+) B\)", detail)
        chunk = int(m.group(1)) if m else None
        good = ok and path.startswith(want) and chunk == 1387
        ok_all &= good
        print(f"{a:18} {cgn:22} {'ok  ' if good else 'FAIL'} {path} in {took:.1f}s, chunk {chunk}", flush=True)
        if args.verbose or not good:
            print(detail, flush=True)
    return 0 if ok_all else 1


def cmd_lan(args):
    """Two hosts on one network, no address given: the receiver announces
    itself with multicast DNS, the sender asks for it by ID. And the other
    way about: a receiver that does not announce is not found, and a
    sender that does not ask finds nothing — nobody is discoverable by
    default. With `--v6` the network has IPv6 only: the question goes to
    ff02::fb and the answer names an IPv6 address."""
    v6 = getattr(args, "v6", False)
    receiver_at = "[2a0e:aa00:9::2]:" if v6 else "10.9.0.2:"
    lab = Lab()
    try:
        lab.mk("A")
        lab.mk("B")
        # Both ends are made in this namespace first, so they cannot share a
        # name until each has moved to its own.
        lab.link("A", "lanA", "B", "lanB")
        for ns, old in (("A", "lanA"), ("B", "lanB")):
            lab.x(ns, "ip", "link", "set", old, "name", "eth0")
        if v6:
            lab.addr6("A", "eth0", "2a0e:aa00:9::1/64")
            lab.addr6("B", "eth0", "2a0e:aa00:9::2/64")
        else:
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
                 "--identity", f"{d}/r-{name}.key", "--bind", "[::]:5555" if v6 else "0.0.0.0:5555", "--no-nat"]
                + (["--announce-lan"] if announce else [])
                + ["--log-level", os.environ.get("NATLAB_LOG", "info")],
                f"receiver-{name}.log",
            )
            m = wait_for(lab, f"receiver-{name}.log", r"Receiver ID: (sh4?-\S+)", 15)
            if not m or (announce and not wait_for(lab, f"receiver-{name}.log", r"announced on the local network", 10)):
                print(f"{name}: the receiver did not start:\n" + lab.log(f"receiver-{name}.log")[-1500:])
                results.append(False)
                return
            start = time.time()
            sender = lab.spawn(
                "A",
                [f"{BIN}/sharp-sender", data, m.group(1), "--headless", "--no-nat"]
                + (["--lan"] if ask else [])
                + ["--identity", f"{d}/s-{name}.key", "--state-dir", f"{d}/sst-{name}", "--log-level", os.environ.get("NATLAB_LOG", "info")],
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
            transferred = got == want and conn is not None and plain(conn.group(1)).startswith(receiver_at)
            ok = transferred == expect_ok
            results.append(ok)
            what = f"via {plain(conn.group(1))}" if conn else "found nobody"
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


def start_miniupnpd(lab, gw, ext_if, lan_ip, protocols, ext_ip, prefix=24):
    """miniupnpd — an independent implementation of UPnP-IGD, NAT-PMP and
    PCP — as the router's daemon, with the nftables backend and only the
    protocols in `protocols` switched on ("upnp-v1": UPnP, describing itself
    as an IGDv1 router, which has no AddAnyPortMapping). It answers at
    `lan_ip`, and hosts whose addresses share its first `prefix` bits (its
    "LAN") alone."""
    lab.nft(gw, MINIUPNPD_TABLE)
    conf = f"""ext_ifname={ext_if}
listening_ip={lan_ip}/{prefix}
ipv6_disable=yes
enable_pcp_pmp={'yes' if ('pcp' in protocols or 'natpmp' in protocols) else 'no'}
enable_upnp={'yes' if ('upnp' in protocols or 'upnp-v1' in protocols) else 'no'}
{'force_igd_desc_v1=yes' if 'upnp-v1' in protocols else ''}
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


PCP_ANYCAST = "192.0.0.9"
PCP_ANYCAST_V6 = "2001:1::1"
# What miniupnpd logs when a request of each kind has asked it for a
# forward to the receiver (10.2.0.2, port 5555).
DAEMON_GRANTED = {
    "pcp": r"PCP MAP: added mapping UDP \d+->10\.2\.0\.2:5555",
    "natpmp": r"NAT-PMP port mapping request : \d+->10\.2\.0\.2:5555 udp",
    "upnp": r"Add(?:Any)?PortMapping: ext port \d+ to 10\.2\.0\.2:5555 protocol UDP",
    "upnp-v1": r"AddPortMapping: ext port \d+ to 10\.2\.0\.2:5555 protocol UDP",
}
# With the port taken (`--taken`), what it logs of the way round: the port
# it found in use, and for UPnP which action of which version of the
# service asked for another.
TAKEN_SAID = {
    "pcp": [r"PCP MAP: added mapping UDP (?!5555\b)\d+->10\.2\.0\.2:5555"],
    "natpmp": [r"port 5555 protocol udp already in use"],
    "upnp": [r"port 5555 UDP \(rhost ''\) already redirected to 10\.2\.0\.99:5555",
             r"WANIPConnection:2#AddAnyPortMapping"],
    "upnp-v1": [r"port 5555 UDP \(rhost ''\) already redirected to 10\.2\.0\.99:5555",
                r"WANIPConnection:1#AddPortMapping"],
}
# And what settles it, whatever was said: the router's own rule, the
# forwarded port translated to the receiver.
ROUTER_RULE = r"th dport {port} dnat ip to 10\.2\.0\.2:5555"
TAKEN_PORT = 5555
# Takes the router's port 5555 for somebody else, in the protocol of the
# row, before the receiver asks for it (`portmap --taken`). PCP and NAT-PMP
# map only for the host that asks, so it is the receiver's own host at
# another inside port (6000); UPnP would take that for an update of one
# mapping, so there it is another host of the network (10.2.0.99). Run in
# the receiver's namespace: proto, router, the daemon's log.
TAKE_PORT = r"""
import os, re, socket, struct, sys, time, urllib.request
proto, router, log = sys.argv[1:4]
if proto in ("pcp", "natpmp"):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("10.2.0.2", 0))
    s.settimeout(1.0)
    if proto == "pcp":
        # MAP, RFC 6887 section 11.1: UDP, inside port 6000, 5555 suggested.
        me = bytes(10) + b"\xff\xff" + socket.inet_aton("10.2.0.2")
        req = (struct.pack("!BBHI", 2, 1, 0, 3600) + me + os.urandom(12)
               + struct.pack("!B3xHH", 17, 6000, 5555) + bytes(10) + b"\xff\xff" + bytes(4))
    else:
        # RFC 6886 section 3.3: UDP, inside port 6000, 5555 suggested.
        req = struct.pack("!BBHHHI", 0, 1, 0, 6000, 5555, 3600)
    for _ in range(4):
        s.sendto(req, (router, 5351))
        try:
            data = s.recv(1100)
            break
        except socket.timeout:
            pass
    else:
        sys.exit(f"{proto}: no answer")
    if proto == "pcp":
        result, port = data[3], struct.unpack("!H", data[42:44])[0]
    else:
        result, port = struct.unpack("!H", data[2:4])[0], struct.unpack("!H", data[10:12])[0]
    print(f"{proto}: 5555 -> 10.2.0.2:6000, result {result}, port {port}")
    sys.exit(0 if result == 0 and port == 5555 else 1)
http = None
for _ in range(50):
    m = re.search(r"HTTP listening on port (\d+)", open(log).read())
    if m:
        http = m.group(1)
        break
    time.sleep(0.1)
if not http:
    sys.exit("upnp: the daemon says of no HTTP port")
base = f"http://{router}:{http}"
fetch = urllib.request.build_opener(urllib.request.ProxyHandler({})).open
desc = fetch(base + "/rootDesc.xml", timeout=5).read().decode()
m = re.search(r"<serviceType>(urn:schemas-upnp-org:service:WANIPConnection:\d)</serviceType>.*?"
              r"<controlURL>([^<]+)</controlURL>", desc, re.S)
stype, ctl = m.groups()
body = ('<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
        f'<u:AddPortMapping xmlns:u="{stype}"><NewRemoteHost></NewRemoteHost>'
        '<NewExternalPort>5555</NewExternalPort><NewProtocol>UDP</NewProtocol>'
        '<NewInternalPort>5555</NewInternalPort><NewInternalClient>10.2.0.99</NewInternalClient>'
        '<NewEnabled>1</NewEnabled><NewPortMappingDescription>somebody else</NewPortMappingDescription>'
        '<NewLeaseDuration>3600</NewLeaseDuration></u:AddPortMapping></s:Body></s:Envelope>')
req = urllib.request.Request(base + ctl, data=body.encode(), headers={
    "Content-Type": 'text/xml; charset="utf-8"', "SOAPAction": f'"{stype}#AddPortMapping"'})
fetch(req, timeout=5).read()
print(f"upnp ({stype.rsplit(':', 1)[1] == '2' and 'IGDv2' or 'IGDv1'}): 5555 -> 10.2.0.99:5555")
"""


def cmd_portmap(args):
    """A receiver behind a router that runs miniupnpd asks it for a forward,
    publishes the address the router granted, and a sender behind *any* kind
    of NAT reaches it there — with no relay, no card and no punching from the
    receiver's side. That is what a port forward is worth: it turns the
    hardest receiver into a public one.

    With `--anycast` the receiver's router translates nothing and answers
    nothing; the NAT is the carrier's, in front of it, and its PCP server
    is reached at the PCP anycast address (RFC 7723) alone — miniupnpd
    listens there and nowhere else, so a forward granted can only have come
    from there.

    With `--taken` the router's port 5555 is already forwarded to somebody
    else when the receiver asks for it (`TAKE_PORT`): what the receiver is
    granted, and publishes, is a port the router picked — a PCP or NAT-PMP
    server's own choice, AddAnyPortMapping on an IGDv2 router, and on an
    IGDv1 router ("upnp-v1") one of the ports the receiver tries itself."""
    ok_all = True
    if args.taken and args.anycast:
        raise SystemExit("--taken is a router's port; --anycast has no router doing it")
    protos = args.protocols or (["pcp"] if args.anycast else
                                ["pcp", "natpmp", "upnp", "upnp-v1"] if args.taken else ["pcp", "natpmp", "upnp"])
    if args.anycast and protos != ["pcp"]:
        raise SystemExit("the anycast address is PCP's alone (RFC 7723)")
    kinds = args.senders or (["port_restricted", "symmetric_random"] if args.taken else list(NAT_KINDS))
    print(f"{'receiver asks by':18} {'receiver NAT':18} {'sender behind':18} result")
    for proto in protos:
        for b_nat in args.receivers:
            for a_nat in kinds:
                lab = Lab()
                try:
                    if args.anycast:
                        topo = Topo(lab, a_nat, "route", None, b_nat)
                    else:
                        topo = Topo(lab, a_nat, b_nat)
                    d = lab.dir
                    lab.spawn(
                        "S",
                        [f"{BIN}/sharp-relay", "--bind", "0.0.0.0:5560", "--stun", S1, "--stun", S2,
                         "--identity", f"{d}/relay.key", "--log", "info"],
                        "relay.log",
                    )
                    if args.anycast:
                        # On the carrier's side of its link to the home
                        # router, and its "LAN" is everyone behind it.
                        lab.x("CB", "ip", "addr", "add", f"{PCP_ANYCAST}/32", "dev", "cl")
                        start_miniupnpd(lab, "CB", "cw", PCP_ANYCAST, [proto], topo.wan_ip["B"], prefix=0)
                    else:
                        start_miniupnpd(lab, "RB", "wan", "10.2.0.1", [proto], topo.wan_ip["B"])
                    if proto == "natpmp":
                        # The daemon speaks PCP and NAT-PMP on one switch, and
                        # the receiver asks PCP first: without this the
                        # forward would be PCP's, and NAT-PMP proved nothing.
                        # (PCP is version 2, NAT-PMP 0, in the first byte.)
                        lab.nft("RB", """table inet nopcp {
  chain in {
    type filter hook input priority filter - 10;
    iifname "lan" udp dport 5351 @th,64,8 2 drop
  }
}
""")
                    time.sleep(1.0)
                    label = f"{proto} at {PCP_ANYCAST}" if args.anycast else proto
                    if args.taken:
                        took_first = lab.x("B", sys.executable, "-c", TAKE_PORT, proto.split("-")[0], "10.2.0.1",
                                           os.path.join(d, "miniupnpd.log"), check=False)
                        if took_first.returncode != 0:
                            print(f"{label:18} {b_nat:18} {a_nat:18} FAIL port {TAKEN_PORT} could not be taken first: "
                                  f"{(took_first.stdout + took_first.stderr).strip()[-300:]}\n"
                                  + "--- miniupnpd\n" + lab.log("miniupnpd.log")[-1000:])
                            ok_all = False
                            continue
                    data = os.path.join(d, "payload.bin")
                    with open(data, "wb") as f:
                        f.write(os.urandom(1 << 20))
                    want = hashlib.sha256(open(data, "rb").read()).hexdigest()
                    os.makedirs(f"{d}/out", exist_ok=True)
                    lab.spawn(
                        "B",
                        [f"{BIN}/sharp-receiver", "--headless", "--output", f"{d}/out", "--state-dir", f"{d}/rst",
                         "--identity", f"{d}/r.key", "--bind", "0.0.0.0:5555", "--stun", f"{S1}:3478",
                         "--log-level", os.environ.get("NATLAB_LOG", "info")],
                        "receiver.log",
                    )
                    m = wait_for(lab, "receiver.log", r"reachable from outside at (\S+) \(port forward\)", 25)
                    log = lab.log("receiver.log")
                    if not m:
                        print(f"{label:18} {b_nat:18} {a_nat:18} FAIL the receiver was granted no forward\n"
                              + "\n".join(l[:200] for l in log.splitlines()[-12:])
                              + "\n--- miniupnpd\n" + lab.log("miniupnpd.log")[-1500:])
                        ok_all = False
                        continue
                    forwarded = m.group(1)
                    rid = re.search(r"Receiver ID: (sh4?-\S+)", log).group(1)
                    start = time.time()
                    sender = lab.spawn(
                        "A",
                        [f"{BIN}/sharp-sender", data, f"{rid}@{forwarded}", "--headless", "--no-nat",
                         "--identity", f"{d}/s.key", "--state-dir", f"{d}/sst", "--log-level", os.environ.get("NATLAB_LOG", "info")],
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
                    # And the forward is the one asked for: the daemon's own
                    # log names the request, and the router's rules hold the
                    # forward — the port published, to the receiver.
                    daemon = lab.log("miniupnpd.log")
                    granted = re.search(DAEMON_GRANTED[proto], daemon)
                    port = int(forwarded.rsplit(":", 1)[1])
                    rules = lab.x("CB" if args.anycast else "RB", "nft", "list", "table", "inet", "miniupnpd",
                                  check=False).stdout
                    rule = re.search(ROUTER_RULE.format(port=port), rules)
                    said = [re.search(r, daemon) for r in TAKEN_SAID[proto]] if args.taken else []
                    ok = (got == want and conn is not None and plain(conn.group(1)) == plain(forwarded) and bool(granted)
                          and bool(rule) and all(said) and not (args.taken and port == TAKEN_PORT))
                    ok_all &= ok
                    print(f"{label:18} {b_nat:18} {a_nat:18} {'ok  ' if ok else 'FAIL'} via {forwarded} in {took:.1f}s; "
                          + (f"{TAKEN_PORT} taken first ({took_first.stdout.strip()}); " if args.taken else "")
                          + (f"the daemon: \"{granted.group(0)}\"" if granted
                             else f"the daemon's log shows no {proto} request that made the forward")
                          + "".join(f", \"{m.group(0)}\"" if m else f", nothing like /{r}/"
                                    for m, r in zip(said, TAKEN_SAID[proto] if args.taken else [])
                                    if not (m and granted and m.group(0) == granted.group(0)))
                          + (f"; the router: \"{rule.group(0)}\"" if rule else f"; the router has no rule for port {port}"),
                          flush=True)
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
    open a way in, and only the protocols in `protocols` are switched on.
    The daemon's default `secure_mode` stays on, as on any router that ships
    it: a host may open a pinhole for its own address, and only over IPv6 is
    the address its request comes from one the daemon can check."""
    lab.nft(gw, MINIUPNPD6_TABLE)
    # The LAN side is named by its interface: the daemon takes an address
    # only for IPv4, and "the network interface name is mandatory to enable
    # IPv6" (its own sample configuration).
    conf = f"""ext_ifname=wan
ext_ifname6=wan
listening_ip=lan
ipv6_disable=no
enable_pcp_pmp={'yes' if 'pcp' in protocols else 'no'}
enable_upnp={'yes' if 'upnp' in protocols else 'no'}
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
"""
    # (No permission rule for IPv6: the daemon's `allow` lines are IPv4 only,
    # and it takes a line naming `::/0` as an error in the whole file.)
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
    control: the firewall must stop the sender, or the test proves nothing.
    `pcp-anycast` is PCP with the daemon reachable at the PCP anycast
    address (RFC 7723) alone."""
    ok_all = True
    protos = args.protocols or ["pcp", "pcp-anycast", "upnp"]
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
                start_miniupnpd6(lab, "RB", ["pcp" if proto == "pcp-anycast" else proto], "10.2.0.1", "2a0e:aa00:2:1::1")
                if proto == "pcp-anycast":
                    # The PCP anycast address (RFC 7723), and PCP at any other
                    # address of the router's dropped: a pinhole opened can
                    # only have been asked for there.
                    lab.x("RB", "ip", "-6", "addr", "add", f"{PCP_ANYCAST_V6}/128", "dev", "lo")
                    lab.nft("RB", f"""table inet anycastonly {{
  chain in {{
    type filter hook input priority filter - 10;
    udp dport 5351 ip6 daddr != {PCP_ANYCAST_V6} drop
    udp dport 5351 ip6 daddr {PCP_ANYCAST_V6} counter
  }}
}}
""")
                if proto == "upnp":
                    # The daemon answers PCP over IPv6 whether or not it was
                    # told to (its own choice), and the receiver asks by every
                    # means at once: without this the pinhole that lets the
                    # sender in could be PCP's, and UPnP proved nothing.
                    lab.nft("RB", """table inet nopcp {
  chain in {
    type filter hook input priority filter - 10;
    iifname "lan" udp dport 5351 drop
  }
}
""")
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
                 "--identity", f"{d}/r.key", "--bind", "[::]:5555", *stun_args(topo), "--log-level", os.environ.get("NATLAB_LOG", "info")],
                "receiver.log",
            )
            rid = wait_for(lab, "receiver.log", r"Receiver ID: (sh4?-\S+)", 15)
            if not rid:
                print("the receiver did not start:\n" + lab.log("receiver.log")[-1200:])
                ok_all = False
                continue
            # What it publishes once its tests and the router have answered.
            time.sleep(12 if proto else 8)
            log = lab.log("receiver.log")
            forwards = re.findall(r"(?:IPv6 firewall|pinhole)[^\n]*", log)
            published = re.findall(r"Senders use: (sh4?-\S+)", log)
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
                 "--identity", f"{d}/s.key", "--state-dir", f"{d}/sst", "--log-level", os.environ.get("NATLAB_LOG", "info")],
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
            # And what let it in was what the receiver asked by: the daemon's
            # own log says which request opened the hole.
            daemon = lab.log("miniupnpd.log") if proto else ""
            pcp_map = re.search(r"PCP MAP: added mapping UDP 5555->2a0e:", daemon)
            if proto == "pcp-anycast":
                asked = re.search(r"counter packets (\d+)", lab.x("RB", "nft", "list", "table", "inet", "anycastonly").stdout)
                pcp_map = pcp_map if asked and int(asked.group(1)) > 0 else None
            evidence = {
                "pcp": pcp_map,
                "pcp-anycast": pcp_map,
                "upnp": re.search(r"WANIPv6FirewallControl:1#AddPinhole", daemon),
            }.get(proto, True)
            ok = transferred == bool(proto) and bool(evidence)
            ok_all &= ok
            what = "got in" if transferred else "was stopped by the firewall"
            if proto and transferred and not evidence:
                what += f", but not through a {proto} pinhole"
            elif proto and evidence:
                what += {"pcp": " through a PCP MAP", "upnp": " through UPnP AddPinhole",
                         "pcp-anycast": f" through a PCP MAP asked at {PCP_ANYCAST_V6}"}[proto]
            print(f"{proto or 'nothing':18} {'yes' if proto else 'none':8} "
                  f"{'ok  ' if ok else 'FAIL'} the sender {what} (via {', '.join(v6)}) in {took:.1f}s", flush=True)
            if not ok:
                print("\n".join(l[:200] for l in log.splitlines()[-14:]))
                print(lab.log("miniupnpd.log")[-1500:] if proto else "")
                print(lab.log("sender.log")[-1200:])
        finally:
            lab.close()
    return 0 if ok_all else 1


# What makes a NAT loop back (RFC 4787 REQ-9) what a host inside sends to
# the outside address, for `samenat`: to whichever host has that port
# outside — the NAT keeps the port a host sends from, and the receiver sends
# from 5555, the sender from the kernel's ephemeral range — and from the
# outside address, as the RFC wants, so that each sees the other where the
# relay said it would be. A host sending to its own outside address gets
# its own packet back, from there: what the hairpinning test looks for.
HAIRPIN = """table ip hairpin {
  chain pre {
    type nat hook prerouting priority dstnat - 1; policy accept;
    iifname "lan" ip daddr 11.1.0.1 udp dport 5555 dnat to 10.1.0.3
    iifname "lan" ip daddr 11.1.0.1 udp dport 32768-60999 dnat to 10.1.0.2
  }
  chain post {
    type nat hook postrouting priority srcnat - 1; policy accept;
    ip saddr 10.1.0.0/24 ip daddr 10.1.0.0/24 ct status dnat snat to 11.1.0.1
  }
}
"""


def cmd_samenat(args):
    """Two hosts behind one NAT. A Linux NAT does not loop packets back
    (RFC 4787 REQ-9) for the ports it hands out dynamically, so the public
    address a relay tells the sender is the router itself: the receiver's
    own address on the network is worth having, and where it is kept back
    only a relay gets the transfer across. Unless the NAT does loop back
    (`HAIRPIN`): then the two meet at their outside addresses. Each case
    also checks what the receiver measured of the NAT."""
    ok_all = True
    print(f"{'case':56} result")
    for name, extra, carry, loops, want in (
        ("the receiver publishes its address on the network", [], True, False, "lan"),
        ("...keeps it back, and the relay carries", ["--no-lan-addresses"], True, False, "relay"),
        ("...keeps it back, and the relay only introduces", ["--no-lan-addresses"], False, False, "none"),
        ("...and the NAT loops back (hairpinning)", ["--no-lan-addresses"], False, True, "direct-via-nat"),
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
            lab.core_links += ["iA", "iS"]
            sh("ip", "link", "set", "iA", "up")
            sh("ip", "link", "set", "iS", "up")
            lab.x("RA", "ip", "link", "set", "wan0", "name", "wan")
            lab.x("A", "ip", "link", "set", "vA", "name", "eth0")
            lab.x("A2", "ip", "link", "set", "vA2", "name", "eth0")
            lab.x("RA", "ip", "link", "add", "lan", "type", "bridge")
            for ifn in ("pA", "pA2"):
                lab.x("RA", "ip", "link", "set", ifn, "master", "lan")
                lab.x("RA", "ip", "link", "set", ifn, "up")
            # The bridge is the router's switch: what one host sends another
            # is switched, and only what is sent to the router is routed —
            # and translated. With br_netfilter loaded, Linux would put the
            # switched frames through the router's rules too, and a packet
            # looped back to the host it came from would be switched back
            # untranslated (the host drops it: its own address as source).
            lab.x("RA", "sysctl", "-qw", "net.bridge.bridge-nf-call-iptables=0", check=False)
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
            if loops:
                lab.nft("RA", HAIRPIN)
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
            rid_m = wait_for(lab, "relay.log", r"Receivers: --relay (sh4?-\S+?)@", 10)
            data = os.path.join(d, "payload.bin")
            with open(data, "wb") as f:
                f.write(os.urandom(1 << 20))
            want_hash = hashlib.sha256(open(data, "rb").read()).hexdigest()
            os.makedirs(f"{d}/out", exist_ok=True)
            lab.spawn(
                "A2",
                [f"{BIN}/sharp-receiver", "--headless", "--output", f"{d}/out", "--state-dir", f"{d}/rst",
                 "--identity", f"{d}/r.key", "--bind", "0.0.0.0:5555", "--stun", f"{S1}:3478",
                 "--relay", f"{rid_m.group(1)}@{S1}:5560", *extra, "--log-level", os.environ.get("NATLAB_LOG", "info")],
                "receiver.log",
            )
            m = wait_for(lab, "receiver.log", r"Senders use: (sh4?-\S+@[\d\[]\S*)", 30)
            log = lab.log("receiver.log")
            hairpin = "no hairpinning" if "no hairpinning" in log else ("hairpinning works" if "hairpinning works" in log else "unmeasured")
            rid = re.search(r"Receiver ID: (sh4?-\S+)", log).group(1)
            address = m.group(1) if m else f"{rid}@{S1}:9"
            start = time.time()
            sender = lab.spawn(
                "A",
                [f"{BIN}/sharp-sender", data, address, "--relay", f"{S1}:5560", "--headless", "--stun", f"{S1}:3478",
                 "--identity", f"{d}/s.key", "--state-dir", f"{d}/sst", "--log-level", os.environ.get("NATLAB_LOG", "info")],
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
            ok = path == want and hairpin == ("hairpinning works" if loops else "no hairpinning")
            ok_all &= ok
            print(f"{name:56} {'ok  ' if ok else 'FAIL'} {path} in {took:.1f}s (the NAT says: {hairpin})", flush=True)
            if not ok:
                print(lab.log("sender.log")[-1500:])
                print(log[-1500:])
        finally:
            lab.close()
    return 0 if ok_all else 1


# A carrier's NAT that loops back what its subscribers send to its own
# address: the receiver's port to the receiver's home router, the ports a
# sender's router hands out to the sender's.
CGN_HAIRPIN = """table ip hairpin {
  chain pre {
    type nat hook prerouting priority dstnat - 1; policy accept;
    iifname "cl" ip daddr 11.1.0.1 udp dport 5555 dnat to 100.64.0.3
    iifname "cl" ip daddr 11.1.0.1 udp dport 32768-60999 dnat to 100.64.0.2
  }
  chain post {
    type nat hook postrouting priority srcnat - 1; policy accept;
    ip saddr 100.64.0.0/24 ip daddr 100.64.0.0/24 ct status dnat snat to 11.1.0.1
  }
}
"""


def cmd_samecgn(args):
    """Two subscribers of one carrier, each behind a home router of their
    own, the two routers behind the same carrier-grade NAT (RFC 6598): the
    public address a relay names is the carrier's for both, and the two
    meet there only if the carrier's NAT loops back (RFC 4787 REQ-9), which
    a Linux NAT does not do by itself. Otherwise only a relay gets the
    transfer across — and if it only introduces, nothing does. Each case
    also checks what the receiver measured of the loop."""
    ok_all = True
    print(f"{'case':58} result")
    for name, carry, loops, want in (
        ("the carrier's NAT does not loop back, and the relay carries", True, False, "relay"),
        ("...and the relay only introduces", False, False, "none"),
        ("the carrier's NAT loops back", False, True, "direct-via-nat"),
    ):
        lab = Lab()
        try:
            # "I", the internet, is this process's own namespace (see `Topo`).
            for ns in ("A", "B", "RA", "RB", "C", "S"):
                lab.mk(ns)
            lab.link("A", "eth0", "RA", "lan")
            lab.link("B", "eth0", "RB", "lan")
            # The carrier's access network: a segment both home routers'
            # outside ports are on, with the carrier's NAT as its gateway.
            lab.link("RA", "wan", "C", "pa")
            lab.link("RB", "wan", "C", "pb")
            lab.link("C", "cw", "I", "iC")
            lab.link("S", "s0", "I", "iS")
            lab.x("C", "ip", "link", "add", "cl", "type", "bridge")
            for ifn in ("pa", "pb"):
                lab.x("C", "ip", "link", "set", ifn, "master", "cl")
                lab.x("C", "ip", "link", "set", ifn, "up")
            lab.x("C", "sysctl", "-qw", "net.bridge.bridge-nf-call-iptables=0", check=False)
            lab.addr("C", "cl", "100.64.0.1/24")
            for host, gw, n, wan in (("A", "RA", 1, "100.64.0.2"), ("B", "RB", 2, "100.64.0.3")):
                lab.addr(host, "eth0", f"10.{n}.0.2/24", f"10.{n}.0.1")
                lab.addr(gw, "lan", f"10.{n}.0.1/24")
                lab.addr(gw, "wan", f"{wan}/24", "100.64.0.1")
                lab.x(gw, "sysctl", "-qw", "net.ipv4.ip_forward=1")
                lab.nft(gw, gateway_input())
                lab.nft(gw, nat_rules("port_restricted", f"10.{n}.0.2").replace("$WANIP", wan))
            lab.addr("C", "cw", "11.1.0.1/24", "11.1.0.254")
            lab.addr("I", "iC", "11.1.0.254/24")
            lab.addr("S", "s0", f"{S1}/24", "11.9.0.254")
            lab.x("S", "ip", "addr", "add", f"{S2}/24", "dev", "s0")
            lab.addr("I", "iS", "11.9.0.254/24")
            lab.x("I", "sysctl", "-qw", "net.ipv4.ip_forward=1")
            lab.x("C", "sysctl", "-qw", "net.ipv4.ip_forward=1")
            lab.nft("C", gateway_input("cw"))
            lab.nft("C", nat_rules("port_restricted", "100.64.0.0/24", lan="cl", wan="cw")
                    .replace("$WANIP", "11.1.0.1"))
            if loops:
                lab.nft("C", CGN_HAIRPIN)
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
            lab.spawn("S", [f"{BIN}/sharp-relay", "--bind", "0.0.0.0:5560", "--stun", S1, "--stun", S2,
                            "--identity", f"{d}/relay.key", "--log", "info"], "relay.log")
            rid_m = wait_for(lab, "relay.log", r"Receivers: --relay (sh4?-\S+?)@", 10)
            data = os.path.join(d, "payload.bin")
            with open(data, "wb") as f:
                f.write(os.urandom(1 << 20))
            want_hash = hashlib.sha256(open(data, "rb").read()).hexdigest()
            os.makedirs(f"{d}/out", exist_ok=True)
            lab.spawn("B", [f"{BIN}/sharp-receiver", "--headless", "--output", f"{d}/out", "--state-dir", f"{d}/rst",
                            "--identity", f"{d}/r.key", "--bind", "0.0.0.0:5555", "--stun", f"{S1}:3478",
                            "--relay", f"{rid_m.group(1)}@{S1}:5560", "--no-lan-addresses",
                            "--log-level", os.environ.get("NATLAB_LOG", "info")], "receiver.log")
            m = wait_for(lab, "receiver.log", r"Senders use: (sh4?-\S+@[\d\[]\S*)", 30)
            log = lab.log("receiver.log")
            hairpin = ("no hairpinning" if "no hairpinning" in log
                       else ("hairpinning works" if "hairpinning works" in log else "unmeasured"))
            rid = re.search(r"Receiver ID: (sh4?-\S+)", log).group(1)
            address = m.group(1) if m else f"{rid}@{S1}:9"
            start = time.time()
            sender = lab.spawn("A", [f"{BIN}/sharp-sender", data, address, "--relay", f"{S1}:5560", "--headless",
                                     "--stun", f"{S1}:3478", "--identity", f"{d}/s.key", "--state-dir", f"{d}/sst",
                                     "--log-level", os.environ.get("NATLAB_LOG", "info")], "sender.log")
            try:
                sender.wait(timeout=30)
            except subprocess.TimeoutExpired:
                sender.kill()
            took = time.time() - start
            got = None
            for f in os.listdir(f"{d}/out"):
                if not f.endswith(".sharp-part"):
                    got = hashlib.sha256(open(f"{d}/out/{f}", "rb").read()).hexdigest()
            slog = lab.log("sender.log")
            proven = re.findall(r"receiver address (\S+) proven", slog)
            conn = re.search(r"Connected to (\S+)", slog)
            last = proven[-1] if proven else (conn.group(1) if conn else None)
            topo = type("Topo", (), {"wan_ip": {"C": "11.1.0.1"}})()
            path = classify(last, topo, 5560) if got == want_hash else "none"
            ok = path == want and hairpin == ("hairpinning works" if loops else "no hairpinning")
            ok_all &= ok
            print(f"{name:58} {'ok  ' if ok else 'FAIL'} {path} in {took:.1f}s (the NAT says: {hairpin})", flush=True)
            if not ok or args.verbose:
                print(slog[-1500:])
                print(log[-1500:])
        finally:
            lab.close()
    return 0 if ok_all else 1


# An address of the server host that nobody has any business sending to:
# the one a hostile DHT node plants (`dhtplant`).
PLANTED = "11.9.0.12"


def planted_counter(lab):
    """What the kernel of the server host counted towards PLANTED: (packets,
    UDP payload bytes)."""
    out = lab.x("S", "nft", "list", "chain", "inet", "plant", "input").stdout
    m = re.search(r"counter packets (\d+) bytes (\d+)", out)
    packets, total = (int(m.group(1)), int(m.group(2))) if m else (0, 0)
    return packets, total - 28 * packets


def cmd_dhtplant(args):
    """A DHT node on the lookup's path that answers every question with an
    address of its choosing beside the real ones — here one of the server
    host's, where the kernel counts whatever arrives: what the two ends of a
    meeting through the DHT send to an address planted this way
    (docs/THREAT_MODEL.md, R24). An honest node beside it holds what the two
    announce. With the receiver there (the meeting has to happen all the
    same), and with nobody there at all, for as long as `--wait` (the sender
    looks for five minutes). One pass of prediction is 8235 bytes (61
    ports), a spray 18 432 (2048); plain punches are 135 bytes a pass."""
    failures = 0
    print(f"{'case':56} {'result':28} planted address got")
    for case, a_nat, b_nat in (("the receiver is there", "port_restricted", "full_cone"),
                               ("the receiver is there", "port_restricted", "symmetric_random"),
                               ("nobody is there", "port_restricted", "full_cone")):
        lab = Lab()
        try:
            topo = Topo(lab, a_nat, b_nat)
            d = lab.dir
            lab.x("S", "ip", "addr", "add", f"{PLANTED}/24", "dev", "s0")
            lab.x("S", "nft", "add", "table", "inet", "plant")
            lab.x("S", "nft", "add", "chain", "inet", "plant", "input",
                  "{ type filter hook input priority 0 ; policy accept ; }")
            lab.x("S", "nft", "add", "rule", "inet", "plant", "input", "ip", "daddr", PLANTED, "counter")
            lab.spawn("S", [f"{BIN}/sharp-relay", "--bind", "0.0.0.0:5560", "--stun", S1, "--stun", S2,
                            "--identity", f"{d}/relay.key", "--log", "info"], "relay.log")
            wait_for(lab, "relay.log", r"Receivers: --relay", 10)
            # Two nodes, as a lookup meets in the real DHT: an honest one, and
            # one that adds the planted address to every answer.
            node = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dht_node.py")
            lab.spawn("S", ["python3", node, "--bind", f"{S1}:6881"], "dht.log")
            lab.spawn("S", ["python3", node, "--bind", f"{S2}:6881", "--plant", f"{PLANTED}:7000"],
                      "dht-hostile.log")
            if not (wait_for(lab, "dht.log", r"dht node", 10) and wait_for(lab, "dht-hostile.log", r"dht node", 10)):
                print("a DHT node did not start:\n" + lab.log("dht.log") + lab.log("dht-hostile.log"))
                return 1
            dht_args = ["--dht", "--dht-bootstrap", f"{S1}:6881", "--dht-bootstrap", f"{S2}:6881"]
            data, want = make_payload(d)
            os.makedirs(f"{d}/out", exist_ok=True)
            there = case == "the receiver is there"
            if there:
                lab.spawn("B", [f"{BIN}/sharp-receiver", "--headless", "--output", f"{d}/out",
                                "--state-dir", f"{d}/rst", "--identity", f"{d}/r.key", "--bind", "0.0.0.0:5555",
                                "--stun", f"{S1}:3478", *dht_args, "--log-level", os.environ.get("NATLAB_LOG", "info")], "receiver.log")
                rid = wait_for(lab, "receiver.log", r"Receiver ID: (sh4?-\S+)", 15).group(1)
            else:
                shown = lab.x("B", f"{BIN}/sharp-receiver", "--identity", f"{d}/r.key", "--id").stdout
                rid = re.search(r"(sh4?-[a-z0-9]+)", shown).group(1)
            start = time.time()
            sender = lab.spawn("A", [f"{BIN}/sharp-sender", data, rid, "--headless", "--stun", f"{S1}:3478",
                                     *dht_args, "--identity", f"{d}/s.key", "--state-dir", f"{d}/sst",
                                     "--log-level", os.environ.get("NATLAB_LOG", "info")], "sender.log")
            limit = args.timeout if there else args.wait
            try:
                sender.wait(timeout=limit)
            except subprocess.TimeoutExpired:
                sender.kill()
            took = time.time() - start
            got = None
            for name in os.listdir(f"{d}/out"):
                if not name.endswith(".sharp-part"):
                    got = hashlib.sha256(open(f"{d}/out/{name}", "rb").read()).hexdigest()
            packets, payload = planted_counter(lab)
            planted_asked = "planted" if f"{PLANTED}:7000" in lab.log("sender.log") else "not seen"
            if there:
                result = ("delivered" if got == want else "NOT delivered") + f" in {took:.1f}s"
            else:
                result = f"searched for {took:.0f}s"
            bad = there and got != want
            failures += bad
            print(f"{case + ', ' + a_nat + '/' + b_nat:56} {result:28} {packets} datagrams, {payload} B"
                  f"  (sender log: {planted_asked})")
            if bad and args.verbose:
                print("--- sender.log\n" + lab.log("sender.log")[-3000:])
        finally:
            lab.close()
    print("(UDP payload counted by the planted host's kernel; a meeting that does not happen fails the run)")
    return 1 if failures else 0


def cmd_early(args):
    """A sender that asks the relay for a receiver before that receiver has
    registered — two people starting at about the same time — keeps asking,
    and is put through once the receiver is there. The relay may only
    introduce and the receiver's NAT lets in nothing it has not been sent
    to, so the introduction is the only way and a sender that gave up on the
    relay at the first "unknown" would never arrive."""
    ok_all = True
    print(f"{'sender behind':18} {'receiver behind':18} result")
    for a_nat, b_nat in (("open", "port_restricted"), ("port_restricted", "restricted"), ("full_cone", "symmetric_random")):
        lab = Lab()
        try:
            topo = Topo(lab, a_nat, b_nat)
            d = lab.dir
            relay_may_only_introduce(lab, False)
            lab.spawn(
                "S",
                [f"{BIN}/sharp-relay", "--bind", "0.0.0.0:5560", "--stun", S1, "--stun", S2,
                 "--identity", f"{d}/relay.key", "--log", "info"],
                "relay.log",
            )
            rid = wait_for(lab, "relay.log", r"Receivers: --relay (sh4?-\S+?)@", 10).group(1)
            # The receiver's ID is known before it runs: it is its key's.
            shown = lab.x("B", f"{BIN}/sharp-receiver", "--identity", f"{d}/r.key", "--id").stdout
            receiver_id = re.search(r"(sh4?-[a-z0-9]+)", shown).group(1)
            data = os.path.join(d, "payload.bin")
            with open(data, "wb") as f:
                f.write(os.urandom(1 << 20))
            want = hashlib.sha256(open(data, "rb").read()).hexdigest()
            os.makedirs(f"{d}/out", exist_ok=True)
            start = time.time()
            sender = lab.spawn(
                "A",
                [f"{BIN}/sharp-sender", data, f"{receiver_id}@{S1}:9", "--relay", f"{S1}:5560", "--headless",
                 "--stun", f"{S1}:3478", "--identity", f"{d}/s.key", "--state-dir", f"{d}/sst", "--log-level", os.environ.get("NATLAB_LOG", "info")],
                "sender.log",
            )
            time.sleep(args.delay)
            lab.spawn(
                "B",
                [f"{BIN}/sharp-receiver", "--headless", "--output", f"{d}/out", "--state-dir", f"{d}/rst",
                 "--identity", f"{d}/r.key", "--bind", "0.0.0.0:5555", "--stun", f"{S1}:3478",
                 "--relay", f"{rid}@{S1}:5560", "--log-level", os.environ.get("NATLAB_LOG", "info")],
                "receiver.log",
            )
            try:
                sender.wait(timeout=args.timeout)
            except subprocess.TimeoutExpired:
                sender.kill()
            took = time.time() - start
            got = None
            for f in os.listdir(f"{d}/out"):
                if not f.endswith(".sharp-part"):
                    got = hashlib.sha256(open(f"{d}/out/{f}", "rb").read()).hexdigest()
            log = lab.log("sender.log")
            conn = re.search(r"Connected to (\S+)", log)
            path = classify(conn.group(1) if conn else None, topo, 5560) if got == want else "none"
            asked_again = "asking again" in log
            # Put through, directly, and because it asked again: a sender
            # that got in without having to would show nothing of the kind.
            ok = got == want and is_direct(path) and asked_again
            ok_all &= ok
            print(f"{a_nat:18} {b_nat:18} {'ok  ' if ok else 'FAIL'} {path} in {took:.1f}s "
                  f"(the sender {'asked again' if asked_again else 'did not ask again'} for its receiver, which started "
                  f"{args.delay:.1f}s after it)", flush=True)
            if not ok:
                print(log[-2000:])
                print(lab.log("receiver.log")[-1500:])
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
        rid_m = wait_for(lab, "relay.log", r"Receivers: --relay (sh4?-\S+?)@", 10)
        data = os.path.join(d, "payload.bin")
        with open(data, "wb") as f:
            f.write(os.urandom(1 << 20))
        want = hashlib.sha256(open(data, "rb").read()).hexdigest()
        os.makedirs(f"{d}/out", exist_ok=True)
        lab.spawn(
            "B",
            [f"{BIN}/sharp-receiver", "--headless", "--output", f"{d}/out", "--state-dir", f"{d}/rst",
             "--identity", f"{d}/r.key", "--bind", "0.0.0.0:5555", "--stun", f"{S1}:3478",
             "--relay", f"{rid_m.group(1)}@{S1}:5560", "--log-level", os.environ.get("NATLAB_LOG", "info")],
            "receiver.log",
        )
        m = wait_for(lab, "receiver.log", r"Senders use: (sh4?-\S+@[\d\[]\S*)", 30)
        rid = re.search(r"Receiver ID: (sh4?-\S+)", lab.log("receiver.log")).group(1)
        address = m.group(1) if m else f"{rid}@{S1}:9"
        print(f"the NAT in front of the receiver forgets a UDP flow after {args.memory} s; waiting {args.wait} s idle")
        end = time.time() + args.wait
        alive = []
        adapted_at = None
        while time.time() < end:
            time.sleep(max(1, args.wait // 12))
            ct = conntrack(lab, "RB")
            flows = [l for l in ct.splitlines() if "udp" in l and "dst=11.9.0.10" in l.split("src=")[1] and "dport=5560" in l]
            alive.append(len(flows))
            if len(alive) == 1 and not flows:
                print("(nothing about the receiver's flow in the conntrack table; it reads:)\n" + ct[:700])
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
             "--identity", f"{d}/s.key", "--state-dir", f"{d}/sst", "--log-level", os.environ.get("NATLAB_LOG", "info")],
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
        # The samples after the receiver found out how short the NAT's memory
        # is, less one: the interval takes effect at the refresh after the one
        # it was measured in. Three at least, or nothing was shown.
        after = alive[adapted_at + 1:] if adapted_at is not None else []
        kept = bool(shortened) and len(after) >= 3 and all(n > 0 for n in after)
        ok = got == want and kept
        print(f"a sender put through after the wait: {'ok' if got == want else 'FAILED'} via {conn.group(1) if conn else 'nothing'}; "
              f"mapping kept alive in the {len(after)} sample(s) after the receiver adapted: {'yes' if kept else 'NO'}")
        if not ok:
            print(log[-1500:])
            print(lab.log("sender.log")[-1500:])
        return 0 if ok else 1
    finally:
        lab.close()


class Cut:
    """Cuts the direct path between the two networks once the sender's
    session runs on it, and leaves the server reachable from both: what a
    direct path that dies looks like to the two ends — a gateway that
    reboots and forgets its mappings, a firewall rule, a route that goes.
    Then follows, in the sender's log, where the session goes."""

    RULES = """table inet cut {
  chain cut {
    type filter hook forward priority filter - 2; policy accept;
    ip saddr 11.1.0.0/16 ip daddr 11.2.0.0/16 drop
    ip saddr 11.2.0.0/16 ip daddr 11.1.0.0/16 drop
  }
}
"""
    # Where the session is, as the sender says it: the address it connected
    # to, one that answered a handshake, one that was proven.
    PATH = r"Connected to (\S+)|receiver answered at (\S+)|receiver address (\S+) proven"

    def __init__(self, turn):
        self.turn = turn
        self.started = time.time()
        self.at = None       # when the cut was made
        self.direct = None   # seconds from the start to the direct path
        self.offset = 0      # how much of the sender's log came before the cut
        self.back = None     # seconds from the cut to a server carrying again
        self.trail = []      # the paths after the cut, in order
        self.told = []       # the sender's lines about its path

    def paths(self, log, topo):
        return [classify(next(g for g in m.groups() if g), topo, 5560, turn=self.turn)
                for m in re.finditer(self.PATH, log)]

    # What the sender says of where its session goes, kept for the report:
    # the logs are gone with the laboratory.
    TOLD = re.compile(r"Connected to|answered at|proven|claims address|NAT let|runs from|carried by|"
                      r"punching towards|no packets from|receiver is back|birthday")

    def __call__(self, lab, topo):
        log = lab.log("sender.log")
        self.told = [l[:220] for l in log.splitlines() if self.TOLD.search(l)]
        if self.at is None:
            paths = self.paths(log, topo)
            if paths and paths[-1].startswith("direct"):
                lab.nft("I", self.RULES)
                self.at = time.time()
                self.direct = self.at - self.started
                self.offset = len(log)
            return
        self.trail = self.paths(log[self.offset:], topo)
        if self.back is None and self.trail and is_carried(self.trail[-1]):
            self.back = time.time() - self.at


# A session that began through a server and moved to a direct path: on its
# own socket (two NATs that keep one mapping), and on the socket of a
# birthday meeting (the sender's NAT draws ports at random) — the case in
# which the way back leaves from another socket than the one the session is
# on: the one the server knows.
FALLBACK_CASES = [
    ("port_restricted", "port_restricted", "relay"),
    ("symmetric_random", "port_restricted", "relay"),
    ("port_restricted", "port_restricted", "turn"),
    ("symmetric_random", "port_restricted", "turn"),
]


def cmd_fallback(args):
    """A session that went direct loses its direct path in the middle of a
    transfer while the server it began through is still there: it is
    expected to go back to that server and finish, not to wait for the
    direct path to come back. The sender notices the silence after its
    stall timeout (20 s) and then asks every address the receiver is known
    by, the server's among them. How long a server keeps the way open is its
    own business: a relay releases a pair's port after a minute without
    traffic (so the cut is made as soon as the session is direct), a TURN
    server keeps an allocation as long as its owner refreshes it."""
    os.environ.setdefault("NATLAB_SIZE_MB", "40")
    os.environ.setdefault("NATLAB_MAX_RATE", "16M")
    cases = [c for c in FALLBACK_CASES if not args.via or c[2] == args.via]
    ok_all = True
    print(f"{'sender behind':18} {'receiver behind':18} {'via':6} result")
    for a, b, via in cases:
        cut = Cut(turn=(via == "turn"))
        # The logs are kept whatever happens: a transfer that got through
        # may still not have done what was asked of it.
        ok, path, took, detail = transfer(a, b, timeout=args.timeout, via=via, verbose=True, during=cut)
        trail = [p for i, p in enumerate(cut.trail) if i == 0 or p != cut.trail[i - 1]]
        if cut.at is None:
            good = False
            verdict = "the session never ran directly: nothing was cut"
        else:
            good = ok and cut.back is not None
            verdict = f"direct after {cut.direct:.1f}s, then cut; " + (
                f"carried by the {cut.trail[-1] if cut.trail else '?'} again {cut.back:.1f}s later"
                if cut.back is not None else "never carried again")
            verdict += f" (after the cut: {' -> '.join(trail) or 'nothing'})"
        ok_all &= good
        print(f"{a:18} {b:18} {via:6} {'ok  ' if good else 'FAIL'} {'delivered' if ok else 'NOT delivered'} "
              f"in {took:.1f}s; {verdict}", flush=True)
        if args.verbose or not good:
            print("--- what the sender said of its path\n" + "\n".join(cut.told[-60:]), flush=True)
            print(detail, flush=True)
    return 0 if ok_all else 1


class Move:
    """Moves hosts from their network to a second one in the middle of a
    transfer — Wi-Fi to LTE: once the sender's session runs directly, the
    first network's link goes down and the default route goes to the
    second network's router, whose NAT (`kind`) every packet leaves through
    from then on. The sockets stay as they are, as a phone's do when it
    changes networks. Then follows where the session goes: the receiver's
    log says when it moved to the sender's new address, the sender's when
    it proved the receiver's."""

    TOLD = re.compile(r"Connected to|answered at|proven|claims address|NAT let|runs from|carried by|"
                      r"punching towards|no packets from|receiver is back|birthday|registered|"
                      r"moving the session|No answer|waiting")

    def __init__(self, hosts, kind):
        self.hosts, self.kind = hosts, kind
        self.started = time.time()
        self.ready = False
        self.at = None        # when the hosts moved
        self.direct = None    # seconds from the start to the direct path
        self.offsets = {}     # how much of each log came before the move
        self.trail = []       # the sender's paths after the move, in order
        self.followed = None  # seconds from the move to the other end following
        self.told = []

    def second_network(self, lab, topo, host):
        """A second router for `host`, its link up and addressed but not
        routed through: the LTE a phone holds while on Wi-Fi."""
        n = 3 if host == "A" else 4
        gw, lan, wan = f"R{host}2", f"10.{n}.0", f"11.{n}.0"
        lab.mk(gw)
        lab.link(host, "eth1", gw, "lan")
        lab.x(host, "ip", "addr", "add", f"{lan}.2/24", "dev", "eth1")
        lab.x(host, "ip", "link", "set", "eth1", "up")
        lab.addr(gw, "lan", f"{lan}.1/24")
        lab.link(gw, "wan", "I", f"i{host}2")
        lab.addr(gw, "wan", f"{wan}.1/24", f"{wan}.254")
        lab.addr("I", f"i{host}2", f"{wan}.254/24")
        lab.x(gw, "sysctl", "-qw", "net.ipv4.ip_forward=1")
        lab.nft(gw, gateway_input())
        lab.nft(gw, nat_rules(self.kind, f"{lan}.2").replace("$WANIP", f"{wan}.1"))
        topo.wan_ip[f"{host}2"] = f"{wan}.1"

    def switch(self, lab, host):
        n = 3 if host == "A" else 4
        lab.x(host, "ip", "link", "set", "eth0", "down")
        lab.x(host, "ip", "route", "replace", "default", "via", f"10.{n}.0.1", "dev", "eth1")

    def __call__(self, lab, topo):
        if not self.ready:
            for host in self.hosts:
                self.second_network(lab, topo, host)
            self.ready = True
        slog = lab.log("sender.log")
        self.told = [l[:220] for name in ("sender.log", "receiver.log")
                     for l in lab.log(name).splitlines() if self.TOLD.search(l)]
        paths = [classify(next(g for g in m.groups() if g), topo, 5560) for m in re.finditer(Cut.PATH, slog)]
        if self.at is None:
            if paths and paths[-1].startswith("direct"):
                for host in self.hosts:
                    self.switch(lab, host)
                self.at = time.time()
                self.direct = self.at - self.started
                self.offsets = {name: len(lab.log(name)) for name in ("sender.log", "receiver.log")}
            return
        self.trail = [classify(next(g for g in m.groups() if g), topo, 5560)
                      for m in re.finditer(Cut.PATH, slog[self.offsets["sender.log"]:])]
        if self.followed is None:
            # The other end has followed: the receiver proved the sender's
            # new address, the sender the receiver's.
            rlog = lab.log("receiver.log")[self.offsets["receiver.log"]:]
            slog_after = slog[self.offsets["sender.log"]:]
            sender_followed = "A" not in self.hosts or re.search(r"sender address \S+ proven", rlog)
            receiver_followed = "B" not in self.hosts or re.search(
                r"receiver address \S*" + re.escape(topo.wan_ip["B2"]) + r"\S* proven", slog_after)
            if sender_followed and receiver_followed:
                self.followed = time.time() - self.at


# Who moves, from which networks, to a second network of which kind.
# (sender's network, receiver's network, who moves, the second network)
MOBILITY_CASES = [
    ("port_restricted", "port_restricted", ("A",), "port_restricted"),
    ("port_restricted", "port_restricted", ("A",), "symmetric_random"),
    ("port_restricted", "port_restricted", ("B",), "port_restricted"),
    ("port_restricted", "port_restricted", ("A", "B"), "port_restricted"),
]


def cmd_mobility(args):
    """One end, or both, changes networks in the middle of a transfer that
    runs directly (Wi-Fi to LTE). Expected: the transfer finishes, and on a
    direct path again — not left on the relay, not broken off. Long enough
    for that: a receiver learns its new address at its next keepalive to
    the relay (every 7.5 to 25 s, by what its NAT keeps)."""
    os.environ.setdefault("NATLAB_SIZE_MB", "80")
    os.environ.setdefault("NATLAB_MAX_RATE", "16M")
    ok_all = True
    print(f"{'sender behind':18} {'receiver behind':18} {'moves':6} {'to':18} result")
    cases = [c for i, c in enumerate(MOBILITY_CASES) if not args.case or i + 1 in args.case]
    for a, b, hosts, kind in cases:
        move = Move(hosts, kind)
        ok, path, took, detail = transfer(a, b, timeout=args.timeout, via="relay", verbose=True, during=move,
                                          keep=bool(os.environ.get("NATLAB_KEEP")))
        trail = [p for i, p in enumerate(move.trail) if i == 0 or p != move.trail[i - 1]]
        if move.at is None:
            good, verdict = False, "the session never ran directly: nobody moved"
        else:
            # Where the session ended: the last path the sender went to
            # after the move, or — the sender moving alone, its receiver's
            # address the same — the path it was on, if the receiver
            # followed it there directly.
            if trail:
                end = trail[-1]
            elif move.followed is not None:
                end = "direct (followed)"
            else:
                end = "nowhere new"
            good = ok and is_direct(end)
            verdict = (f"direct after {move.direct:.1f}s, then moved; "
                       + (f"followed {move.followed:.1f}s later" if move.followed is not None else "not followed")
                       + f"; ended {end} (after the move: {' -> '.join(trail) or 'the same path'})")
        ok_all &= good
        who = "+".join("sender" if h == "A" else "receiver" for h in hosts)
        print(f"{a:18} {b:18} {who:6} {kind:18} {'ok  ' if good else 'FAIL'} "
              f"{'delivered' if ok else 'NOT delivered'} in {took:.1f}s; {verdict}", flush=True)
        if args.verbose or not good:
            print("--- what the two said of their path\n" + "\n".join(move.told[-80:]), flush=True)
            if not good:
                print(detail, flush=True)
    return 0 if ok_all else 1


# How fast each way carries, with nothing capping it: straight between two
# public hosts, through a relay's port, through a TURN server — the two
# networks unable to reach each other for the last two, so the server
# carries all of it. (name, sender's network, receiver's, how they meet,
# isolated)
SPEED_PATHS = [
    ("direct", "open", "open", "relay", False),
    ("relay", "port_restricted", "port_restricted", "relay", True),
    ("TURN", "port_restricted", "port_restricted", "turn", True),
]


def cmd_speed(args):
    """What a transfer gets through each kind of path on this machine
    (ROADMAP E6). The laboratory's links have no limit of their own: what
    is measured is the programs — the relay's forwarding, coturn's, the two
    ends — on the CPU they share with each other, in whatever build
    SHARP_BIN_DIR holds (a debug build is several times slower)."""
    os.environ["NATLAB_SIZE_MB"] = str(args.mb)
    os.environ.pop("NATLAB_MAX_RATE", None)
    ok_all = True
    print(f"{'path':8} {'carried by':16} result")
    for name, a, b, via, isolate in SPEED_PATHS:
        ok, path, took, detail = transfer(a, b, timeout=args.timeout, via=via, isolate=isolate, verbose=True)
        m = re.search(r"Done: \S+ \S+ in ([\d.]+)(m?s) \(([\d.]+) (k|M|G)bit/s avg\)", detail)
        if m:
            secs = float(m.group(1)) / (1000.0 if m.group(2) == "ms" else 1.0)
            rate = float(m.group(3)) * {"k": 1e-3, "M": 1.0, "G": 1e3}[m.group(4)]
            said = f"{rate:.1f} Mbit/s ({args.mb} MB in {secs:.1f} s)"
        else:
            said = f"no summary ({took:.1f} s)"
        wanted = {"direct": is_direct, "relay": lambda p: p.startswith("relay"), "TURN": lambda p: p.startswith("turn")}
        good = ok and m is not None and wanted[name](path)
        ok_all &= good
        print(f"{name:8} {path:16} {'ok  ' if good else 'FAIL'} {said}", flush=True)
        if args.verbose or not good:
            print(detail, flush=True)
    return 0 if ok_all else 1


# A carrier-grade NAT (RFC 6598) in front of a home router: two NATs in a
# row, and what a peer meets is what the two do together — the outer one's
# numbering of ports, and whatever filtering is stricter. (sender's router,
# sender's carrier, receiver's router, receiver's carrier, how they meet,
# where the session must end up.)
CGN_CASES = [
    ("port_restricted", "port_restricted", "port_restricted", None, "card", "direct"),
    ("port_restricted", None, "port_restricted", "port_restricted", "card", "direct"),
    ("port_restricted", "symmetric_random", "port_restricted", None, "card", "direct"),
    ("port_restricted", None, "port_restricted", "symmetric_random", "card", "direct"),
    ("port_restricted", "symmetric_random", "port_restricted", "symmetric_random", "card", "none"),
    ("port_restricted", "symmetric_random", "port_restricted", "symmetric_random", "relay", "relay"),
]


def cmd_cgn(args):
    """Two NATs in a row, the outer one a carrier's: a home router whose own
    "public" address is in 100.64.0.0/10, behind a NAT it does not control.
    Punching, the birthday method and the relay have to work through both:
    a stable carrier NAT in front of a stable router is still stable, a
    carrier that draws ports at random makes the pair as hard as a random
    NAT would, and two of those need a server. (Whether the router's port
    forward is any use there is another question: miniupnpd refuses to
    forward at all with an address like that on its external interface, and
    the programs tell a forward granted by a router behind another NAT from a
    real one by that address — unit tests, `nat::forward_address`.)"""
    ok_all = True
    print(f"{'sender behind':42} {'receiver behind':42} {'via':6} result")
    for a, a_cgn, b, b_cgn, via, want in CGN_CASES:
        ok, path, took, detail = transfer(a, b, a_cgn, b_cgn, via=via, timeout=args.timeout,
                                          verbose=args.verbose)
        where = path.split(" ")[0]
        if want == "none":
            met = not ok
        elif want == "direct":
            met = ok and is_direct(where)
        else:
            met = ok and where == want
        ok_all &= met
        side = lambda nat, cgn: nat + (f" + carrier {cgn}" if cgn else "")
        print(f"{side(a, a_cgn):42} {side(b, b_cgn):42} {via:6} {'ok  ' if ok else 'FAIL'} {path:16} {took:5.1f}s "
              f"{'as expected' if met else 'UNEXPECTED (wanted ' + want + ')'}", flush=True)
        if not met and args.verbose:
            print(detail, flush=True)
    return 0 if ok_all else 1


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
    pair.add_argument("--via", choices=["relay", "card", "turn", "dht", "addr"], default="relay",
                      help="how the two find each other: a relay, cards or addresses handed over by hand, a TURN server, the DHT")
    probe = sub.add_parser("probe")
    probe.add_argument("a", nargs="?", choices=list(NAT_KINDS))
    probe.add_argument("b", nargs="?", choices=list(NAT_KINDS))
    probe.add_argument("--all", action="store_true", help="every pair of NAT kinds")
    probe.add_argument("--v6", action="store_true", help="IPv6: every pair of firewall kinds, IPv6 only and dual stack")
    probe.add_argument("--addr", action="store_true", help="swap the Addresses: lines instead of the cards")
    probe.add_argument("--wait", type=int, default=20)
    v6 = sub.add_parser("v6")
    v6.add_argument("--scenario", default=None, help="only the scenarios whose name has this in it")
    v6.add_argument("--direct-only", action="store_true")
    v6.add_argument("--isolate", action="store_true", help="the two networks cannot reach each other, only the server")
    v6.add_argument("--via", choices=["relay", "card", "turn", "dht", "addr"], default="relay")
    v6.add_argument("--timeout", type=int, default=30)
    v6.add_argument("--markdown")
    v6.add_argument("--cell", default=None, help="only this pair of firewalls, e.g. stateful6,open6")
    v6.add_argument("--repeat", type=int, default=1, help="each pair this many times (a race shows up in some runs only)")
    v6.add_argument("--allow-failures", action="store_true")
    v6.add_argument("-v", "--verbose", action="store_true")
    lan = sub.add_parser("lan")
    lan.add_argument("--timeout", type=int, default=25)
    lan.add_argument("--v6", action="store_true", help="a network with IPv6 only")
    sub.add_parser("samenat")
    dp = sub.add_parser("dhtplant")
    dp.add_argument("--wait", type=float, default=45.0, help="how long the sender with nobody to meet runs")
    dp.add_argument("--timeout", type=float, default=60.0)
    dp.add_argument("--verbose", action="store_true")
    early = sub.add_parser("early")
    early.add_argument("--delay", type=float, default=2.5, help="seconds the receiver starts after the sender")
    early.add_argument("--timeout", type=int, default=45)
    cg = sub.add_parser("cgn")
    cg.add_argument("--timeout", type=int, default=60)
    cg.add_argument("-v", "--verbose", action="store_true")
    ds = sub.add_parser("dslite")
    ds.add_argument("--timeout", type=int, default=45)
    ds.add_argument("-v", "--verbose", action="store_true")
    n66 = sub.add_parser("nat66")
    n66.add_argument("--timeout", type=int, default=45)
    n66.add_argument("-v", "--verbose", action="store_true")
    sc = sub.add_parser("samecgn")
    sc.add_argument("-v", "--verbose", action="store_true")
    sp = sub.add_parser("speed")
    sp.add_argument("--mb", type=int, default=100, help="the file's size in megabytes")
    sp.add_argument("--timeout", type=int, default=300)
    sp.add_argument("-v", "--verbose", action="store_true")
    mob = sub.add_parser("mobility")
    mob.add_argument("--timeout", type=int, default=150)
    mob.add_argument("--case", type=int, nargs="*", help="only these cases, counted from 1")
    mob.add_argument("-v", "--verbose", action="store_true")
    fb = sub.add_parser("fallback")
    fb.add_argument("--via", choices=["relay", "turn"], default=None, help="only the cases through this server")
    fb.add_argument("--timeout", type=int, default=150)
    fb.add_argument("-v", "--verbose", action="store_true")
    to = sub.add_parser("timeout")
    to.add_argument("--memory", type=int, default=8, help="seconds the NAT keeps a UDP flow")
    to.add_argument("--wait", type=int, default=60, help="seconds the receiver is left idle")
    pm6 = sub.add_parser("portmap6")
    pm6.add_argument("--protocols", nargs="*", choices=["pcp", "pcp-anycast", "upnp"])
    pm6.add_argument("--timeout", type=int, default=25)
    pm = sub.add_parser("portmap")
    pm.add_argument("--protocols", nargs="*", choices=["pcp", "natpmp", "upnp", "upnp-v1"])
    pm.add_argument("--receivers", nargs="*", default=["port_restricted", "symmetric_random"], choices=list(NAT_KINDS))
    pm.add_argument("--senders", nargs="*", choices=list(NAT_KINDS))
    pm.add_argument("--timeout", type=int, default=25)
    pm.add_argument("--anycast", action="store_true",
                    help="the NAT and its PCP server are the carrier's, at the PCP anycast address")
    pm.add_argument("--taken", action="store_true",
                    help="the router's port 5555 is forwarded to somebody else before the receiver asks")
    matrix = sub.add_parser("matrix")
    matrix.add_argument("kinds", nargs="*", help="a subset of: " + " ".join(NAT_KINDS))
    matrix.add_argument("--markdown", help="write the results as a table to this file")
    matrix.add_argument("--allow-failures", action="store_true")
    matrix.add_argument("--direct-only", action="store_true", help="the relay may introduce but not carry")
    matrix.add_argument("--isolate", action="store_true", help="the two networks cannot reach each other, only the server")
    matrix.add_argument("--via", choices=["relay", "card", "turn", "dht", "addr"], default="relay",
                        help="how the two find each other: a relay, cards or addresses handed over by hand, a TURN server, the DHT")
    matrix.add_argument("--timeout", type=int, default=30)
    matrix.add_argument("-v", "--verbose", action="store_true", help="the logs of every pair that was not as expected")
    args = ap.parse_args()
    sh("ip", "link", "set", "lo", "up")
    sys.exit({"oracle": cmd_oracle, "pair": cmd_pair, "probe": cmd_probe, "matrix": cmd_matrix, "v6": cmd_v6, "portmap": cmd_portmap, "portmap6": cmd_portmap6, "samenat": cmd_samenat, "dhtplant": cmd_dhtplant, "timeout": cmd_timeout, "lan": cmd_lan, "early": cmd_early, "fallback": cmd_fallback, "cgn": cmd_cgn, "mobility": cmd_mobility,
              "speed": cmd_speed, "samecgn": cmd_samecgn, "nat66": cmd_nat66,
              "dslite": cmd_dslite}[args.cmd](args))


if __name__ == "__main__":
    main()
