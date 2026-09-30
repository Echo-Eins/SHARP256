#!/usr/bin/env python3
"""What a STUN server answers an address it cannot know is real, measured
from outside.

A STUN server answers whatever address a request comes from, and a request
can come from a forged one: every byte of the answer beyond the request's
own is a byte an attacker gets aimed at somebody else for free. SHARP-256
holds everything it sends to an address nobody has proven to no more than
came from it (docs/THREAT_MODEL.md, "Об усилении"); for the STUN server of
sharp-relay that means answering only requests at least as long as the
answer, and SHARP-256's clients pad theirs with a SOFTWARE attribute.

This script shares no code with the implementation: it builds the requests
itself, sends each from a fresh socket and counts what comes back.

    amplab.py stun      sharp-relay's STUN server, on 127.0.0.1 and ::1:
                        a bare request, CHANGE-REQUEST and RESPONSE-PORT
                        ones, and each padded as SHARP-256 pads it
    amplab.py public    public STUN servers: is a request padded with
                        SOFTWARE answered, and one padded with PADDING
                        (RFC 5780) — which has to be understood?

SHARP_BIN_DIR is where sharp-relay is (default target/release);
AMPLAB_NOTE goes into the header. Exits non-zero if an answer was longer
than its request (stun) or a padded request went unanswered (public).
"""

import argparse
import os
import socket
import struct
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BIN = os.environ.get("SHARP_BIN_DIR", os.path.join(ROOT, "target", "release"))
COOKIE = 0x2112A442
SOFTWARE, PADDING, CHANGE_REQUEST, RESPONSE_PORT = 0x8022, 0x0026, 0x0003, 0x0027
PADDED = 128


def attr(t, v):
    return struct.pack("!HH", t, len(v)) + v + b"\0" * ((4 - len(v) % 4) % 4)


def request(attrs, pad_with=None, to=PADDED):
    body = b"".join(attr(t, v) for t, v in attrs)
    if pad_with is not None:
        room = to - 20 - len(body) - 4
        body += attr(pad_with, (b"SHARP-256" + b" " * room)[:room] if pad_with == SOFTWARE else b"\0" * room)
    return struct.pack("!HHI", 1, len(body), COOKIE) + os.urandom(12) + body


def ask(family, addr, build, wait=0.4, loopback=True):
    """Sends `build(local port)` from a fresh socket; returns its length,
    the bytes that came back to the socket within `wait` (every datagram)
    and how many datagrams."""
    s = socket.socket(family, socket.SOCK_DGRAM)
    if loopback:
        s.bind(("::1" if family == socket.AF_INET6 else "127.0.0.1", 0))
    else:
        s.bind(("", 0))
    msg = build(s.getsockname()[1])
    s.sendto(msg, addr)
    s.settimeout(wait)
    back, n = 0, 0
    try:
        while True:
            d, _ = s.recvfrom(4096)
            back += len(d)
            n += 1
    except socket.timeout:
        pass
    s.close()
    return len(msg), back, n


def free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def header(cmd):
    def run(*c):
        try:
            return subprocess.run(c, capture_output=True, text=True).stdout.strip().splitlines()[0]
        except Exception:
            return "?"
    print("# amplab %s" % cmd)
    print("# commit:  %s%s" % (run("git", "-C", ROOT, "rev-parse", "--short", "HEAD"),
                              "" if subprocess.run(["git", "-C", ROOT, "diff", "--quiet", "HEAD", "--", "src"]).returncode == 0
                              else " (with local changes)"))
    if cmd == "stun":
        print("# binaries: %s" % (os.path.relpath(BIN, ROOT) if BIN.startswith(ROOT + os.sep) else BIN))
    for line in os.environ.get("AMPLAB_NOTE", "").splitlines():
        print("# " + line)
    print()


def cmd_stun(_args):
    header("stun")
    port = free_port()
    with tempfile.TemporaryDirectory(prefix="amplab_") as d:
        relay = subprocess.Popen(
            [os.path.join(BIN, "sharp-relay"), "--bind", "127.0.0.1:%d" % free_port(),
             "--stun", "127.0.0.1", "--stun", "::1", "--stun-port", str(port),
             "--identity", os.path.join(d, "relay.key")],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            deadline = time.time() + 10
            while time.time() < deadline:
                line = relay.stdout.readline()
                if line.startswith("STUN:"):
                    break
            else:
                print("sharp-relay did not start its STUN server")
                return 2
            # (Change address needs a second address of the family, which
            # loopback does not have: the server rightly stays silent.)
            shapes = [
                ("bare", lambda _p: []),
                ("change port", lambda _p: [(CHANGE_REQUEST, struct.pack("!I", 0x02))]),
                # To the asking socket's own port, so that the answer is
                # counted here.
                ("response port", lambda p: [(RESPONSE_PORT, struct.pack("!HH", p, 0))]),
            ]
            longer = 0
            for family, host in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
                for name, attrs in shapes:
                    for padded in (False, True):
                        sent, back, n = ask(family, (host, port),
                                            lambda p: request(attrs(p), SOFTWARE if padded else None))
                        verdict = "LONGER" if back > sent else "ok"
                        longer += back > sent
                        print("  %-4s %-14s %-7s %4d B -> %4d B in %d datagram(s)  %.2fx  %s" % (
                            "v4" if family == socket.AF_INET else "v6", name,
                            "padded" if padded else "", sent, back, n, back / sent, verdict))
                        # The server lets one client have 40 answers at once
                        # and 20 a second: stay well inside that.
                        time.sleep(0.06)
            print("stun: %s" % ("no answer longer than its request" if not longer else
                                "%d answer(s) longer than the request" % longer))
            return 1 if longer else 0
        finally:
            relay.terminate()
            relay.wait(10)


def cmd_public(_args):
    header("public")
    servers = [("stun.l.google.com", 19302), ("stun1.l.google.com", 19302), ("stun.cloudflare.com", 3478)]
    failed = 0
    for host, port in servers:
        try:
            addr = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)[0][4]
        except OSError as e:
            print("  %-22s cannot be resolved: %s" % (host, e))
            failed += 1
            continue
        for label, pad in (("bare", None), ("SOFTWARE", SOFTWARE), ("PADDING", PADDING)):
            got = 0
            for _ in range(3):
                _sent, back, _n = ask(socket.AF_INET, addr, lambda _p: request([], pad), wait=2.0,
                                      loopback=False)
                if back:
                    got = back
                    break
            print("  %-22s %-9s %3d B -> %s" % (host, label, 20 if pad is None else PADDED,
                                                "%d B" % got if got else "no answer"))
            if pad == SOFTWARE and not got:
                failed += 1
    print("public: %s" % ("every server answers a request padded with SOFTWARE" if not failed else
                          "%d server(s) did not" % failed))
    return 1 if failed else 0


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("stun")
    sub.add_parser("public")
    args = p.parse_args()
    return {"stun": cmd_stun, "public": cmd_public}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
