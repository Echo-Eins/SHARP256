#!/usr/bin/env python3
"""One node of the Mainline DHT (BEP 5), and the whole of a laboratory's DHT.

Written for the laboratory, and independently of the Rust client it checks:
bencoding, the KRPC messages (ping, find_node, get_peers, announce_peer),
tokens bound to the asker's address, and peers stored per infohash — with
every lookup ending here, since here is all there is. What it does not do is
route: a real node returns the nodes it knows that are closer to the
infohash, and this one knows none.

    dht_node.py --bind 11.9.0.10:6881
"""

import argparse
import hashlib
import hmac
import os
import socket
import struct
import sys
import time


def bdecode(data, i=0):
    c = data[i:i + 1]
    if c == b"i":
        j = data.index(b"e", i)
        return int(data[i + 1:j]), j + 1
    if c == b"l":
        i += 1
        out = []
        while data[i:i + 1] != b"e":
            v, i = bdecode(data, i)
            out.append(v)
        return out, i + 1
    if c == b"d":
        i += 1
        out = {}
        while data[i:i + 1] != b"e":
            k, i = bdecode(data, i)
            v, i = bdecode(data, i)
            out[k] = v
        return out, i + 1
    j = data.index(b":", i)
    n = int(data[i:j])
    return data[j + 1:j + 1 + n], j + 1 + n


def bencode(x):
    if isinstance(x, int):
        return b"i%de" % x
    if isinstance(x, bytes):
        return b"%d:%s" % (len(x), x)
    if isinstance(x, str):
        return bencode(x.encode())
    if isinstance(x, list):
        return b"l" + b"".join(bencode(v) for v in x) + b"e"
    if isinstance(x, dict):
        return b"d" + b"".join(bencode(k) + bencode(v) for k, v in sorted(x.items())) + b"e"
    raise TypeError(x)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", required=True)
    args = ap.parse_args()
    host, port = args.bind.rsplit(":", 1)
    host = host.strip("[]")
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.bind((host, int(port)))
    node_id = os.urandom(20)
    secret = os.urandom(16)
    peers = {}  # infohash -> {(ip, port): time}

    def token(ip):
        return hmac.new(secret, ip.encode(), hashlib.sha1).digest()[:8]

    print(f"dht node {node_id.hex()} on {args.bind}", flush=True)
    while True:
        data, addr = sock.recvfrom(4096)
        ip, sport = addr[0], addr[1]
        try:
            msg, end = bdecode(data)
            if end != len(data) or msg.get(b"y") != b"q":
                continue
            t, q, a = msg[b"t"], msg[b"q"], msg[b"a"]
        except Exception:
            continue

        def reply(r):
            sock.sendto(bencode({"t": t, "y": "r", "r": r}), addr)

        def error(code, text):
            sock.sendto(bencode({"t": t, "y": "e", "e": [code, text]}), addr)

        ih = a.get(b"info_hash")
        print(f"{q.decode(errors='replace')} from {ip}:{sport}" + (f" for {ih.hex()[:8]}" if ih else "") +
              (" (read-only)" if msg.get(b"ro") == 1 else ""), flush=True)
        if q == b"ping":
            reply({"id": node_id})
        elif q == b"find_node":
            reply({"id": node_id, "nodes": b""})
        elif q == b"get_peers" and ih and len(ih) == 20:
            r = {"id": node_id, "token": token(ip), "nodes": b""}
            found = peers.get(ih, {})
            if found:
                # Each in its own family's compact form (BEP 5, BEP 32).
                r["values"] = [
                    socket.inet_pton(socket.AF_INET6 if ":" in p[0] else socket.AF_INET, p[0]) + struct.pack(">H", p[1])
                    for p in found
                ]
            reply(r)
        elif q == b"announce_peer" and ih and len(ih) == 20:
            if a.get(b"token") != token(ip):
                error(203, "bad token")
                continue
            p = sport if a.get(b"implied_port") == 1 else a.get(b"port", 0)
            peers.setdefault(ih, {})[(ip, p)] = time.time()
            print(f"  stored {ip}:{p} under {ih.hex()[:8]}", flush=True)
            reply({"id": node_id})
        else:
            error(204, "method unknown")


if __name__ == "__main__":
    sys.exit(main())
