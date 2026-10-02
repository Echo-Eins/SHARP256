#!/usr/bin/env python3
"""Continuous operation (ROADMAP J3): a relay and a receiver that run for as
long as asked while senders come and go, and what the two hold meanwhile.

    scripts/soak/soak.py [--minutes 10] [--csv FILE]

On loopback in a network namespace of its own: sharp-relay and
sharp-receiver start once and run throughout; senders follow one another
without a pause, in turn
  * straight to the receiver,
  * through the relay (introduced by it, then carried or not),
  * cut off in the middle (killed) and sent again, to resume,
with files of a few hundred kilobytes to a few megabytes, every one checked
whole on arrival. Every ten seconds the relay's and the receiver's resident
memory, open file descriptors and threads are written down (`--csv`); at
the end: transfers done and failed, and how each measure moved over the
second half of the run — where a leak shows as a steady rise.

Weeks of it are a server's job (the same script, `--minutes 40320`); here
it runs for minutes. The binaries are SHARP_BIN_DIR's (by default
target/debug). Needs unshare (the script re-executes itself under
`unshare -rn`).
"""

import argparse
import hashlib
import os
import random
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BIN = os.environ.get("SHARP_BIN_DIR", os.path.join(ROOT, "target", "debug"))


def wait_for(path, pattern, seconds):
    end = time.time() + seconds
    while time.time() < end:
        try:
            m = re.search(pattern, open(path).read())
            if m:
                return m
        except OSError:
            pass
        time.sleep(0.1)
    return None


def measure(pid):
    """(resident bytes, open descriptors, threads) of a process."""
    try:
        status = open(f"/proc/{pid}/status").read()
        rss = int(re.search(r"VmRSS:\s+(\d+) kB", status).group(1)) * 1024
        threads = int(re.search(r"Threads:\s+(\d+)", status).group(1))
        fds = len(os.listdir(f"/proc/{pid}/fd"))
        return rss, fds, threads
    except (OSError, AttributeError):
        return None


def slope(points):
    """Least-squares slope of (t, v) points, per hour."""
    if len(points) < 2:
        return 0.0
    n = len(points)
    mt = sum(t for t, _ in points) / n
    mv = sum(v for _, v in points) / n
    den = sum((t - mt) ** 2 for t, _ in points)
    return 0.0 if den == 0 else sum((t - mt) * (v - mv) for t, v in points) / den * 3600


def main():
    if os.environ.get("SOAK_IN") != "1":
        os.execvp("unshare", ["unshare", "-rn", "env", "SOAK_IN=1", sys.executable] + sys.argv)
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--minutes", type=float, default=10.0)
    ap.add_argument("--csv", help="where the measurements go (default: the laboratory's directory, removed)")
    args = ap.parse_args()
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    d = tempfile.mkdtemp(prefix="soak.")
    out = os.path.join(d, "out")
    os.makedirs(out)
    relay_log, recv_log = os.path.join(d, "relay.log"), os.path.join(d, "receiver.log")
    relay = subprocess.Popen(
        [f"{BIN}/sharp-relay", "--bind", "127.0.0.1:5560", "--identity", f"{d}/relay.key", "--log", "warn"],
        stdout=open(relay_log, "w"), stderr=subprocess.STDOUT)
    m = wait_for(relay_log, r"Receivers: --relay (sh4?-\S+?)@", 15)
    if not m:
        print("the relay did not start:\n" + open(relay_log).read())
        return 1
    relay_id = m.group(1)
    receiver = subprocess.Popen(
        [f"{BIN}/sharp-receiver", "--headless", "--output", out, "--state-dir", f"{d}/rst",
         "--identity", f"{d}/r.key", "--bind", "127.0.0.1:5555", "--no-nat", "--no-tcp",
         "--no-lan-addresses", "--relay", f"{relay_id}@127.0.0.1:5560", "--log-level", "warn"],
        stdout=open(recv_log, "w"), stderr=subprocess.STDOUT)
    m = wait_for(recv_log, r"Senders use: (sh4?-[a-z0-9]+)", 15)
    if not m:
        print("the receiver did not start:\n" + open(recv_log).read())
        return 1
    rid = m.group(1)
    csv_path = args.csv or os.path.join(d, "soak.csv")
    csv = open(csv_path, "w")
    csv.write("seconds,relay_rss,relay_fds,relay_threads,receiver_rss,receiver_fds,receiver_threads,done,failed\n")
    start = time.time()
    end = start + args.minutes * 60
    next_sample = start
    samples = []
    done = failed = 0
    failures = []
    rng = random.Random(1)
    n = 0
    try:
        while time.time() < end:
            n += 1
            kind = ("direct", "relay", "cut")[n % 3]
            size = rng.randint(200, 4000) * 1024
            data = os.path.join(d, f"f{n}.bin")
            with open(data, "wb") as f:
                f.write(os.urandom(size))
            want = hashlib.sha256(open(data, "rb").read()).hexdigest()
            target = f"{rid}@127.0.0.1:5555" if kind != "relay" else rid
            cmd = [f"{BIN}/sharp-sender", data, target, "--headless", "--no-nat", "--no-tcp",
                   "--identity", f"{d}/s.key", "--state-dir", f"{d}/sst", "--log-level", "warn",
                   "--max-rate", "40M"]
            if kind == "relay":
                cmd += ["--relay", f"{relay_id}@127.0.0.1:5560"]
            if kind == "cut":
                p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                time.sleep(0.15)
                p.send_signal(signal.SIGKILL)
                p.wait()
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            got = os.path.join(out, f"f{n}.bin")
            whole = os.path.exists(got) and hashlib.sha256(open(got, "rb").read()).hexdigest() == want
            if r.returncode == 0 and whole:
                done += 1
            else:
                failed += 1
                failures.append(f"#{n} {kind}: exit {r.returncode}, whole {whole}: {(r.stdout + r.stderr)[-300:]}")
            for path in (data, got):
                try:
                    os.remove(path)
                except OSError:
                    pass
            now = time.time()
            if now >= next_sample:
                a, b = measure(relay.pid), measure(receiver.pid)
                if a is None or b is None:
                    failures.append(f"at {now - start:.0f} s the relay or the receiver is gone")
                    break
                samples.append((now - start, a, b))
                csv.write(",".join(str(x) for x in (round(now - start), *a, *b, done, failed)) + "\n")
                csv.flush()
                next_sample = now + 10
    finally:
        for p in (receiver, relay):
            p.terminate()
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
        csv.close()
    half = [s for s in samples if s[0] >= samples[-1][0] / 2] if samples else []
    names = ("resident memory", "descriptors", "threads")
    print(f"{args.minutes:g} minutes: {done} transfers whole, {failed} not; {len(samples)} measurements")
    for who, k in (("relay", 1), ("receiver", 2)):
        if not half:
            break
        parts = []
        for i, name in enumerate(names):
            pts = [(s[0], s[k][i]) for s in half]
            first, last = pts[0][1], pts[-1][1]
            unit = (lambda v: f"{v / 1e6:.1f} MB") if i == 0 else (lambda v: f"{v:.0f}")
            parts.append(f"{name} {unit(first)} → {unit(last)} ({unit(slope(pts))}/h)")
        print(f"  {who:8} over the second half: " + "; ".join(parts))
    for f in failures[:10]:
        print("  " + f)
    if not args.csv:
        shutil.rmtree(d, ignore_errors=True)
    else:
        print(f"measurements in {csv_path}")
    return 0 if failed == 0 and samples else 1


if __name__ == "__main__":
    sys.exit(main())
