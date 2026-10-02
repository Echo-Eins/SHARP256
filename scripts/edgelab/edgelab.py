#!/usr/bin/env python3
"""Edge volumes (ROADMAP C2), at the scale one machine takes in minutes.

    scripts/edgelab/edgelab.py disk     # a full disk: before the transfer, and in the middle of it
    scripts/edgelab/edgelab.py many [--files 20000]   # a directory of many small files

`disk`: the receiver's output directory is a tmpfs of its own, 24 MiB.
  1. A file larger than the space: refused before anything is written,
     with the reason, and nothing left behind.
  2. Space taken by someone else in the middle of a transfer: the receiver
     stops with the reason (the write failed), keeps what it has for a
     resume, and when the space is freed the transfer is sent again and
     resumes from there instead of starting over — from what its resume
     state last said was on disk: what was written after that (at most
     `persist_interval`, 2 s, of it) is received again.
`many`: a directory of `--files` files of a few hundred bytes each, in
  folders of a thousand: sent whole, its times and the rate of files a
  second said.

Both ends on loopback in a network namespace of their own, sharp-sender and
sharp-receiver as built (SHARP_BIN_DIR, by default target/debug). Needs
unshare and mount (the script re-executes itself under `unshare -rnm`: root
in a user namespace may mount a tmpfs).
"""

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BIN = os.environ.get("SHARP_BIN_DIR", os.path.join(ROOT, "target", "debug"))
PORT = 5555


def sh(*cmd, check=True):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)}: {r.stderr.strip()}")
    return r


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


class Ends:
    """A receiver on loopback, writing into `out`, and senders to it."""

    def __init__(self, d, out):
        self.d, self.out = d, out
        self.log = os.path.join(d, "receiver.log")
        self.receiver = subprocess.Popen(
            [f"{BIN}/sharp-receiver", "--headless", "--output", out, "--state-dir", f"{d}/rst",
             "--identity", f"{d}/r.key", "--bind", f"127.0.0.1:{PORT}", "--no-nat", "--no-tcp",
             "--no-lan-addresses", "--log-level", "info"],
            stdout=open(self.log, "w"), stderr=subprocess.STDOUT)
        m = wait_for(self.log, r"Senders use: (sh4?-[a-z0-9]+)", 15)
        if not m:
            raise RuntimeError("the receiver did not start:\n" + open(self.log).read())
        self.id = m.group(1)

    def send(self, path, *extra, timeout=120):
        """Runs a sender to completion: (exit code, its output)."""
        r = subprocess.run(
            [f"{BIN}/sharp-sender", path, f"{self.id}@127.0.0.1:{PORT}", "--headless", "--no-nat",
             "--no-tcp", "--identity", f"{self.d}/s.key", "--state-dir", f"{self.d}/sst",
             "--log-level", "warn", *extra],
            capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout + r.stderr

    def close(self):
        self.receiver.terminate()
        try:
            self.receiver.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.receiver.kill()


def payload(path, mb):
    with open(path, "wb") as f:
        for _ in range(mb):
            f.write(os.urandom(1 << 20))
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def cmd_disk(args):
    d = tempfile.mkdtemp(prefix="edgelab.")
    out = os.path.join(d, "out")
    os.makedirs(out)
    sh("mount", "-t", "tmpfs", "-o", "size=24m", "tmpfs", out)
    ends = Ends(d, out)
    results = []
    try:
        # 1. Larger than the space there is.
        big = os.path.join(d, "big.bin")
        payload(big, 32)
        code, said = ends.send(big)
        refused = code != 0 and "not enough disk space" in said
        results.append(("larger than the space", refused and not os.listdir(out),
                        "refused: " + (re.search(r"Transfer failed: (.*)", said) or re.search(r"(.*)", said)).group(1)[:160]
                        if refused else f"exit {code}: {said[-300:]}"))

        # 2. Space taken in the middle of the transfer, then freed.
        mid = os.path.join(d, "mid.bin")
        want = payload(mid, 16)
        filler = os.path.join(d, "filler")
        os.makedirs(filler)
        sender = subprocess.Popen(
            [f"{BIN}/sharp-sender", mid, f"{ends.id}@127.0.0.1:{PORT}", "--headless", "--no-nat", "--no-tcp",
             "--identity", f"{d}/s.key", "--state-dir", f"{d}/sst", "--log-level", "warn",
             "--max-rate", "2M"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        # After the receiver has kept its state a time or two.
        time.sleep(4.5)
        # Someone else's file fills what is left of the disk.
        hog = os.path.join(out, "someone-elses.bin")
        with open(hog, "wb") as f:
            try:
                while True:
                    f.write(b"\0" * (1 << 20))
                    f.flush()
            except OSError:
                pass
        try:
            said, _ = sender.communicate(timeout=120)
        except subprocess.TimeoutExpired:
            sender.kill()
            said, _ = sender.communicate()
        stopped = sender.returncode != 0 and "No space left" in said
        parts = [f for f in os.listdir(out) if f.endswith(".sharp-part")]
        results.append(("the space taken meanwhile", stopped and len(parts) == 1,
                        ("stopped: " + re.search(r"Transfer failed: (.*)", said).group(1)[:160]
                         + f"; kept {parts}") if stopped else f"exit {sender.returncode}: {said[-400:]}"))
        # Freed again: the transfer sent again resumes.
        os.remove(hog)
        code, said = ends.send(mid)
        got = None
        if os.path.exists(os.path.join(out, "mid.bin")):
            got = hashlib.sha256(open(os.path.join(out, "mid.bin"), "rb").read()).hexdigest()
        m = re.search(r"resuming mid\.bin: (\d+) of (\d+) bytes", open(ends.log).read())
        resumed = m is not None and int(m.group(1)) > 0
        results.append(("sent again once freed", code == 0 and got == want and resumed,
                        f"resumed from {int(m.group(1)) / 1e6:.1f} MB of {int(m.group(2)) / 1e6:.1f}, whole"
                        if code == 0 and got == want and resumed else f"exit {code}, whole {got == want}, "
                        f"resumed {m.group(0) if m else 'no'}: {said[-300:]}"))
    finally:
        ends.close()
        sh("umount", out, check=False)
        shutil.rmtree(d, ignore_errors=True)
    failures = 0
    for name, ok, said in results:
        print(f"{'✓' if ok else '✗'} {name:28} {said}", flush=True)
        failures += not ok
    print(f"{failures} not as required" if failures else "all as required")
    return 1 if failures else 0


def cmd_many(args):
    d = tempfile.mkdtemp(prefix="edgelab.")
    src = os.path.join(d, "tree")
    out = os.path.join(d, "out")
    os.makedirs(out)
    n = args.files
    made = time.time()
    for i in range(n):
        folder = os.path.join(src, f"d{i // 1000:04}")
        if i % 1000 == 0:
            os.makedirs(folder)
        with open(os.path.join(folder, f"f{i:07}.txt"), "wb") as f:
            f.write(os.urandom(200 + i % 300))
    made = time.time() - made
    ends = Ends(d, out)
    try:
        start = time.time()
        code, said = ends.send(src, timeout=max(600, n // 20))
        took = time.time() - start
    finally:
        ends.close()
    got = sum(len(fs) for _, _, fs in os.walk(os.path.join(out, "tree")))
    same = code == 0 and got == n
    if same:
        for i in range(0, n, max(1, n // 97)):
            rel = os.path.join(f"d{i // 1000:04}", f"f{i:07}.txt")
            if open(os.path.join(src, rel), "rb").read() != open(os.path.join(out, "tree", rel), "rb").read():
                same = False
    shutil.rmtree(d, ignore_errors=True)
    print(f"{'✓' if same else '✗'} {n} files in {n // 1000 + (n % 1000 > 0)} folders: made in {made:.1f} s, "
          f"sent in {took:.1f} s ({n / took:.0f} files a second), {got} arrived"
          + ("" if same else f" — exit {code}: {said[-400:]}"), flush=True)
    return 0 if same else 1


def main():
    if os.environ.get("EDGELAB_IN") != "1":
        os.execvp("unshare", ["unshare", "-rnm", "env", "EDGELAB_IN=1", sys.executable] + sys.argv)
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("disk")
    many = sub.add_parser("many")
    many.add_argument("--files", type=int, default=20000)
    args = ap.parse_args()
    sh("ip", "link", "set", "lo", "up")
    sys.exit({"disk": cmd_disk, "many": cmd_many}[args.cmd](args))


if __name__ == "__main__":
    main()
