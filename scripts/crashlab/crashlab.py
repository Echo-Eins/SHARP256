#!/usr/bin/env python3
"""Power cuts under a transfer: what does the receiver keep, and is it true?

After a power cut a disk holds only what was flushed to it. The receiver
keeps three kinds of things there: the file (or directory tree) being
received, the resume state that says which of its bytes are already on
disk, and — once it is verified — the result under its final name. The
promise is: after a cut at any moment, the transfer resumes when the power
is back and completes correctly (nothing here stands in its way: the
source is unchanged, the disk has room), never from bytes that the state
claims but the disk lost; and never is anything under a final name that is
not what was sent.

Two independent instruments, because a power cut loses two kinds of thing:

* Data not flushed with fsync. LazyFS (a FUSE file system from INESC TEC,
  https://github.com/dsrhaslab/lazyfs) keeps written data in a cache of its
  own and puts it on the disk under it only when fsync says so;
  "lazyfs::clear-cache" throws away what was not flushed, and
  "lazyfs::crash" does that at a chosen operation and kills the file
  system. The receiver writes its output and its state on a LazyFS mount.

* Names not flushed with an fsync of their directory: a file created,
  renamed into place or removed may be back as it was after a power cut
  unless the directory was flushed. LazyFS does not model this (it passes
  directory operations to the disk at once), so it is checked by an audit
  of the receiver's system calls under strace: every name that matters is
  flushed, in an order that keeps the promise, before the result is
  reported.

    crashlab.py cut [--kind file|tree] [--points N]   power cut at N moments of a transfer, then a restart
    crashlab.py at                                     LazyFS dies at chosen operations (the flush of a state
                                                       file, the rename of a partial file into place, ...)
    crashlab.py audit                                  the receiver's system calls during a transfer

Needs Linux, python3, fusermount3, the binaries (SHARP_BIN_DIR, default
target/release), LAZYFS (the lazyfs executable) for cut and at, STRACE (a
strace build) for audit; CRASHLAB_NOTE goes into the log's header (what
build this is, if not the one checked out). No root: LazyFS is a user mount. Each scenario
prints what it found and exits non-zero if any promise was broken.
"""

import argparse
import hashlib
import json
import os
import random
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BIN = os.environ.get("SHARP_BIN_DIR", os.path.join(ROOT, "target", "release"))
LAZYFS = os.environ.get("LAZYFS", "lazyfs")
STRACE = os.environ.get("STRACE", "strace")
PART = ".sharp-part"
ANSI = re.compile(r"\x1b\[[0-9;]*m")
# Slow enough that a transfer lasts several persist intervals (2 s) and the
# file system's cache never holds more than it can.
RATE = os.environ.get("CRASHLAB_RATE", "64M")
FILE_MB = int(os.environ.get("CRASHLAB_FILE_MB", "48"))


def log(*a):
    print(*a, flush=True)


# ---------------------------------------------------------------------------
# What is sent, and comparing what arrived with it
# ---------------------------------------------------------------------------

def make_file(path, mb):
    rnd = random.Random(20260930)
    with open(path, "wb") as f:
        for _ in range(mb):
            f.write(rnd.randbytes(1 << 20))


def make_tree(root):
    """Nested directories, empty ones, empty files and files of every size
    up to a quarter of a megabyte, with modes and times of their own."""
    rnd = random.Random(20260930)
    modes = [0o644, 0o600, 0o640, 0o755, 0o400]
    dirs = [root]
    os.makedirs(root)
    for i in range(24):
        parent = rnd.choice(dirs)
        d = os.path.join(parent, "d%02d" % i)
        os.mkdir(d)
        dirs.append(d)
    for i in range(300):
        d = rnd.choice(dirs)
        size = 0 if i % 17 == 0 else rnd.randint(1, 256 << 10)
        p = os.path.join(d, "f%03d.bin" % i)
        with open(p, "wb") as f:
            f.write(rnd.randbytes(size))
        os.chmod(p, rnd.choice(modes))
        t = 1_600_000_000 + rnd.randint(0, 10**8)
        os.utime(p, ns=(t * 10**9 + 123, t * 10**9 + rnd.randint(0, 10**9 - 1)))
    for d in reversed(dirs[1:]):
        os.chmod(d, rnd.choice([0o755, 0o750, 0o700]))
        t = 1_500_000_000 + rnd.randint(0, 10**8)
        os.utime(d, ns=(t * 10**9, t * 10**9 + 555))


def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def describe(root, times=True):
    """Everything about a tree the receiver promises to reproduce: names,
    kinds, contents, permission bits and (with `times`) modification
    times."""
    out = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            p = os.path.join(dirpath, name)
            st = os.lstat(p)
            rel = os.path.relpath(p, root)
            kind = "d" if stat.S_ISDIR(st.st_mode) else "f"
            out[rel] = (
                kind,
                digest(p) if kind == "f" else None,
                stat.S_IMODE(st.st_mode),
                st.st_mtime_ns if times else None,
            )
    return out


def same(src, dst, kind, times=True):
    """None if `dst` is what was sent, else what differs. LazyFS does not
    keep times set through a descriptor (futimens), so on it they are not
    compared; the audit, on an ordinary file system, compares them."""
    if kind == "file":
        if not os.path.isfile(dst):
            return "not a file"
        return None if digest(src) == digest(dst) else "different contents"
    if not os.path.isdir(dst):
        return "not a directory"
    # A tree's own modes may keep the owner out; look at it as it is.
    a, b = describe(src, times), describe(dst, times)
    if a.keys() != b.keys():
        return "entries differ: %s" % sorted(set(a) ^ set(b))[:5]
    for rel in a:
        if a[rel] != b[rel]:
            return "%s differs: sent %s, have %s" % (rel, a[rel], b[rel])
    return None


ON_LAZYFS = False


def finals(out):
    """What is under a final name in the output directory."""
    return [os.path.join(out, n) for n in sorted(os.listdir(out)) if PART not in n]


# ---------------------------------------------------------------------------
# LazyFS
# ---------------------------------------------------------------------------

class LazyFs:
    def __init__(self, work):
        self.root = os.path.join(work, "disk")
        self.mnt = os.path.join(work, "mnt")
        self.fifo = os.path.join(work, "faults.fifo")
        self.log = os.path.join(work, "lazyfs.log")
        self.config = os.path.join(work, "lazyfs.toml")
        self.proc = None
        for d in (self.root, self.mnt):
            os.makedirs(d, exist_ok=True)
        with open(self.config, "w") as f:
            f.write(
                '[faults]\nfifo_path="%s"\n[cache]\napply_eviction=false\n'
                '[cache.simple]\ncustom_size="768mb"\nblocks_per_page=1\n'
                '[filesystem]\nlog_all_operations=false\nlogfile="%s"\n' % (self.fifo, self.log)
            )

    def mount(self):
        # LazyFS (fa7d32e) takes an argument with "-o" anywhere in it for
        # an option of its own, and then looks for config/default.toml
        # instead of the configuration given: the work directories are named
        # "crashlab_..." so that no random suffix after a dash starts with o.
        for attempt in range(3):
            if os.path.exists(self.log):
                os.remove(self.log)
            out = open(self.log + ".out", "a")
            self.proc = subprocess.Popen(
                [LAZYFS, self.mnt, "--config-path", self.config,
                 "-o", "modules=subdir", "-o", "subdir=" + self.root, "-f"],
                stdout=out, stderr=subprocess.STDOUT,
            )
            for _ in range(200):
                if os.path.ismount(self.mnt):
                    return
                if self.proc.poll() is not None:
                    break
                time.sleep(0.05)
            self.unmount()
        raise RuntimeError("LazyFS did not mount (%s)" % self.log)

    def command(self, cmd):
        with open(self.fifo, "w") as f:
            f.write(cmd + "\n")

    def logged(self, needle):
        try:
            with open(self.log) as f:
                return needle in f.read()
        except FileNotFoundError:
            return False

    def clear_cache(self):
        """What a power cut does to data: whatever was not flushed is gone."""
        before = open(self.log).read().count("cache is cleared") if os.path.exists(self.log) else 0
        self.command("lazyfs::clear-cache")
        for _ in range(200):
            if os.path.exists(self.log) and open(self.log).read().count("cache is cleared") > before:
                return
            time.sleep(0.05)
        raise RuntimeError("LazyFS did not clear its cache")

    def crash_at(self, timing, op, from_rgx=None, to_rgx=None):
        cmd = "lazyfs::crash::timing=%s::op=%s" % (timing, op)
        if from_rgx:
            cmd += "::from_rgx=" + from_rgx
        if to_rgx:
            cmd += "::to_rgx=" + to_rgx
        self.command(cmd)

    def alive(self):
        return self.proc is not None and self.proc.poll() is None

    def unmount(self):
        subprocess.run(["fusermount3", "-u", "-z", self.mnt], capture_output=True)
        if self.proc is not None:
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        self.proc = None


# ---------------------------------------------------------------------------
# The programs
# ---------------------------------------------------------------------------

class Receiver:
    def __init__(self, work, out, state, port, prefix=None):
        self.args = [os.path.join(BIN, "sharp-receiver"), "--headless", "--no-nat",
                     "--bind", "127.0.0.1:%d" % port, "--output", out, "--state-dir", state,
                     "--identity", os.path.join(work, "receiver.key"), "--log-level", "debug"]
        self.prefix = prefix or []
        self.logpath = os.path.join(work, "receiver.log")
        self.proc = None
        self.id = subprocess.run(self.args[:1] + ["--identity", self.args[self.args.index("--identity") + 1], "--id"],
                                 capture_output=True, text=True, check=True).stdout.strip()

    def start(self):
        out = open(self.logpath, "a")
        out.write("=== start %.3f\n" % time.time())
        out.flush()
        self.proc = subprocess.Popen(self.prefix + self.args, stdout=out, stderr=subprocess.STDOUT)

    def text(self):
        with open(self.logpath, errors="replace") as f:
            return ANSI.sub("", f.read())

    def resumed(self):
        """(bytes on disk, of how many) each time a transfer was resumed."""
        return [(int(a), int(b)) for a, b in
                re.findall(r"resuming [^\n]*?: (\d+) of (\d+) bytes already on disk", self.text())]

    def kill(self):
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGKILL)
            self.proc.wait()

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGINT)
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.kill()


class SenderRun:
    def __init__(self, work, src, receiver, port, append=False):
        self.logpath = os.path.join(work, "sender.log")
        state = os.path.join(work, "sender-state")
        os.makedirs(state, exist_ok=True)
        self.proc = subprocess.Popen(
            [os.path.join(BIN, "sharp-sender"), src, "%s@127.0.0.1:%d" % (receiver.id, port),
             "--headless", "--no-nat", "--max-rate", RATE, "--state-dir", state,
             "--identity", os.path.join(work, "sender.key"), "--log-level", "info"],
            stdout=open(self.logpath, "a" if append else "w"), stderr=subprocess.STDOUT,
        )
        self.started = time.time()

    def wait(self, timeout):
        try:
            return self.proc.wait(timeout)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
            return None



def free_port():
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def sources(work, kind):
    src_dir = os.path.join(work, "src")
    os.makedirs(src_dir, exist_ok=True)
    if kind == "file":
        src = os.path.join(src_dir, "data.bin")
        if not os.path.exists(src):
            make_file(src, FILE_MB)
    else:
        src = os.path.join(src_dir, "tree")
        if not os.path.exists(src):
            make_tree(src)
    return src


def check_after_cut(out, state, src, kind):
    """What a power cut may leave: under a final name only what was sent;
    state files that are whole JSON or absent. Returns (broken, notes)."""
    broken, notes = [], []
    for p in finals(out):
        why = same(src, p, kind, times=not ON_LAZYFS)
        if why:
            broken.append("%s under a final name, and %s" % (os.path.basename(p), why))
    for name in sorted(os.listdir(state)) if os.path.isdir(state) else []:
        p = os.path.join(state, name)
        if name.endswith(".json"):
            try:
                with open(p) as f:
                    json.load(f)
            except Exception as e:
                notes.append("state %s unreadable (%s): its progress is lost" % (name, type(e).__name__))
    return broken, notes


def check_after_restart(out, src, kind, exit_code):
    """After the power came back: nothing under a final name that is not
    what was sent, and the transfer completed — nothing here makes that
    impossible (the source is there, the disk has room), so a transfer that
    only fails, however openly, has not kept the promise either."""
    broken = []
    if exit_code != 0:
        broken.append("the transfer did not complete after the power came back (sender exit %s)" % exit_code)
    results = finals(out)
    good = [p for p in results if same(src, p, kind, times=not ON_LAZYFS) is None]
    for p in results:
        why = same(src, p, kind, times=not ON_LAZYFS)
        if why:
            broken.append("%s under a final name, and %s" % (os.path.basename(p), why))
    if exit_code == 0 and not good:
        broken.append("the sender reports success and nothing correct is under a final name")
    return broken


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------

def one_cut(kind, when, calibrated, keep):
    """A transfer, a power cut at `when` (seconds after the sender started,
    or a phase name), the receiver restarted on what survived."""
    work = tempfile.mkdtemp(prefix="crashlab_")
    fs = LazyFs(work)
    fs.mount()
    out, state = os.path.join(fs.mnt, "out"), os.path.join(fs.mnt, "state")
    os.makedirs(out)
    os.makedirs(state)
    src = sources(work, kind)
    port = free_port()
    r = Receiver(work, out, state, port)
    r.start()
    time.sleep(0.5)
    s = SenderRun(work, src, r, port)
    phase = None
    if isinstance(when, str):
        # Wait for the receiver to say it is in that phase.
        needle = {"verifying": "received; verifying", "stored": "stored as"}[when]
        deadline = time.time() + calibrated * 3 + 30
        while needle not in r.text() and time.time() < deadline and s.proc.poll() is None:
            time.sleep(0.005)
        phase = when
    else:
        time.sleep(max(0.0, s.started + when - time.time()))
    finished_before = s.proc.poll() is not None
    # The cut: the process first, so that nothing is written after the
    # cache is cleared; then everything it did not flush is gone.
    r.kill()
    fs.clear_cache()
    broken, notes = check_after_cut(out, state, src, kind)
    # Power back: the file system as the disk had it, the receiver again.
    fs.unmount()
    fs.mount()
    r.start()
    code = s.wait(calibrated * 4 + 120)
    broken += check_after_restart(out, src, kind, code)
    copies = len(finals(out))
    resumed = r.resumed()
    r.stop()
    fs.unmount()
    label = phase or "%.1f s" % when
    verdict = "BROKEN" if broken else "kept"
    detail = []
    if finished_before:
        detail.append("the transfer had already ended")
    if resumed:
        detail.append("resumed with %d of %d B on disk" % resumed[-1])
    if copies > 1:
        # The result had reached its final name, but not the sender's
        # ears: received again, under the next free name.
        detail.append("%d whole copies under final names" % copies)
    detail += notes + broken
    log("  %-10s cut at %-10s -> %s%s" % (kind, label, verdict, ("  (" + "; ".join(detail) + ")") if detail else ""))
    if keep or broken:
        log("    kept for inspection: %s" % work)
    else:
        shutil.rmtree(work, ignore_errors=True)
    return not broken


def calibrate(kind):
    """How long an uninterrupted transfer takes, on LazyFS."""
    work = tempfile.mkdtemp(prefix="crashlab_")
    fs = LazyFs(work)
    fs.mount()
    out, state = os.path.join(fs.mnt, "out"), os.path.join(fs.mnt, "state")
    os.makedirs(out)
    os.makedirs(state)
    src = sources(work, kind)
    port = free_port()
    r = Receiver(work, out, state, port)
    r.start()
    time.sleep(0.5)
    s = SenderRun(work, src, r, port)
    code = s.wait(300)
    took = time.time() - s.started
    ok = code == 0 and all(same(src, p, kind, times=False) is None for p in finals(out)) and finals(out)
    r.stop()
    fs.unmount()
    shutil.rmtree(work, ignore_errors=True)
    if not ok:
        raise RuntimeError("an uninterrupted %s transfer did not complete (exit %s)" % (kind, code))
    return took


def cmd_cut(args):
    global ON_LAZYFS
    ON_LAZYFS = True
    kinds = ["file", "tree"] if args.kind == "both" else [args.kind]
    failures = 0
    for kind in kinds:
        took = calibrate(kind)
        log("%s: an uninterrupted transfer takes %.1f s on LazyFS" % (kind, took))
        points = [took * (i + 0.5) / args.points for i in range(args.points)]
        for when in points + ["verifying", "stored"]:
            if not one_cut(kind, when, took, args.keep):
                failures += 1
    log("cut: %s" % ("every promise kept" if failures == 0 else "%d BROKEN" % failures))
    return 1 if failures else 0


# Operations to die at: (kind, timing, op, from, to, what it is). LazyFS
# (as of fa7d32e) matches a rename by its destination only, and only when a
# source pattern is given as well, which it then ignores; so renames are
# named by where they go, with ".*" for the source.
AT = [
    # (kind, timing, op, from, to, armed when, what it is): "start" arms the
    # crash before the transfer begins, "middle" halfway through it, so that
    # it strikes a state file or a flush that follows others. Temporary
    # names are matched as this code makes them and as the code before
    # file::durable did (without the random part).
    ("file", "before", "fsync", r"/state/recv-[^/]*\.json(\.[0-9a-f]+)?\.tmp$", None, "middle", "before a state file is flushed"),
    ("file", "after", "rename", ".*", r"/state/recv-[^/]*\.json$", "middle", "right after a state file is renamed into place"),
    ("file", "before", "fsync", r"\.sharp-part$", None, "middle", "before the partial file is flushed"),
    # The final move is renameat2 with RENAME_NOREPLACE, which LazyFS does
    # not take; the receiver then links the file under its new name and
    # removes the old one.
    ("file", "before", "rename", ".*", r"/out/data\.bin$", "start", "before the partial file is renamed into place"),
    ("file", "after", "link", ".*", r"/out/data\.bin$", "start", "right after it is linked into place"),
    ("tree", "before", "fsync", r"/state/recv-[^/]*\.manifest(\.[0-9a-f]+)?\.tmp$", None, "start", "before the manifest is flushed"),
    ("tree", "before", "fsync", r"\.sharp-part/.+", None, "middle", "before a file of the tree is flushed"),
    ("tree", "before", "rename", ".*", r"/out/tree$", "start", "before the tree is renamed into place"),
    ("tree", "after", "rename", ".*", r"/out/tree$", "start", "right after it is renamed into place"),
]


def one_at(kind, timing, op, from_rgx, to_rgx, armed, what, keep, took):
    work = tempfile.mkdtemp(prefix="crashlab_")
    fs = LazyFs(work)
    fs.mount()
    out, state = os.path.join(fs.mnt, "out"), os.path.join(fs.mnt, "state")
    os.makedirs(out)
    os.makedirs(state)
    src = sources(work, kind)
    port = free_port()
    r = Receiver(work, out, state, port)
    r.start()
    time.sleep(0.5)
    if armed == "start":
        fs.crash_at(timing, op, from_rgx, to_rgx)
    s = SenderRun(work, src, r, port)
    if armed == "middle":
        time.sleep(took / 2)
        fs.crash_at(timing, op, from_rgx, to_rgx)
    deadline = time.time() + 300
    while fs.alive() and time.time() < deadline and s.proc.poll() is None:
        time.sleep(0.05)
    crashed = not fs.alive()
    r.kill()
    fs.unmount()
    # Power back.
    fs.mount()
    broken, notes = check_after_cut(out, state, src, kind)
    r.start()
    restarted = False
    if crashed and s.proc.poll() is not None:
        # The receiver saw its file system go and told the sender, which
        # stopped with its state kept; the user starts it again.
        s = SenderRun(work, src, r, port, append=True)
        restarted = True
    code = s.wait(400)
    broken += check_after_restart(out, src, kind, code)
    copies = len(finals(out))
    resumed = r.resumed()
    r.stop()
    fs.unmount()
    detail = []
    if not crashed:
        detail.append("NOT REACHED: the operation never happened")
    if restarted:
        detail.append("the sender had stopped and was started again")
    if resumed:
        detail.append("resumed with %d of %d B on disk" % resumed[-1])
    if copies > 1:
        # The result had reached its final name, but not the sender's
        # ears: received again, under the next free name.
        detail.append("%d whole copies under final names" % copies)
    detail += notes + broken
    bad = broken or not crashed
    log("  %-4s died %-50s -> %s%s" % (kind, what, "BROKEN" if broken else ("?" if not crashed else "kept"),
                                       ("  (" + "; ".join(detail) + ")") if detail else ""))
    if keep or bad:
        log("    kept for inspection: %s" % work)
    else:
        shutil.rmtree(work, ignore_errors=True)
    return not bad


def cmd_at(args):
    global ON_LAZYFS
    ON_LAZYFS = True
    took = {kind: calibrate(kind) for kind in ("file", "tree")}
    for kind, t in took.items():
        log("%s: an uninterrupted transfer takes %.1f s on LazyFS" % (kind, t))
    chosen = [a for i, a in enumerate(AT) if args.only is None or i in args.only]
    failures = sum(0 if one_at(*a, keep=args.keep, took=took[a[0]]) else 1 for a in chosen)
    log("at: %s" % ("every promise kept" if failures == 0 else "%d BROKEN or not reached" % failures))
    return 1 if failures else 0


# ---------------------------------------------------------------------------
# The system call audit
# ---------------------------------------------------------------------------

LINE = re.compile(r"^(?P<pid>\d+)\s+(?P<t>\d+\.\d+)\s+(?P<call>\w+)\((?P<args>.*)\)\s+=\s+(?P<ret>-?\d+|\?)")
STARTED = re.compile(r"^(?P<pid>\d+)\s+(?P<t>\d+\.\d+)\s+(?P<call>\w+)\((?P<args>.*) <unfinished \.\.\.>$")
RESUMED = re.compile(r"^(?P<pid>\d+)\s+(?P<t>\d+\.\d+)\s+<\.\.\. (?P<call>\w+) resumed>(?P<args>.*)\)\s+=\s+(?P<ret>-?\d+|\?)")
FDPATH = re.compile(r"(-?\d+)<([^>]*)>")
STRPATH = re.compile(r'"((?:[^"\\]|\\.)*)"')


def parse_trace(path):
    """(time, call, [paths the call names or its descriptors point to], args),
    for the calls that succeeded. A call another thread interrupted in the
    trace ("<unfinished ...>", then "<... resumed>") counts when it returned."""
    events = []
    pending = {}
    with open(path, errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            m = LINE.match(line)
            if m is None:
                started = STARTED.match(line)
                if started:
                    pending[started.group("pid")] = (started.group("call"), started.group("args"))
                    continue
                resumed = RESUMED.match(line)
                if resumed is None or resumed.group("pid") not in pending:
                    continue
                call, head = pending.pop(resumed.group("pid"))
                t, a, ret = resumed.group("t"), head + resumed.group("args"), resumed.group("ret")
            else:
                call, t, a, ret = m.group("call"), m.group("t"), m.group("args"), m.group("ret")
            if ret == "?" or int(ret) < 0:
                continue
            # Descriptor paths first, then any string arguments (renameat2
            # names its paths as strings, relative to AT_FDCWD).
            paths = [p for _, p in FDPATH.findall(a)]
            paths += [bytes(x, "utf-8").decode("unicode_escape") for x in STRPATH.findall(a)]
            events.append((float(t), call, paths, a))
    events.sort(key=lambda e: e[0])
    return events


MODIFY = {"write", "pwrite64", "pwritev", "pwritev2", "writev", "ftruncate", "fallocate",
          "fchmod", "futimens", "utimensat", "fchmodat"}
SYNC = {"fsync", "fdatasync"}
RENAME = {"rename", "renameat", "renameat2"}


def absolute(p, cwd):
    return os.path.normpath(p if os.path.isabs(p) else os.path.join(cwd, p))


def audit_trace(events, out, state, cwd, reported_at):
    """Every rename into a place that matters: the thing renamed flushed
    after its last change, the directory flushed after the rename, and —
    for the result — before the receiver reported it stored."""
    problems = []
    renames = []
    for i, (t, call, paths, a) in enumerate(events):
        if call in RENAME and len(paths) >= 2:
            src, dst = absolute(paths[-2], cwd), absolute(paths[-1], cwd)
            renames.append((i, t, src, dst))
    checked = 0
    for i, t, src, dst in renames:
        into_state = os.path.dirname(dst) == state
        into_out = os.path.dirname(dst) == out and PART not in os.path.basename(dst)
        if not (into_state or into_out):
            continue
        checked += 1
        # What was renamed: a file, or a tree (every entry below it).
        below = [src] + ([] if not os.path.isdir(dst) else
                         [os.path.join(src, os.path.relpath(os.path.join(d, n), dst))
                          for d, dirs, files in os.walk(dst) for n in dirs + files])
        for entry in below:
            last_change, last_sync = None, None
            for j in range(i):
                tj, callj, pathsj, _ = events[j]
                if not pathsj or absolute(pathsj[0], cwd) != entry:
                    continue
                if callj in MODIFY:
                    last_change = j
                if callj in SYNC:
                    last_sync = j
            if last_change is not None and (last_sync is None or last_sync < last_change):
                problems.append("%s renamed to %s with changes to it not flushed" % (entry, dst))
                break
        parent = os.path.dirname(dst)
        synced = [tj for tj, callj, pathsj, _ in events[i + 1:]
                  if callj in SYNC and pathsj and absolute(pathsj[0], cwd) == parent]
        if not synced:
            problems.append("rename to %s never flushed with its directory" % dst)
        elif into_out and reported_at is not None and synced[0] > reported_at:
            problems.append("%s reported stored before its directory was flushed" % dst)
    return checked, problems


def cmd_audit(args):
    failures = 0
    for kind in ["file", "tree"]:
        work = tempfile.mkdtemp(prefix="crashlab_audit_")
        out, state = os.path.join(work, "out"), os.path.join(work, "state")
        os.makedirs(out)
        os.makedirs(state)
        src = sources(work, kind)
        port = free_port()
        trace = os.path.join(work, "receiver.strace")
        prefix = [STRACE, "-f", "-ttt", "-y", "-qq", "-o", trace, "-e",
                  "trace=openat,creat,write,pwrite64,pwritev,writev,ftruncate,fallocate,fsync,fdatasync,"
                  "rename,renameat,renameat2,unlink,unlinkat,mkdir,mkdirat,fchmod,fchmodat,utimensat"]
        r = Receiver(work, out, state, port, prefix=prefix)
        r.start()
        time.sleep(1.0)
        s = SenderRun(work, src, r, port)
        code = s.wait(300)
        time.sleep(0.5)
        r.stop()
        text = r.text()
        m = re.search(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+)Z\s+INFO[^\n]*stored as", text)
        reported_at = None
        if m:
            import datetime
            reported_at = datetime.datetime.strptime(m.group(1)[:26], "%Y-%m-%dT%H:%M:%S.%f").replace(
                tzinfo=datetime.timezone.utc).timestamp()
        events = parse_trace(trace)
        checked, problems = audit_trace(events, out, state, os.getcwd(), reported_at)
        if code != 0:
            problems.append("the transfer failed (exit %s)" % code)
        # On an ordinary file system the result is compared in full, times
        # included.
        differs = [same(src, p, kind) for p in finals(out)]
        if not differs or any(differs):
            problems.append("the result is not what was sent: %s" % differs)
        if reported_at is None:
            problems.append("the receiver never reported the result stored")
        log("  %-4s %d system calls, %d renames into place checked -> %s" % (
            kind, len(events), checked, "kept" if not problems else "BROKEN"))
        for p in problems[:20]:
            log("    " + p)
        if problems:
            failures += 1
            log("    kept for inspection: %s" % work)
        else:
            shutil.rmtree(work, ignore_errors=True)
    log("audit: %s" % ("every promise kept" if failures == 0 else "%d BROKEN" % failures))
    return 1 if failures else 0


def header(args):
    def run(*cmd):
        try:
            return subprocess.run(cmd, capture_output=True, text=True).stdout.strip().splitlines()[0]
        except Exception:
            return "?"
    log("# crashlab %s" % " ".join(sys.argv[1:]))
    log("# commit:  %s%s" % (run("git", "-C", ROOT, "rev-parse", "--short", "HEAD"),
                            "" if subprocess.run(["git", "-C", ROOT, "diff", "--quiet", "HEAD", "--", "src"]).returncode == 0
                            else " (with local changes)"))
    log("# binaries: %s" % (os.path.relpath(BIN, ROOT) if BIN.startswith(ROOT + os.sep) else BIN))
    for b in ("sharp-sender", "sharp-receiver"):
        log("# %s sha256 %s" % (b, digest(os.path.join(BIN, b))[:16]))
    log("# kernel:  %s" % run("uname", "-sr"))
    if args.cmd in ("cut", "at"):
        log("# lazyfs:  commit %s" % run("git", "-C", os.path.dirname(os.path.realpath(LAZYFS)), "rev-parse", "--short", "HEAD"))
    if args.cmd == "audit":
        log("# strace:  %s" % run(STRACE, "-V"))
    log("# rate %s, file %d MiB" % (RATE, FILE_MB))
    for line in os.environ.get("CRASHLAB_NOTE", "").splitlines():
        log("# " + line)
    log("")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("cut")
    c.add_argument("--kind", choices=["file", "tree", "both"], default="both")
    c.add_argument("--points", type=int, default=8)
    c.add_argument("--keep", action="store_true")
    a = sub.add_parser("at")
    a.add_argument("--keep", action="store_true")
    a.add_argument("--only", type=int, nargs="*", help="numbers of the operations to die at (from 0)")
    sub.add_parser("audit")
    args = p.parse_args()
    header(args)
    return {"cut": cmd_cut, "at": cmd_at, "audit": cmd_audit}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
