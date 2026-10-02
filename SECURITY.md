# Security

SHARP-256 moves files between people who may be watched, and its value is
that what it promises holds. If you have found a way in which it does not,
please say so privately first.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: the repository's **Security**
tab → **Report a vulnerability**. The report reaches the maintainer only,
and the advisory is written together there.

Please include what you can of:

* what is affected — the protocol (docs/PROTOCOL.md), the implementation,
  the relay, the laboratories' claims;
* how to see it: a command line, a capture, a test, an input to one of the
  fuzzing targets (`cargo fuzz list`);
* what an adversary gains, in the terms of docs/THREAT_MODEL.md (which
  class of adversary, which guarantee Г1–Г39 breaks).

Do not open a public issue for something that could hurt users before it is
fixed. Anything that is plainly not a vulnerability — a crash on input only
the user can give, a documentation slip — is welcome as an ordinary issue.

## What to expect

* An answer within a week, saying whether it reproduces.
* For a real vulnerability: a fix on the main branch and in a release, an
  advisory crediting you (unless you prefer otherwise), and a line in
  CHANGELOG.md. Disclosure is coordinated with you; ninety days is the
  outer limit unless we agree otherwise.
* There is no bug bounty yet (docs/ROADMAP.md, J2).

## What is in scope

Everything that docs/THREAT_MODEL.md says SHARP-256 protects: the contents
and metadata of transfers, the long-term keys, the receiver's availability
and file system, the bandwidth of both ends and of relays (amplification),
the resume state. Its explicit non-goals (§6) — anonymity, hiding that two
addresses talk, a compromised endpoint, an adversary with more bandwidth
than the link — are not vulnerabilities, though a way to do better at them
is still interesting.

Versions: the latest release and the main branch. The protocol versions in
use are 3 and 4 (docs/PROTOCOL.md §11).

## How the code is checked

What has been done to find vulnerabilities before anyone else does, and
what each check covers and misses: docs/THREAT_MODEL.md §9 (every claim and
the test behind it), docs/FUZZING.md, docs/SANITIZERS.md, docs/UNSAFE.md,
docs/MUTANTS.md, docs/SUPPLY_CHAIN.md. Release binaries for Linux are
reproducible, and every release carries provenance signed through Sigstore
(docs/SUPPLY_CHAIN.md).
