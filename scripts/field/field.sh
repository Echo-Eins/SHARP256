#!/bin/sh
# Field tests: SHARP-256 between people in different networks, with what
# each run says kept for sending back (docs/FIELD.md).
#
#   field.sh probe   [sharp-probe options]             how this network looks from outside
#   field.sh receive [sharp-receiver options]          receive, until Ctrl-C
#   field.sh send FILE RECEIVER [sharp-sender options] send
#   field.sh pack                                      every report in one archive, to send back
#
# Everything lives under $FIELD_DIR (default ./sharp-field): keys/ (the
# identities, kept between runs so a receiver's ID stays the same; never
# packed), state/, received/ (never packed), and reports/, one directory a
# run: the command, the system, and the whole of what the program printed,
# at debug level. The binaries are taken from $SHARP_BIN, else from next to
# this script, else from PATH.
set -eu

FIELD_DIR=${FIELD_DIR:-./sharp-field}
here=$(cd "$(dirname "$0")" && pwd)

die() {
    echo "field.sh: $*" >&2
    exit 2
}

binary() {
    for d in ${SHARP_BIN:-} "$here" "$here/../../target/release" "$here/../../target/debug"; do
        if [ -x "$d/$1" ]; then
            echo "$d/$1"
            return
        fi
    done
    command -v "$1" || die "$1 not found: set SHARP_BIN to the directory it is in"
}

# The command as run, with what must not travel hidden: a shared secret, a
# passphrase, a TURN password.
redacted() {
    out=
    hide=
    for a in "$@"; do
        if [ -n "$hide" ]; then
            a="<hidden>"
            hide=
        else
            case "$a" in
                --secret | --identity-passphrase-file) hide=1 ;;
                --secret=*) a="--secret=<hidden>" ;;
            esac
            case "$a" in
                *:*@*) a=$(printf '%s' "$a" | sed 's/:[^:@]*@/:<hidden>@/') ;;
            esac
        fi
        out="$out '$a'"
    done
    printf '%s\n' "$out"
}

system() {
    echo "date (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "system:     $(uname -srm)"
    if [ -r /etc/os-release ]; then
        . /etc/os-release
        echo "release:    ${PRETTY_NAME:-?}"
    elif command -v sw_vers >/dev/null 2>&1; then
        echo "release:    macOS $(sw_vers -productVersion)"
    fi
    echo "program:    $("$1" --version 2>/dev/null || echo '?')"
    echo
    echo "interfaces:"
    if command -v ip >/dev/null 2>&1; then
        ip -brief address 2>/dev/null || true
    else
        ifconfig 2>/dev/null | grep -E '^[a-z0-9]|inet' || true
    fi
}

# Runs one program with the whole of its output kept: on screen, and in the
# run's report, ending with how it exited.
run() {
    role=$1
    prog=$2
    shift 2
    bin=$(binary "$prog")
    report="$FIELD_DIR/reports/$(date -u +%Y%m%dT%H%M%SZ)-$role"
    mkdir -p "$report" "$FIELD_DIR/keys" "$FIELD_DIR/state/$role"
    chmod 700 "$FIELD_DIR/keys"
    redacted "$prog" "$@" >"$report/command.txt"
    system "$bin" >"$report/system.txt"
    echo "report: $report"
    # NO_COLOR: a log that is read later, not a terminal. Ctrl-C stops the
    # program, not tee: what the program says on its way out is kept too.
    { NO_COLOR=1 "$bin" "$@" && rc=0 || rc=$?; echo "exit: $rc"; } 2>&1 |
        (trap '' INT; tee "$report/log.txt")
}

[ $# -ge 1 ] || die "probe, receive, send FILE RECEIVER, or pack (see the top of this script)"
cmd=$1
shift
case "$cmd" in
    probe)
        run probe sharp-probe --identity "$FIELD_DIR/keys/probe.key" --log-level debug "$@"
        ;;
    receive)
        mkdir -p "$FIELD_DIR/received"
        run receiver sharp-receiver --headless --identity "$FIELD_DIR/keys/receiver.key" \
            --state-dir "$FIELD_DIR/state/receiver" --output "$FIELD_DIR/received" \
            --log-level debug "$@"
        ;;
    send)
        [ $# -ge 2 ] || die "send FILE RECEIVER [sharp-sender options]"
        file=$1
        receiver=$2
        shift 2
        [ -f "$file" ] || die "no file $file"
        run sender sharp-sender "$file" "$receiver" --headless \
            --identity "$FIELD_DIR/keys/sender.key" --state-dir "$FIELD_DIR/state/sender" \
            --log-level debug "$@"
        ;;
    pack)
        [ -d "$FIELD_DIR/reports" ] || die "nothing to pack: no runs yet in $FIELD_DIR"
        out="$FIELD_DIR/sharp-field-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
        # The reports only: no keys, no state, nothing received.
        tar -C "$FIELD_DIR" -czf "$out" reports
        echo "$out"
        echo "In it: what each run printed — IP addresses, both sides' IDs, file"
        echo "names and sizes. No keys, no file contents. Send it the way you trust."
        ;;
    *)
        die "unknown command $cmd: probe, receive, send, or pack"
        ;;
esac
