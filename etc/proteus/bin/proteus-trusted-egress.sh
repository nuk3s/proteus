#!/bin/bash
# Reconcile the trusted-egress data path with /etc/proteus/trusted.json.
#
# Idempotent, and safe to run at any time including when the feature is off.
# There are two "off" states and they are deliberately not the same:
#
#   no pairing        A COMPLETE teardown, the interface included. This is the
#                     shipped default, so a box that never pairs a UDM behaves
#                     exactly as it did before this feature existed.
#   paired, no ranges The tunnel comes up and NOTHING else does. The documented
#                     rollout is: pair, confirm the peer handshakes, watch which
#                     source addresses arrive on the tunnel, and only then
#                     configure a range. Tearing the interface down for an empty
#                     list would make every one of those steps impossible and
#                     leave the operator guessing the answer the tunnel exists to
#                     provide. Nothing is forwarded in this state either — an
#                     empty @trusted_src gates everything, and no rule or route
#                     is installed.
#
# What this does NOT do is create key material. Pairing mints a private key and
# is a deliberate operator action through the web UI (broker cmd=udm-peer); this
# script only applies what pairing left behind. An unpaired box therefore stays
# inert no matter what the list says.
#
# The state it owns, and nothing else:
#   @trusted_src            the nft set the dispatch gate consults
#   wg-udm                  the tunnel interface, address, MTU and peer
#   ip rule pref 90         proteus' own traffic -> main table
#   ip rule pref 95         client VLAN -> a trusted range, on the main table
#   ip rule pref 100        replies to trusted ranges and to the tunnel subnet
#                           -> the tunnel table
#   ip route table 110      the tunnel table: a route per range and one for the
#                           tunnel subnet, and a blackhole default at the
#                           largest metric behind them
#   ns-proton-*             a return route per trusted range, and one for the
#                           tunnel subnet
#
# Every change is made before the thing it replaces is removed. A reply from a
# slot to a trusted host is accepted by the forward chain as established, so if
# it ever finds no pref-100 rule it routes via `main` and leaves the management
# uplink. That used to happen for a few milliseconds on every run, because the
# rules were all deleted and then re-added. The sections below say which order
# each step keeps and why. The one exception is a stale rule that the kernel
# will not let a wanted rule be added next to (see rule_ensure).
set -euo pipefail

log() { printf '[%(%FT%T%z)T] proteus-trusted-egress: %s\n' -1 "$*" >&2; }

# Base env then the UI overlay, matching proteus-client-isolation.sh: the config
# files are the source of truth, so an inherited variable must not be able to
# apply a shape the operator never configured. The path overrides exist only so
# the tests can run hermetically.
PROTEUS_ENV_FILE="${PROTEUS_ENV_FILE:-/etc/proteus/proteus.env}"
PROTEUS_LOCAL_ENV_FILE="${PROTEUS_LOCAL_ENV_FILE:-/etc/proteus/proteus-local.env}"
# shellcheck disable=SC1090
[ -r "$PROTEUS_ENV_FILE" ]       && . "$PROTEUS_ENV_FILE"
# shellcheck disable=SC1090
[ -r "$PROTEUS_LOCAL_ENV_FILE" ] && . "$PROTEUS_LOCAL_ENV_FILE"

BIN="${PROTEUS_BIN:-/etc/proteus/bin}"
STATE_DIR="${PROTEUS_STATE_DIR:-/etc/proteus/state}"
TRUSTED_FILE="${PROTEUS_TRUSTED_FILE:-/etc/proteus/trusted.json}"
KEY_DIR="${PROTEUS_UDM_KEY_DIR:-/etc/proteus/wg/udm}"
MGMT_CIDR="${PROTEUS_MGMT_CIDR:-10.0.0.0/24}"
CLIENT_VLAN_CIDR="${PROTEUS_CLIENT_VLAN_CIDR:-172.16.1.0/24}"
# TUNNEL_CIDR and TUNNEL_MTU are genuinely site-settable: set either in
# proteus.env or in the proteus-local.env overlay (both sourced above, overlay
# last) and this script and the broker's pairing renderer follow.
TUNNEL_CIDR="${PROTEUS_UDM_TUNNEL_CIDR:-10.99.99.0/30}"
# The port is NOT: it is FIXED, in lockstep with `define UDM_TUNNEL_PORT` in
# etc/nftables.conf and install/templates/nftables.conf.tmpl: the input chain
# accepts the handshake on that port and nothing renders one of the three from
# another. Setting the variable alone moves the listener to a port the firewall
# drops, which looks exactly like a UDM that will not connect. Change all three
# or none; a test asserts they agree.
TUNNEL_PORT="${PROTEUS_UDM_TUNNEL_PORT:-51821}"
TUNNEL_MTU="${PROTEUS_UDM_TUNNEL_MTU:-1420}"
RT_TABLE="${PROTEUS_TRUSTED_TABLE:-110}"
IFACE=wg-udm
NFT_TABLE="inet filter"
SET=trusted_src
PREF_SELF=90
PREF_CLIENT=95
PREF_RETURN=100
# The largest route metric, as for the slot tables' sentinels in routeguard.sh:
# every real route beats it.
CATCH_METRIC=4294967295

# Reading the kernel's state back. A reconcile removes only what is stale, so it
# has to know what is installed, and that is parsed from `ip -j` here rather
# than matched as text, because what `ip` prints is not what was added: a /32
# prints without its length, `from all` means no source at all, and a boundary
# CIDR written with host bits (allowed for PROTEUS_CLIENT_VLAN_CIDR) is stored
# and printed as written, so it has to be compared as written. `-N` keeps table
# 254 from printing as "main". Three questions, one per mode:
#
#   rules <listing> "<self> <client> <return>" <pref|from|to|table>...
#       Which rules at the three preferences this script owns must go. Prints
#       `del <selectors>` per rule, pref 100 first and 90 last, the order they
#       must be removed in. It will not touch two kinds, and names them instead:
#       `odd <pref> <rule>`, one with attributes this script never sets, and
#       `kept <pref> <rule>`, a stale one whose selectors would first match a
#       rule that has to stay. The kernel deletes the FIRST rule in list order
#       that matches what the request names, and a side left out of the request
#       matches anything, so the deletes are simulated against the listing
#       before any is printed. A stale pref-95 rule also stays while a stale
#       pref-100 rule for its range does, so the two never come apart.
#   ensure <listing> <pref|from|to|table>
#       Why `ip rule add` said "File exists" for that rule (see rule_ensure).
#       Prints `ok` if the rule is installed. Otherwise one line per rule the
#       kernel takes it for a duplicate of: `del <selectors>` for one this
#       script may remove, `odd` and `kept` as above for one it may not.
#   table <listing> <range>...
#       Which routes in the tunnel table are stale: anything but a metric-0
#       route to a configured range (replaced in place before this runs) and
#       the catch. Prints `<dst> [metric N]` per route.
#   ns <listing> <transit> <veth> <client cidr> <range>...
#       Which return routes in a slot namespace are stale: a route via the
#       transit address that is neither a wanted range nor the client VLAN's.
#       vpnns-up.sh owns that one, and a slot keeps the one it was built with
#       after PROTEUS_CLIENT_VLAN_CIDR changes (the installer does not rebuild
#       running slots), so any route overlapping the client VLAN is left.
#       Removing it would send the clients' replies into the slot's tunnel.
#       Prints one destination per line.
PLAN_PY='
import ipaddress, json, sys

TABLES = {"main": "254", "local": "255", "default": "253"}
PLAIN = {"priority", "src", "srclen", "dst", "dstlen", "table", "protocol"}
# What the kernel compares only when the rule being added names it, the way it
# treats the source and destination (fib4_rule_compare()). A rule carrying one
# of these still blocks an add of a rule without it.
PARTIAL = {"tos", "dscp", "flow_from", "flow_to"}
CATCH_METRIC = 4294967295

def pair(addr, plen):
    if addr in (None, "", "all", "default"):
        return ("0.0.0.0", 0)
    return (str(ipaddress.IPv4Address(addr)), 32 if plen in (None, "") else int(plen))

def spec(text):
    addr, _, plen = text.partition("/")
    return pair(addr, plen)

def net(text):
    return ipaddress.IPv4Network("0.0.0.0/0" if text == "default" else text, strict=False)

def table(name):
    return TABLES.get(str(name), str(name))

def key(r):
    return (int(r["priority"]), pair(r.get("src"), r.get("srclen")),
            pair(r.get("dst"), r.get("dstlen")), table(r.get("table", "")))

def selectors(k):
    out = ["pref", str(k[0])]
    if k[1][1]:
        out += ["from", "%s/%d" % k[1]]
    if k[2][1]:
        out += ["to", "%s/%d" % k[2]]
    return out + ["lookup", k[3]]

def hits(k, r):
    if int(r["priority"]) != k[0] or table(r.get("table", "")) != k[3]:
        return False
    rk = key(r)
    return (not k[1][1] or rk[1] == k[1]) and (not k[2][1] or rk[2] == k[2])

def rules(listing, prefs, wanted):
    prefs = tuple(int(p) for p in prefs.split())
    own_client, own_return = prefs[1], prefs[2]
    want = set()
    for w in wanted:
        p, s, d, t = w.split("|")
        want.add((int(p), spec(s), spec(d), table(t)))
    live = [r for r in json.loads(listing or "[]") if int(r.get("priority", -1)) in prefs]
    odd = [r for r in live if set(r) - PLAIN]
    sim, dels, left = list(live), [], []
    work = [r for r in live if not any(r is o for o in odd) and key(r) not in want]
    work.sort(key=lambda r: -int(r["priority"]))
    for _ in range(4 * len(work)):
        if not work:
            break
        r = work.pop(0)
        if not any(r is x for x in sim):
            continue
        k = key(r)
        if k[0] == own_client and k[2][1] and any(
                key(x)[0] == own_return and key(x)[2] == k[2] and key(x) not in want
                for x in sim):
            continue  # a stale return rule for this range stays, so its pin does too
        first = next(x for x in sim if hits(k, x))
        if first is not r and (any(first is o for o in odd) or key(first) in want):
            left.append(r)
            continue
        sim = [x for x in sim if x is not first]
        dels.append(k)
        if first is not r:
            work.append(r)
    for k in sorted(dels, key=lambda k: -k[0]):
        print("del", " ".join(selectors(k)))
    for verb, found in (("odd", odd), ("kept", left)):
        for r in found:
            print(verb, r["priority"], json.dumps(r, separators=(",", ":")))

def ensure(listing, wanted):
    p, s, d, t = wanted.split("|")
    w = (int(p), spec(s), spec(d), table(t))
    live = [r for r in json.loads(listing or "[]") if int(r.get("priority", -1)) == w[0]]
    if any(key(r) == w and not set(r) - PLAIN for r in live):
        print("ok")
        return
    sim = list(live)
    for r in live:
        k = key(r)
        # The kernel duplicate test: the same table, everything else equal,
        # and the source and destination only where the new rule names them.
        if k[3] != w[3] or (w[1][1] and k[1] != w[1]) or (w[2][1] and k[2] != w[2]) \
                or set(r) - PLAIN - PARTIAL:
            continue
        line = "%s %s" % (r["priority"], json.dumps(r, separators=(",", ":")))
        if set(r) - PLAIN:
            print("odd", line)
            continue
        first = next(x for x in sim if hits(k, x))
        if first is not r:
            print("kept", line)
            continue
        sim = [x for x in sim if x is not r]
        print("del", " ".join(selectors(k)))

def tunnel_table(listing, wanted):
    want = {net(c) for c in wanted}
    for r in json.loads(listing or "[]"):
        dst, metric = r.get("dst", "default"), int(r.get("metric") or 0)
        if metric == 0 and net(dst) in want:
            continue
        if dst == "default" and metric == CATCH_METRIC:
            continue
        print(dst, *(["metric", str(metric)] if metric else []))

def ns(listing, transit, veth, client, wanted):
    want, client = {net(c) for c in wanted}, net(client)
    for r in json.loads(listing or "[]"):
        dst = r.get("dst", "default")
        if r.get("gateway") == transit and r.get("dev") == veth and dst != "default" \
                and net(dst) not in want and not net(dst).overlaps(client):
            print(dst)

mode, args = sys.argv[1], sys.argv[2:]
if mode == "rules":
    rules(args[0], args[1], args[2:])
elif mode == "ensure":
    ensure(args[0], args[1])
elif mode == "table":
    tunnel_table(args[0], args[1:])
elif mode == "ns":
    ns(args[0], args[1], args[2], args[3], args[4:])
else:
    sys.exit(2)
'

# Delete every rule at a preference. `ip rule del pref N` removes one at a time
# and fails once none are left, which is the loop's exit condition. Capped so a
# spuriously succeeding delete cannot spin here forever. Teardown only: it
# removes live rules too, which a reconcile must never do.
del_rules() {
    local n=0
    while [ "$n" -lt 16 ] && ip rule del pref "$1" 2>/dev/null; do n=$((n+1)); done
}

# rule_ensure <pref|from|to|table>: add that rule unless it is installed. A rule
# surviving from the last run makes `ip rule add` fail "File exists", but that
# alone does not prove the rule is there. The kernel's duplicate test ignores
# any selector the new rule leaves out (rule_exists(), fib4_rule_compare()), so
# `from <mgmt ip> lookup main pref 90` is refused while `from <mgmt ip> to X
# lookup main pref 90` is installed, and `to <range> lookup 110 pref 100` while
# `from S to <range> lookup 110 pref 100` is. Trusting the error would leave
# the rule missing, and the removal step would then take the look-alike as
# stale: pref 100 with no pref 90, the lockout, or a range with no return rule.
#
# So after "File exists" the rules are read back. A look-alike is a stale rule
# at a preference this script owns, which the removal step would take anyway,
# and the kernel accepts the wanted rule only once it is gone: it is removed and
# the add repeated. Only what the look-alike alone matched goes without a rule
# for that moment, and the rule that replaces it matches that too. A look-alike
# this script may not remove (see PLAN_PY) fails the run instead, so nothing
# after it is applied.
rule_ensure() {
    local spec=$1 p s d t args=() err listing plan verb rest
    IFS='|' read -r p s d t <<<"$spec"
    [ "$s" = all ] || args+=(from "$s")
    [ "$d" = all ] || args+=(to "$d")
    args+=(lookup "$t" pref "$p")
    # LC_ALL=C: the EEXIST test matches iproute2's strerror() text, which is
    # localized.
    err=$(LC_ALL=C ip rule add "${args[@]}" 2>&1) && return 0
    case "$err" in
        *"File exists"*) ;;
        *) log "ERROR: ip rule add ${args[*]}: $err"; return 1 ;;
    esac
    if ! listing=$(ip -N -j -4 rule show) \
       || ! plan=$(python3 -c "$PLAN_PY" ensure "$listing" "$spec"); then
        log "ERROR: ip rule add ${args[*]}: File exists, and the rules could not be read back to check"
        return 1
    fi
    [ "$plan" = ok ] && return 0
    # An empty plan names no look-alike (the blocking rule went away since the
    # add); the add is simply tried again.
    if [ -n "$plan" ] && grep -qv '^del ' <<<"$plan"; then
        log "ERROR: ip rule add ${args[*]}: the kernel takes it for a duplicate of a rule" \
            "this script does not remove: $(grep -v '^del ' <<<"$plan" | cut -d' ' -f3- | tr '\n' ' ')"
        return 1
    fi
    # shellcheck disable=SC2086  # $rest is ip-rule selectors, one per word
    while read -r verb rest; do
        [ "$verb" = del ] || continue
        log "WARN: removing a rule at pref $p that blocks 'ip rule add ${args[*]}': $rest"
        ip rule del $rest || { log "ERROR: could not remove it"; return 1; }
    done <<<"$plan"
    err=$(LC_ALL=C ip rule add "${args[@]}" 2>&1) && return 0
    log "ERROR: ip rule add ${args[*]}: $err"
    return 1
}

# ns_return_routes [range...]: make every slot namespace's trusted return routes
# exactly these ranges. The wanted ones are (re)installed first, then any other
# return route through the slot's transit address is removed, except the client
# VLAN's. With no arguments that removes them all, which is what teardown wants.
#
# Removing one matters as much as adding one. Without it a reply to that range
# keeps crossing into this namespace, and once the range's pref-100 rule is gone
# it routes via `main` out the uplink for as long as the flow lives. With the
# route gone, the reply follows the slot's default route into the slot's own
# tunnel, as it did before this feature existed, and never comes back here.
# So every caller removes these BEFORE the rules.
#
# Returns 1 if a namespace could not be read or a stale route not removed. Every
# caller then keeps the rules that slot may still depend on, and fails the run
# so that systemd retries it.
ns_return_routes() {
    local state rc=0
    for state in "$STATE_DIR"/proton-*.state; do
        [ -r "$state" ] || continue
        (
            # shellcheck disable=SC1090
            . "$state"
            # Any of these missing would trip `set -u` inside this subshell and
            # end it with no word of why: that slot would silently never get a
            # return route. Name the file instead.
            if [ -z "${NS:-}" ] || [ -z "${VETH_NS:-}" ] || [ -z "${TRANSIT_MAIN:-}" ]; then
                log "skipping $state: no NS, VETH_NS or TRANSIT_MAIN in it"
                exit 0
            fi
            ip netns list | awk '{print $1}' | grep -qxF "$NS" || exit 0
            for c in "$@"; do
                ip -n "$NS" route replace "$c" via "$TRANSIT_MAIN" dev "$VETH_NS" || true
            done
            if ! listing=$(ip -n "$NS" -j -4 route show) \
               || ! stale=$(python3 -c "$PLAN_PY" ns "$listing" "$TRANSIT_MAIN" "$VETH_NS" \
                                "$CLIENT_VLAN_CIDR" "$@"); then
                log "WARN: could not read the routes in $NS; stale return routes left in place"
                exit 1
            fi
            rc=0
            for c in $stale; do
                ip -n "$NS" route del "$c" via "$TRANSIT_MAIN" dev "$VETH_NS" || { rc=1
                    log "WARN: could not remove the return route for $c from $NS"; }
            done
            exit "$rc"
        ) || rc=1
    done
    return "$rc"
}

# Every step is attempted even when an earlier one fails, and a failure is named
# rather than swallowed. "Off means off" is a promise, so a teardown that only
# half happened has to be visible in the log instead of passing for success —
# and must not abort the steps after it, which is exactly what an unguarded
# AND-list would do under `set -e`. Both functions below keep to that.
#
# teardown_routing() is everything that CARRIES traffic: the gate, the slot
# return routes, the policy rules and the tunnel table. It is separate from
# teardown() because a paired box with an empty list must lose exactly this much
# and keep its interface.
#
# The order fails closed for flows already in flight. The gate goes first, so
# nothing new is dispatched. Then the slot return routes, so replies stay in
# their slot's tunnel (see ns_return_routes). Then the rules, 100 before 90, and
# pref 90 last of all: it is what keeps the web UI's replies to a trusted-VLAN
# host off the tunnel, and it must outlive every pref-100 rule.
#
# If a slot cannot be cleaned, the rules and table 110 stay, all of them, and
# this returns 1 so the run fails and systemd retries it. That slot may still
# send a trusted host's replies here: with the rules they reach wg-udm, where
# the narrowed peer (or, once wg-udm is gone, the table's catch) drops them;
# without the rules they would route via `main` and out the uplink. Keeping them
# cannot cost the web UI anything, because pref 90 stays with the pref-100 rules
# it was installed ahead of. The usual cause is a slot rotating mid-run, and on
# the retry its namespace is gone and there is nothing left to clean.
#
# A lasting `to <range> blackhole` rule would also have failed closed, and was
# rejected: with the feature off, pref 90 and 95 are gone too, so it would drop
# the web UI's own replies to a trusted-VLAN host, and the client VLAN's pivot
# to it, from then on.
teardown_routing() {
    local rc=0
    if nft list set $NFT_TABLE "$SET" >/dev/null 2>&1; then
        nft flush set $NFT_TABLE "$SET" || { rc=1
            log "WARN: could not flush $NFT_TABLE $SET — the gate may still admit stale ranges"; }
    fi
    if ! ns_return_routes; then
        log "ERROR: a slot namespace may still route trusted replies back here, so the" \
            "rules and table $RT_TABLE are kept until it can be cleaned (they drop those" \
            "replies; without them they would leave by the main table). Will retry."
        return 1
    fi
    del_rules "$PREF_RETURN"
    del_rules "$PREF_CLIENT"
    ip route flush table "$RT_TABLE" 2>/dev/null || true
    del_rules "$PREF_SELF"
    return "$rc"
}

teardown() {
    local rc=0
    teardown_routing || rc=1
    if ip link show "$IFACE" >/dev/null 2>&1; then
        ip link del "$IFACE" || { rc=1
            log "WARN: could not delete $IFACE — the tunnel may still be carrying traffic"; }
    fi
    return "$rc"
}

# Serialise. The broker restarts this unit on every list save and it is also
# WantedBy=multi-user.target, so two copies can overlap. That is not merely
# wasteful: copy B's `del_rules 90` can land between copy A's pref-90 add and
# its pref-100 loop, leaving precisely the pref-100-without-pref-90 lockout the
# ordering below exists to prevent.
LOCKFILE="$STATE_DIR/.trusted-egress.lock"
if [ -d "$STATE_DIR" ]; then
    exec 9>"$LOCKFILE"
    # A bounded wait, not an unbounded one: whoever holds the lock is applying
    # the same file this copy would, so the ranges themselves are never lost —
    # but THIS invocation's save still goes unapplied if the wait runs out, and
    # a dropped save stays dropped until a human reads `systemctl status`. Exit
    # 1, not 0, so that happens instead of a silent no-op; the unit's
    # Restart=on-failure gives the other copy a second chance to let this one
    # through before anyone has to look.
    if ! flock -w 30 9; then
        log "ERROR: another copy is still reconciling (lock $LOCKFILE) after 30s" \
            "— this save was NOT applied. Run" \
            "'systemctl start proteus-trusted-egress.service' once the other copy finishes."
        exit 1
    fi
else
    log "WARN: state dir $STATE_DIR is missing — running without the serialising lock"
fi

# A malformed PROTEUS_MGMT_CIDR would otherwise reach trusted.py, which treats
# an unparseable guard the same as "no ranges configured" (see validate()'s
# "management or client subnet is unconfigured or unparseable" branch) — and
# this script would then report "feature off", misstating a broken config as
# an operator choice. Catch it here, before trusted.py is even invoked, so the
# log names the real cause.
#
# A regex only checks shape, not validity: `172.20.0.0/33` and `999.1.1.1/24`
# both look like a CIDR to a pattern but are not valid networks, so ask
# Python's ipaddress module instead — the same library trusted.py itself uses
# to parse this value, so "valid here" and "valid there" cannot disagree.
if ! python3 -c '
import ipaddress, sys
try:
    ipaddress.IPv4Network(sys.argv[1], strict=False)
except ValueError:
    sys.exit(1)' "$MGMT_CIDR" >/dev/null 2>&1; then
    # Here and at every teardown below, the run fails only when the teardown
    # itself fell short (a slot it could not clean included), so systemd
    # retries it.
    rc=0; teardown || rc=1
    log "ERROR: PROTEUS_MGMT_CIDR '$MGMT_CIDR' is not a valid IPv4 CIDR (expected e.g. 10.0.0.0/24)." \
        "Leaving trusted-egress routing off until it is fixed."
    exit "$rc"
fi

# Pass the guard subnets: with them, trusted.py applies the SAME rules the web
# UI enforces, so a hand-edited trusted.json cannot name the management subnet
# or the client VLAN and have this script route it.
#
# The exit status is captured separately from the output, because the two mean
# different things. trusted.py returns 0 and an empty list for a file that is
# absent, malformed or invalid — those genuinely are "the feature is off". A
# non-zero status means the tool itself could not run, and tearing a working
# tunnel down over a transient python failure would invent an operator decision
# nobody made: losing the configuration is not the same as being told there is
# none.
CIDRS=$(python3 "$BIN/trusted.py" list --file "$TRUSTED_FILE" \
            --mgmt-cidr "$MGMT_CIDR" --client-cidr "$CLIENT_VLAN_CIDR" \
            2>/dev/null) && LIST_RC=0 || LIST_RC=$?

if [ "$LIST_RC" -ne 0 ]; then
    # Non-zero, unlike the states below: this is a broken tool rather than a
    # configuration choice, and it should be visible in `systemctl status`.
    log "ERROR: could not read $TRUSTED_FILE — trusted.py exited $LIST_RC." \
        "Leaving the data path exactly as it is; nothing was changed."
    exit 1
fi

# A pairing is BOTH halves — our own private key and the UDM's public key — and
# without both there is nothing for an interface to do: no peer means no
# handshake, so a tunnel would sit there looking live and pass nothing. This is
# also the only state that removes the interface, which is what makes deleting
# peer.pub a working revocation: the link goes, and every peer it carried with
# it.
#
# -s, not -r: a zero-byte key passes a readability test and then dies inside
# `wg set` after the interface already exists, leaving an address-less, down
# interface and no explanation.
if [ ! -s "$KEY_DIR/server.key" ] || [ ! -s "$KEY_DIR/peer.pub" ]; then
    rc=0; teardown || rc=1
    if [ -n "$CIDRS" ]; then
        log "trusted ranges are configured but this box is not paired with a UDM yet" \
            "— generate a pairing in the web UI (Settings -> UDM tunnel). Data path left off."
    else
        log "no trusted ranges configured and no UDM pairing — feature off, data path torn down"
    fi
    exit "$rc"
fi

if [ "$(id -u)" -ne 0 ]; then
    log "must run as root (writes the live ruleset, routes and the tunnel)"
    exit 1
fi

PROTEUS_TUNNEL_IP=$(python3 "$BIN/trusted.py" addr --cidr "$TUNNEL_CIDR" --which proteus)
TUNNEL_PREFIX="${TUNNEL_CIDR##*/}"

# ---------------------------------------------------------------------------
# 1. The tunnel interface. Created if absent, otherwise reconfigured in place so
#    a list edit never bounces a working tunnel.
#
#    The peer's allowed-ips is the argument because it is the one part that
#    differs between a box with ranges and one still being verified. It is a
#    second, independent gate on accepted sources: WireGuard's cryptokey routing
#    drops anything outside it before nftables ever sees the packet, so both must
#    permit a range for it to work.
# ---------------------------------------------------------------------------
bring_up_tunnel() {
    local allowed=${1:?allowed-ips required} peer p
    ip link show "$IFACE" >/dev/null 2>&1 || ip link add "$IFACE" type wireguard
    wg set "$IFACE" listen-port "$TUNNEL_PORT" private-key "$KEY_DIR/server.key"

    peer=$(cat "$KEY_DIR/peer.pub")
    wg set "$IFACE" peer "$peer" allowed-ips "$allowed"
    # `wg set ... peer` adds or updates ONLY the peer it names; it never removes
    # the others. Without this loop, re-pairing would leave the PREVIOUS peer
    # configured, and because @trusted_src still admits its ranges the supposedly
    # revoked key would keep working forever — the opposite of what the UI
    # promises when it says a new pairing invalidates the old one.
    for p in $(wg show "$IFACE" peers 2>/dev/null || true); do
        if [ "$p" != "$peer" ]; then
            log "revoking superseded tunnel peer $p"
            wg set "$IFACE" peer "$p" remove || log "WARN: could not remove peer $p"
        fi
    done

    ip addr replace "$PROTEUS_TUNNEL_IP/$TUNNEL_PREFIX" dev "$IFACE"
    # 1420 to match the Proton tunnels, so the forward chain's existing `rt mtu`
    # MSS clamp yields the right value in the return direction. It also sidesteps
    # a known UniFi bug: wgclt interfaces are not MSS-clamped by the UDM, and the
    # usual workaround needs SSH, which this UDM does not expose.
    ip link set mtu "$TUNNEL_MTU" dev "$IFACE"
    ip link set "$IFACE" up
}

# Paired, but nothing to route yet: bring the tunnel up and stop there. This is
# the state the rollout runs in — pair, confirm the handshake, watch what
# arrives, THEN configure a range — and it forwards exactly as much as an
# unpaired box does, which is nothing: the gate set stays empty, no policy rule
# is installed, table 110 stays empty and no namespace gets a return route
# (once every slot could be cleaned; see teardown_routing).
if [ -z "$CIDRS" ]; then
    rc=0; teardown_routing || rc=1
    bring_up_tunnel "$TUNNEL_CIDR"
    log "$IFACE is up for pairing verification, but NO trusted ranges are configured," \
        "so nothing is routed through it yet. Confirm the peer with 'wg show $IFACE'," \
        "then watch what arrives with 'tcpdump -ni $IFACE'. Only $TUNNEL_CIDR is" \
        "admitted until a range is configured, so a UDM that does NOT masquerade" \
        "shows rising rx counters and no packets — that answer is the one that" \
        "decides which range to add in the web UI (Settings -> Trusted ranges)."
    exit "$rc"
fi

# proteus' own address inside the management subnet, which the pref-90 rule is
# built from. Determined here, before a single piece of routing state is
# written, because that rule is the ONLY thing keeping this box's own replies —
# the web UI answering a browser on a trusted VLAN among them — out of the
# tunnel. Installing the pref-100 return rules without it produces exactly the
# lockout pref 90 exists to prevent, so "no address" means the whole feature
# stays off rather than half-applied.
MGMT_IP=$(ip -4 -o addr show 2>/dev/null | PYTHONPATH="$BIN" python3 -c '
import sys, trusted
print(trusted.mgmt_ip_from(sys.stdin.read(), sys.argv[1]) or "")' "$MGMT_CIDR" 2>/dev/null || true)

if [ -z "$MGMT_IP" ]; then
    rc=0; teardown || rc=1
    log "no address found inside $MGMT_CIDR — leaving trusted-egress routing off." \
        "That address is what pins this box's own replies to the main table;" \
        "installing the return rules without it would make the web UI unreachable" \
        "from a trusted VLAN. Check PROTEUS_MGMT_CIDR against this box's addresses."
    # Exit 0 unless the teardown fell short: this is a configuration state, not
    # a crash, and a oneshot that fails at boot is noisier than it is useful.
    exit "$rc"
fi

# The peer's allowed-ips first. It narrows as well as widens, and narrowing
# first is the safe way round: a removed range stops arriving at once, and a
# reply routed to it from here on is dropped by WireGuard, which has no peer for
# it. A new range is admitted by WireGuard before anything routes it, but its
# packets arrive unmarked (it is not in @trusted_src yet) and the forward chain
# drops them.
ALLOWED="$TUNNEL_CIDR"
for c in $CIDRS; do ALLOWED="$ALLOWED,$c"; done
bring_up_tunnel "$ALLOWED"

# ---------------------------------------------------------------------------
# 2. Return routing, the MAKE half: everything the new list needs, added before
#    anything stale is removed, so a range that stays configured never loses
#    its rule or its route for an instant. Existing rules are left in place
#    (rule_ensure), and the table's routes are replaced in place, never flushed.
#
# The ordering here is the whole trick. A plain `route add <trusted> dev wg-udm`
# in the main table would also capture proteus' OWN replies to a trusted host —
# including the web UI answering the admin desktop — and send them down a tunnel
# the request never came from. So the tunnel route lives in its own table, and
# pref 90 pins everything proteus originates to the main table first. Reaching
# this point at all means MGMT_IP is known: the gate above refuses to route
# anything when it is not. Within each range, the route goes in before the
# rules that lead to it, and pref 95 before pref 100.
#
# The catch goes in before any of it: a blackhole default at the largest metric,
# the same sentinel routeguard.sh puts in every slot table. Only a pref-100 rule
# leads into this table, so the catch can only ever see a trusted destination,
# and it answers only when that range's own route is missing. That happens
# without this script: when wg-udm goes down or is deleted, the kernel removes
# every route through it, and without the catch the lookup would fall through to
# `main` and out the uplink.
#
# The tunnel subnet gets a route and a return rule here too, although wg-udm's
# connected route in `main` already reaches it: that route goes with the device,
# and a slot's reply to the tunnel address (what a masquerading UDM sends
# everything from) would then leave by `main`'s default route. Through table 110
# it meets the catch instead. It needs no client-VLAN pin: `main` would send the
# client VLAN's packets for it into wg-udm as well.
# ---------------------------------------------------------------------------
ip route replace blackhole default metric "$CATCH_METRIC" table "$RT_TABLE"
for c in $CIDRS "$TUNNEL_CIDR"; do
    ip route replace "$c" dev "$IFACE" table "$RT_TABLE"
done

rule_ensure "$PREF_SELF|$MGMT_IP|all|main"

for c in $CIDRS; do
    # The pref-100 rule below matches on DESTINATION alone, so it captures any
    # source headed for this range — the client VLAN included. That would push a
    # client-VLAN host talking to a trusted host into the tunnel instead of out
    # the management interface, breaking the transit @client_pivot exists to
    # allow when isolation is open (and dropping it outright when it is closed,
    # since the tunnel has no route back to the client VLAN). So pin that pair,
    # and only that pair, to the main table ahead of it.
    #
    # `to "$c"` is load-bearing, not decoration. `from $CLIENT_VLAN_CIDR lookup
    # main` on its own matches EVERY packet the client VLAN sends anywhere, and
    # main's own default route resolves it — so rule evaluation stops at this
    # priority and never reaches the `fwmark N lookup 10N` rules at 500+N where
    # each slot's default route lives. The packet keeps its mark, the forward
    # chain accepts it on that mark alone, and client egress leaves over the
    # management interface with the VPN bypassed entirely: the kill-switch
    # failure this system exists to prevent, reached by failing open. Scoped by
    # destination it can only divert traffic aimed at a range the operator
    # named, and those are RFC1918, which prerouting_mangle returns on before
    # marking anything — so it cannot collide with dispatch either.
    rule_ensure "$PREF_CLIENT|$CLIENT_VLAN_CIDR|$c|main"
    rule_ensure "$PREF_RETURN|all|$c|$RT_TABLE"
done
rule_ensure "$PREF_RETURN|all|$TUNNEL_CIDR|$RT_TABLE"

# ---------------------------------------------------------------------------
# 3. The nft set. Flush and repopulate in one transaction so the gate is never
#    momentarily open on a stale range or shut on a live one. After the rules,
#    so a new range is admitted only once its replies have a way back.
# ---------------------------------------------------------------------------
if nft list set $NFT_TABLE "$SET" >/dev/null 2>&1; then
    {
        printf 'flush set %s %s\n' "$NFT_TABLE" "$SET"
        # The tunnel subnet is added by us, not by the operator: if the UDM
        # masquerades into the tunnel every trusted host arrives as the tunnel
        # address, and without this the feature would silently do nothing.
        printf 'add element %s %s { %s }\n' "$NFT_TABLE" "$SET" "$TUNNEL_CIDR"
        for c in $CIDRS; do
            printf 'add element %s %s { %s }\n' "$NFT_TABLE" "$SET" "$c"
        done
    } | nft -f -
else
    log "set $NFT_TABLE $SET not present (nftables not loaded?) — tunnel up, gate not applied"
fi

# ---------------------------------------------------------------------------
# 4. Return routes inside the slot namespaces, so a list edit takes effect
#    without waiting for each slot's next rotation. vpnns-up.sh does the same
#    for a slot it is bringing up. A new range's route goes in only now that
#    this namespace can route its replies; a removed range's route comes out
#    before its rules do (see ns_return_routes).
# ---------------------------------------------------------------------------
ns_ok=1
# shellcheck disable=SC2086  # one range per word, by design
ns_return_routes $CIDRS "$TUNNEL_CIDR" || ns_ok=0

# ---------------------------------------------------------------------------
# 5. The BREAK half: remove only what the new list no longer wants, pref 100
#    first and 90 last, then the stale routes the removed rules led to.
#
# Held back entirely when a namespace could not be cleaned: that namespace may
# still send a removed range's replies here, and while its rules stay they reach
# wg-udm, where WireGuard drops them. Removing the rules would send them out the
# uplink instead. Exit 1, so Restart=on-failure tries again.
# ---------------------------------------------------------------------------
if [ "$ns_ok" -ne 1 ]; then
    log "ERROR: stale return routes could not be removed from every slot namespace;" \
        "the rules for removed ranges are kept until they are"
    exit 1
fi

WANT=("$PREF_SELF|$MGMT_IP|all|main" "$PREF_RETURN|all|$TUNNEL_CIDR|$RT_TABLE")
for c in $CIDRS; do
    WANT+=("$PREF_CLIENT|$CLIENT_VLAN_CIDR|$c|main" "$PREF_RETURN|all|$c|$RT_TABLE")
done
rc=0
if ! RULES=$(ip -N -j -4 rule show) \
   || ! RULE_PLAN=$(python3 -c "$PLAN_PY" rules "$RULES" \
                        "$PREF_SELF $PREF_CLIENT $PREF_RETURN" "${WANT[@]}"); then
    log "ERROR: could not read the installed rules back; nothing stale was removed"
    exit 1
fi
# shellcheck disable=SC2086  # $rest is ip-rule selectors, one per word
while read -r verb rest; do
    case "$verb" in
        del) ip rule del $rest || { rc=1; log "WARN: could not remove stale rule: $rest"; } ;;
        odd) log "WARN: left a rule at pref ${rest%% *} alone; this script never installs" \
                 "one like it: ${rest#* }" ;;
        kept) log "WARN: kept a stale rule at pref ${rest%% *}: removing it would take" \
                  "another rule first: ${rest#* }" ;;
    esac
done <<<"$RULE_PLAN"

# A table that has never held a route cannot be listed at all (`ip` exits 2),
# which would only mean nothing in it is stale; the catch above makes sure it
# has one by now, so a failure here is real.
# shellcheck disable=SC2086  # one range per word
if ! ROUTES=$(ip -N -j -4 route show table "$RT_TABLE") \
   || ! TABLE_PLAN=$(python3 -c "$PLAN_PY" table "$ROUTES" $CIDRS "$TUNNEL_CIDR"); then
    log "ERROR: could not read table $RT_TABLE back; stale routes in it were left"
    exit 1
fi
# shellcheck disable=SC2086  # $extra is "metric N", or nothing
while read -r dst extra; do
    [ -n "$dst" ] || continue
    ip route del "$dst" $extra table "$RT_TABLE" || { rc=1
        log "WARN: could not remove stale route $dst from table $RT_TABLE"; }
done <<<"$TABLE_PLAN"

log "applied: $(echo "$CIDRS" | tr '\n' ' ')(+$TUNNEL_CIDR) via $IFACE, table $RT_TABLE"
exit "$rc"
