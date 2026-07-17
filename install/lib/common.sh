#!/usr/bin/env bash
# Shared installer helpers: logging, config load+validate, derivation.
# Pure functions where possible so install/tests can source and exercise them.

log()  { printf '[install] %s\n' "$*"; }
warn() { printf '[install] WARN: %s\n' "$*" >&2; }
die()  { printf '[install] ERROR: %s\n' "$*" >&2; return 1; }

REQUIRED_KEYS=(MGMT_IFACE CLIENT_IFACE MGMT_CIDR CLIENT_VLAN_CIDR CLIENT_GW_IP)

# Defaults applied if the config omits them.
_apply_defaults() {
    : "${SLOT_COUNT:=5}"
    : "${DNS_UPSTREAMS:=9.9.9.9 149.112.112.112}"
    : "${PROTON_COUNTRY:=US}"
    : "${STREAMING_MIN_MBPS:=25}"
    : "${NFT_REVERT_SECONDS:=900}"
}

load_config() {
    local f=${1:?config path required}
    [[ -r "$f" ]] || { die "config not readable: $f"; return 1; }
    # shellcheck disable=SC1090
    source "$f"
    _apply_defaults
}

# --- Pure-bash IPv4 helpers. These run in the PREFLIGHT (validate_config and the
#     doctor's SSH-lockout guard) BEFORE install_deps runs, so they must not
#     depend on python3 — a minimal Debian has no python3 until we install it,
#     and a wrong answer here can lock the operator out. 10# forces base-10 so
#     an octet like "08" isn't mis-read as octal. ---

# _ipv4_to_int <a.b.c.d> -> prints the 32-bit int; returns 1 if not a dotted quad.
_ipv4_to_int() {
    local ip=$1 IFS=. a b c d o
    [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || return 1
    read -r a b c d <<<"$ip"
    for o in "$a" "$b" "$c" "$d"; do (( 10#$o <= 255 )) || return 1; done
    printf '%u\n' "$(( (10#$a<<24) | (10#$b<<16) | (10#$c<<8) | 10#$d ))"
}

valid_ipv4() { _ipv4_to_int "$1" >/dev/null 2>&1; }

# valid_cidr <a.b.c.d/len> -> 0 if a well-formed IPv4 CIDR (slash required).
valid_cidr() {
    local base=${1%/*} len=${1#*/}
    [[ "$1" == */* ]] || return 1
    valid_ipv4 "$base" || return 1
    [[ "$len" =~ ^[0-9]+$ ]] && (( 10#$len <= 32 ))
}

# _netmask <prefixlen> -> 32-bit mask int.
_netmask() { local n=$1; (( n == 0 )) && { echo 0; return; }; echo $(( (0xFFFFFFFF << (32 - n)) & 0xFFFFFFFF )); }

# ip_in_cidr <ip> <cidr>  -> 0 if ip within cidr (IPv4); 2 on parse error.
ip_in_cidr() {
    local cidr=$2 base=${2%/*} len=${2#*/} ii bi m
    [[ "$cidr" == */* ]] || len=32
    [[ "$len" =~ ^[0-9]+$ ]] && (( 10#$len <= 32 )) || return 2
    ii=$(_ipv4_to_int "$1")   || return 2
    bi=$(_ipv4_to_int "$base") || return 2
    m=$(_netmask "$len")
    (( (ii & m) == (bi & m) ))
}

# cidrs_overlap <cidrA> <cidrB> -> 0 if they overlap; 2 on parse error.
cidrs_overlap() {
    local abase=${1%/*} alen=${1#*/} bbase=${2%/*} blen=${2#*/} ai bi minlen m
    [[ "$1" == */* ]] || alen=32
    [[ "$2" == */* ]] || blen=32
    ai=$(_ipv4_to_int "$abase") || return 2
    bi=$(_ipv4_to_int "$bbase") || return 2
    minlen=$(( 10#$alen < 10#$blen ? 10#$alen : 10#$blen ))
    m=$(_netmask "$minlen")
    (( (ai & m) == (bi & m) ))
}

validate_config() {
    local k
    for k in "${REQUIRED_KEYS[@]}"; do
        [[ -n "${!k:-}" ]] || { die "missing required config key: $k"; return 1; }
    done
    valid_cidr "$MGMT_CIDR" && valid_cidr "$CLIENT_VLAN_CIDR" && valid_ipv4 "$CLIENT_GW_IP" \
        || { die "MGMT_CIDR/CLIENT_VLAN_CIDR must be IPv4 CIDRs (a.b.c.d/len) and CLIENT_GW_IP an IPv4 address"; return 1; }
    ip_in_cidr "$CLIENT_GW_IP" "$CLIENT_VLAN_CIDR" \
        || { die "CLIENT_GW_IP ($CLIENT_GW_IP) must lie inside CLIENT_VLAN_CIDR ($CLIENT_VLAN_CIDR)"; return 1; }
    ! cidrs_overlap "$MGMT_CIDR" "$CLIENT_VLAN_CIDR" \
        || { die "MGMT_CIDR and CLIENT_VLAN_CIDR must not overlap"; return 1; }
    [[ "$SLOT_COUNT" =~ ^[0-9]+$ ]] && (( SLOT_COUNT >= 1 && SLOT_COUNT <= 9 )) \
        || { die "SLOT_COUNT must be an integer 1-9 (got '$SLOT_COUNT')"; return 1; }
    return 0
}

DNS_INDEX=99   # fixed, off the live (1..SLOT_COUNT) and staging (101..100+N) ranges

# Emit KV lines for every derived value. Sourceable / greppable by render + tests.
derive() {
    local n net3
    # client-VLAN /30 transit prefix base is 172.31.<index>.0/30 (main .1, ns .2)
    for (( n=1; n<=SLOT_COUNT; n++ )); do
        echo "SLOT_${n}_FWMARK=${n}"
        echo "SLOT_${n}_TABLE=$((100 + n))"
        echo "SLOT_${n}_TRANSIT_MAIN=172.31.${n}.1"
        echo "SLOT_${n}_TRANSIT_NS=172.31.${n}.2"
        echo "STAGE_${n}_INDEX=$((100 + n))"
    done
    echo "DNS_INDEX=${DNS_INDEX}"
    echo "DNS_FWMARK=${DNS_INDEX}"
    echo "DNS_TABLE=$((100 + DNS_INDEX))"
    echo "DNS_TRANSIT_MAIN=172.31.${DNS_INDEX}.1"
    echo "DNS_TRANSIT_NS=172.31.${DNS_INDEX}.2"
}
