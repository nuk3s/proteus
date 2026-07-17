#!/usr/bin/env bash
# Proteus TUI toolkit — colors, banner, boxes, steps, spinner, prompts.
# Pure bash + ANSI (256-color). No external deps so it runs on a fresh Debian.
# Source this; then call proteus_banner / step / ok / ask / etc.

# --- capability + palette -----------------------------------------------------
# Honour NO_COLOR and non-tty output by blanking the escapes.
if [[ -n "${NO_COLOR:-}" || ( ! -t 1 && -z "${PROTEUS_FORCE_COLOR:-}" ) ]]; then
    _e() { :; }              # no-op: colors disabled
    C() { printf '%s' ""; }
else
    _e() { printf '\e[%sm' "$1"; }
    C() { printf '\e[%sm' "$1"; }
fi
RESET=$(C 0); BOLD=$(C 1); DIM=$(C 2); ITAL=$(C 3)
# Warm terminal palette (256-color): charcoal ground, bone text, one amber
# accent, muted moss secondary. Flat — no gradient, no glow. Variable names are
# kept for compatibility; the values are the warm set.
AQUA=$(C '38;5;179'); TEAL=$(C '38;5;173'); SEA=$(C '38;5;101')
BLUE=$(C '38;5;66'); IND=$(C '38;5;101'); PURP=$(C '38;5;137'); VIOL=$(C '38;5;173')
INK=$(C '38;5;242'); FOG=$(C '38;5;180'); SNOW=$(C '38;5;187')
GOOD=$(C '38;5;108'); WARNC=$(C '38;5;179'); BAD=$(C '38;5;167'); GOLD=$(C '38;5;179')
# Banner rows: flat amber, no gradient.
_GRAD=("$TEAL" "$TEAL" "$TEAL" "$TEAL" "$TEAL" "$TEAL")

COLS() { local c; c=$(tput cols 2>/dev/null || echo 80); (( c > 100 )) && c=100; echo "$c"; }
# Repeat a (possibly multibyte) string N times. `tr ' ' '─'` corrupts multibyte
# glyphs because tr is byte-oriented, so build the run by hand.
_rep() { local s=$1 n=$2 out=''; while (( n-- > 0 )); do out+="$s"; done; printf '%s' "$out"; }

# --- banner -------------------------------------------------------------------
# The slant figlet of "Proteus", printed with a top-to-bottom color gradient.
proteus_banner() {
    local art=(
'    ____             __                 '
'   / __ \_________  / /____  __  _______'
'  / /_/ / ___/ __ \/ __/ _ \/ / / / ___/'
' / ____/ /  / /_/ / /_/  __/ /_/ (__  ) '
'/_/   /_/   \____/\__/\___/\__,_/____/  '
    )
    echo
    local i
    for i in "${!art[@]}"; do
        printf '  %s%s%s\n' "${_GRAD[$i]}" "${art[$i]}" "$RESET"
    done
    printf '  %s%s~%s %sa new face for every connection%s\n\n' \
        "$VIOL" "$BOLD" "$RESET" "$DIM$ITAL" "$RESET"
}

# small inline wordmark (for footers/prompts): PROTEUS in teal
mark() { printf '%s%sProteus%s' "$TEAL" "$BOLD" "$RESET"; }

# --- rules & boxes ------------------------------------------------------------
hr() {   # faint full-width rule
    local w; w=$(COLS); printf '%s%s%s\n' "$INK" "$(_rep '─' "$w")" "$RESET"
}
rule_title() {  # ── title ──────────────
    local t=$1 w; w=$(COLS)
    local left="── "
    local used=$(( ${#t} + ${#left} + 1 ))
    (( used < w )) || used=$(( w - 1 ))
    printf '%s%s%s%s %s ' "$SEA" "$left" "$RESET$BOLD$SNOW" "$t" "$SEA"
    printf '%s%s\n' "$(_rep '─' "$(( w - used - 1 ))")" "$RESET"
}

# box "Title" line1 line2 ...   → rounded box with a colored title bar
box() {
    local title=$1; shift
    local w; w=$(COLS); (( w > 78 )) && w=78
    local inner=$(( w - 4 ))
    printf '%s┌─%s %s%s%s ' "$SEA" "$RESET" "$BOLD$AQUA" "$title" "$RESET"
    local pad=$(( inner - ${#title} - 1 ))
    (( pad < 0 )) && pad=0
    printf '%s%s┐%s\n' "$SEA" "$(_rep '─' "$pad")" "$RESET"
    local line
    for line in "$@"; do
        # strip ANSI for width math
        local plain; plain=$(sed 's/\x1b\[[0-9;]*m//g' <<<"$line")
        local lpad=$(( inner - ${#plain} )); (( lpad < 0 )) && lpad=0
        printf '%s│%s %b%*s %s│%s\n' "$SEA" "$RESET" "$line" "$lpad" '' "$SEA" "$RESET"
    done
    printf '%s└%s┘%s\n' "$SEA" "$(_rep '─' "$(( inner + 2 ))")" "$RESET"
}

# --- steps & status -----------------------------------------------------------
_STEP_N=0; _STEP_T=0
steps_total() { _STEP_T=$1; }
step() {  # step "Title"  → numbered header with a progress pip line
    _STEP_N=$(( _STEP_N + 1 ))
    echo
    printf '%s%s  %s◈%s %s%s%s  %sstep %d/%d%s\n' \
        "$BOLD" "$VIOL" "$AQUA" "$RESET" "$BOLD$SNOW" "$1" "$RESET" "$DIM" "$_STEP_N" "$_STEP_T" "$RESET"
    # pip progress: filled for done+current, empty for rest
    printf '   '
    local i
    for (( i=1; i<=_STEP_T; i++ )); do
        if (( i < _STEP_N )); then printf '%s●%s' "$SEA" "$RESET"
        elif (( i == _STEP_N )); then printf '%s●%s' "$AQUA" "$RESET"
        else printf '%s○%s' "$INK" "$RESET"; fi
    done
    echo; echo
}
ok()   { printf '   %s✓%s %s\n' "$GOOD" "$RESET" "$1"; }
warn() { printf '   %s⚠%s %s\n' "$WARNC" "$RESET" "$1"; }
bad()  { printf '   %s✗%s %s\n' "$BAD" "$RESET" "$1"; }
info() { printf '   %s➜%s %s\n' "$AQUA" "$RESET" "$1"; }
note() { printf '     %s%s%s\n' "$DIM" "$1" "$RESET"; }
kv()   { printf '   %s%-18s%s %s%s%s\n' "$INK" "$1" "$RESET" "$SNOW" "$2" "$RESET"; }

# --- spinner ------------------------------------------------------------------
# spin "message" seconds   → braille spinner for N seconds (used in demo/waits)
spin() {
    local msg=$1 secs=${2:-2} frames='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏' i=0 n
    # frame-count loop so fractional (and zero) durations work — bash can't do
    # float arithmetic, and each frame is ~0.09s. PROTEUS_SPEED scales all waits
    # (used to keep the recorded demo snappy).
    n=$(awk -v s="$secs" -v sp="${PROTEUS_SPEED:-1}" 'BEGIN{ printf "%d", (s*sp)/0.09 }')
    tput civis 2>/dev/null
    while (( i < n )); do
        printf '\r   %s%s%s %s' "$TEAL" "${frames:$(( i % ${#frames} )):1}" "$RESET" "$msg"
        sleep 0.09; i=$(( i + 1 ))
    done
    tput cnorm 2>/dev/null
    printf '\r   %s✓%s %s\n' "$GOOD" "$RESET" "$msg"
}

# spin_pid "message" <pid>  → spin until the given pid exits, report its status
spin_pid() {
    local msg=$1 pid=$2 frames='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏' i=0
    tput civis 2>/dev/null
    while kill -0 "$pid" 2>/dev/null; do
        printf '\r   %s%s%s %s' "$TEAL" "${frames:$(( i % ${#frames} )):1}" "$RESET" "$msg"
        sleep 0.09; i=$(( i + 1 ))
    done
    wait "$pid"; local rc=$?
    tput cnorm 2>/dev/null
    if (( rc == 0 )); then printf '\r   %s✓%s %s\n' "$GOOD" "$RESET" "$msg"
    else printf '\r   %s✗%s %s\n' "$BAD" "$RESET" "$msg"; fi
    return $rc
}

# --- prompts ------------------------------------------------------------------
ask() {  # ask "Question" "default" -> echoes answer (default on empty)
    local q=$1 def=${2:-} ans
    if [[ -n "$def" ]]; then
        printf '   %s?%s %s %s[%s]%s ' "$VIOL" "$RESET" "$q" "$DIM" "$def" "$RESET" >&2
    else
        printf '   %s?%s %s ' "$VIOL" "$RESET" "$q" >&2
    fi
    read -r ans || true
    echo "${ans:-$def}"
}
confirm() {  # confirm "Question" [Y|N default] -> 0 yes / 1 no
    local q=$1 def=${2:-Y} ans hint
    [[ $def == Y ]] && hint="${BOLD}Y${RESET}${DIM}/n" || hint="${DIM}y/${BOLD}N"
    printf '   %s?%s %s %s[%s%s]%s ' "$VIOL" "$RESET" "$q" "$DIM" "$hint" "$DIM" "$RESET" >&2
    read -r ans || true
    ans=${ans:-$def}
    [[ $ans =~ ^[Yy] ]]
}
pause() { printf '   %s%s%s' "$DIM" "${1:-press enter to continue…}" "$RESET" >&2; read -r _ || true; }
