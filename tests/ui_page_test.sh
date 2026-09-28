#!/usr/bin/env bash
# tests/ui_page_test.sh — cheap guards on the single-file web UI page.
#
# index.html is CSS, HTML and vanilla JS in one file with no build step, so
# nothing else in the suite looks at it at all. These are the invariants worth
# catching by grep: the page never builds DOM from strings, the pairing reply
# (which carries a private key) is only ever fetched by POST, and a displayed
# pairing cannot be destroyed by a redraw.
set -euo pipefail
. "$(dirname "$0")/_assert.sh"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
PAGE="$ROOT/etc/proteus/ui/index.html"

# textContent only. The page renders operator-supplied strings (check URLs,
# CIDRs) and server-supplied ones (exit names, error text); through any of these
# that becomes script injection into a page whose CSP allows inline script.
# Written as patterns so this file does not contain the literals it forbids.
for bad in 'innerHTML' 'outerHTML' 'document\.write' 'insertAdjacentHTML'; do
  grep -qE "$bad" "$PAGE" && r=present || r=absent
  assert_eq "$r" absent "the page never uses ${bad//\\/}"
done

# The pairing response contains the router's private key: it must never be
# reachable by a URL that a browser will remember, prefetch or re-issue.
assert_eq "$(grep -c '/api/udm-peer' "$PAGE")" "1" "one and only one pairing call"
grep -q '"/api/udm-peer",{method:"POST"' "$PAGE" && r=ok || r=fail
assert_eq "$r" ok "and it is a POST"

# A generated pairing cannot be reissued identically, and renderKnobs()
# replaceChildren()s the pane it is displayed in. The poll fires every five
# seconds and "save ranges" sits directly above "generate pairing", so without
# this guard an operator who corrects a range loses the configuration.
grep -qF 'if(!knobsDrawn&&!pairingShown)' "$PAGE" && r=ok || r=fail
assert_eq "$r" ok "a displayed pairing suppresses the settings redraw"
grep -qF '"done, hide this"' "$PAGE" && r=ok || r=fail
assert_eq "$r" ok "and the operator's own action is what clears it"

# Syntax check. The page has no build step, so an error here would otherwise
# reach the gateway and blank the panel for everyone.
python3 -c '
import re, sys
page = open(sys.argv[1]).read()
m = re.search(r"<script>([\s\S]*)</script>", page)
if not m:
    sys.exit("no <script> block")
open(sys.argv[2], "w").write(m.group(1))' "$PAGE" "$TMP/page.js"
if command -v node >/dev/null 2>&1; then
  node --check "$TMP/page.js" 2>/dev/null && r=ok || r=fail
  assert_eq "$r" ok "the page script parses"
else
  echo "  - node not installed, skipping the parse check"
fi

summary
