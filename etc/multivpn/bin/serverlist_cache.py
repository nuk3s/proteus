"""Pure serverlist.json cache validation + repair for proton-mint.

No proton-vpn-core / network imports — unit-testable with stdlib alone
(mirrors the dispatcher.py / dispatcher_logic.py split). proton-mint imports
`repair()` and calls it while holding the mint lock, before proton-vpn-core
reads the cache.

Why this exists: proton-vpn-core's ~23 MB serverlist.json cache gets corrupted
two ways —

  * concurrent write (two mints racing) -> a complete JSON document followed by
    trailing junk. Truncate-repairable. The flock in proton-mint now prevents
    this, but old corrupt files may linger.
  * interrupted write (reboot/kill mid-write) -> a mid-file break. NOT
    truncate-repairable; only a known-good snapshot can restore it.

A corrupt cache is self-perpetuating: the library can't deserialize the session
without a readable server list, so it can't fetch a fresh one to overwrite the
bad file. Repairing here is what lets minting recover unattended after a crash.
"""
from __future__ import annotations

import json
import os
import shutil

# proton-vpn-core's on-disk cache when proton-mint runs as root.
CACHE_PATH = "/var/cache/Proton/VPN/serverlist.json"
GOOD_PATH = CACHE_PATH + ".lastgood"


def is_valid_json(path: str) -> bool:
    try:
        with open(path, encoding="utf-8") as f:
            json.load(f)
        return True
    except (OSError, ValueError):
        return False


def _truncate_repairable(path: str) -> bool:
    """If the file is a valid JSON document followed by trailing junk (the
    concurrent-append corruption), rewrite it as just that leading document and
    return True. Return False if there is no valid leading document (mid-file
    corruption or an unreadable file)."""
    try:
        data = open(path, encoding="utf-8").read()
    except OSError:
        return False
    try:
        _obj, end = json.JSONDecoder().raw_decode(data)
    except ValueError:
        return False
    with open(path, "w", encoding="utf-8") as f:
        f.write(data[:end])
    try:
        os.chmod(path, 0o644)
    except OSError:
        pass
    return True


def repair(cache_path: str = CACHE_PATH, good_path: str = GOOD_PATH) -> str:
    """Ensure cache_path holds valid JSON before proton-vpn-core reads it, and
    maintain good_path as a known-good snapshot. Call while holding the mint
    lock so no writer races the repair.

    Returns an action tag for logging:
      'valid'           cache was already valid (snapshot refreshed)
      'truncated'       trailing junk stripped from a valid leading document
      'restored'        mid-file corruption restored from the snapshot
      'absent-restored' cache was missing, restored from the snapshot
      'absent'          cache missing and no snapshot (library will fetch)
      'quarantined'     corrupt, no snapshot: moved aside for a clean fetch
      'unrecoverable'   corrupt, no snapshot, and could not move it aside
    """
    if not os.path.exists(cache_path):
        if is_valid_json(good_path):
            shutil.copy2(good_path, cache_path)
            return "absent-restored"
        return "absent"

    if is_valid_json(cache_path):
        try:
            shutil.copy2(cache_path, good_path)  # refresh known-good snapshot
        except OSError:
            pass
        return "valid"

    # Corrupt. Trailing-junk is truncate-repairable; mid-file corruption is not.
    if _truncate_repairable(cache_path) and is_valid_json(cache_path):
        try:
            shutil.copy2(cache_path, good_path)
        except OSError:
            pass
        return "truncated"

    if is_valid_json(good_path):
        shutil.copy2(good_path, cache_path)
        return "restored"

    # Not repairable and no snapshot: quarantine so a clean fetch can proceed.
    try:
        os.replace(cache_path, cache_path + ".corrupt")
        return "quarantined"
    except OSError:
        return "unrecoverable"
