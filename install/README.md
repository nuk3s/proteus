# install/ — gateway installer quickstart

Stands up the L3-gateway proteus proxy on a fresh Debian/Ubuntu VM from one
config file, with a preflight doctor and an SSH-lockout apply guard.

## Prerequisite

This box must already be the client VLAN's default gateway — point the
VLAN's gateway at your chosen `CLIENT_GW_IP` (the upstream router/UniFi
still holds the /24 for DHCP; the installer doesn't touch DHCP).

## Steps

```bash
cp install/proteus.conf.example install/proteus.conf
$EDITOR install/proteus.conf              # set MGMT_IFACE, CLIENT_IFACE, CIDRs, etc.

sudo ./install/install.sh --check          # read-only preflight doctor
sudo ./install/install.sh                  # doctor -> deps -> render -> apply, then stops
```

The bare run deliberately stops after apply: nothing is minted, enabled or
started until you confirm you can still reach the box.

The apply phase snapshots the current nftables ruleset and arms a revert
timer (`NFT_REVERT_SECONDS`, default 900s) before loading the new one. If
the new ruleset locks you out or breaks something, it reverts on its own —
no action needed. The revert reloads the old ruleset and puts the previous
`/etc/nftables.conf` back, so a reboot afterwards does not bring the new one
back. (On Debian that previous file is usually the nftables package's stock
accept-all table; a box that had no `/etc/nftables.conf` keeps the new file.)
If the revert has already fired, `--confirm` refuses and says so: re-run the
install. If the
current ruleset cannot be listed, the apply stops before arming anything.
If everything looks right (you still have SSH, and once bootstrapped, client
egress), cancel the timer:

```bash
sudo ./install/install.sh --confirm        # cancels the revert, then runs Proton
                                           # login -> initial mint -> enable
                                           # services -> verify
```

Initial mint runs the full rotation pipeline for every slot plus the DNS
tunnel, so `--confirm` takes a couple of minutes per slot.

`--render` stops one phase earlier than a bare run: doctor + deps + render +
diff, nothing applied. It is not read-only — the deps phase apt-installs
packages. `--check` is the read-only one.

## The one interactive step

Proton VPN requires a one-time interactive login (username/password/TOTP)
to mint the SSO refresh token. The bootstrap phase, which runs under
`--confirm`, skips this automatically if a valid session already exists;
otherwise it prompts once, then every subsequent run and rotation is
unattended.
