# install/ — gateway installer quickstart

Stands up the L3-gateway multivpn proxy on a fresh Debian/Ubuntu VM from one
config file, with a preflight doctor and an SSH-lockout apply guard.

## Prerequisite

This box must already be the client VLAN's default gateway — point the
VLAN's gateway at your chosen `CLIENT_GW_IP` (the upstream router/UniFi
still holds the /24 for DHCP; the installer doesn't touch DHCP).

## Steps

```bash
cp install/multivpn.conf.example install/multivpn.conf
$EDITOR install/multivpn.conf              # set MGMT_IFACE, CLIENT_IFACE, CIDRs, etc.

sudo ./install/install.sh --check          # read-only preflight doctor
sudo ./install/install.sh                  # doctor -> deps -> render -> apply -> bootstrap -> enable -> verify
```

The apply phase snapshots the current nftables ruleset and arms a revert
timer (`NFT_REVERT_SECONDS`, default 900s) before loading the new one. If
the new ruleset locks you out or breaks something, it reverts on its own —
no action needed. If everything looks right (you still have SSH, and once
bootstrapped, client egress), cancel the timer:

```bash
sudo ./install/install.sh --confirm
```

`--render` runs doctor + render + diff without touching the live system —
useful for reviewing what would change before applying.

## The one interactive step

Proton VPN requires a one-time interactive login (username/password/TOTP)
to mint the SSO refresh token. The installer's bootstrap phase skips this
automatically if a valid session already exists; otherwise it prompts once,
then every subsequent run and rotation is unattended.
