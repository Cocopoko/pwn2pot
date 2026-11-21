# pwn2pot

**coco2 → hashcat, zero hands.** Capture → crack, fully automatic.
A pwnagotchi plugin plus a small Windows listener that together remove
every manual step between a handshake landing on the Pi and hashcat
finishing with it on the PC — every crack lands in the potfile.

```
pwnagotchi (coco2)                     host PC (Legion)
┌───────────────────────┐              ┌──────────────────────────────┐
│ handshake captured    │              │ listener :8765               │
│        │              │              │        │                     │
│ hcxpcapngtool         │   HTTP POST  │ dedupe → inbox               │
│ (only COMPLETE        │ ───────────► │        │                     │
│  handshakes yield     │  .22000 line │ hashcat -m 22000 -d 1        │
│  a hash)              │              │  1. Top204Thousand           │
│        │              │              │  2. Top1pt2Million           │
│ spool on disk,        │              │  3. Top1pt2Million + rules   │
│ retried until ACKed   │              │        │                     │
└───────────────────────┘              │ cracks → cracked.log         │
                                       └──────────────────────────────┘
```

Partial captures (AP-side M1/M3 frames only) convert to nothing and
are skipped by design — the bridge only forwards hashes hashcat can
actually work on.

## Pieces

- `plugin/coco2_hashcat_bridge.py` — the pwnagotchi plugin (Python 3.7+,
  uses the `requests` library pwnagotchi already ships).
- `legion/hashcat_bridge_listener.ps1` — HttpListener + hashcat runner.
- `legion/install.ps1` — one-time PC setup: token, firewall, logon task.
- `config.example.toml` — the pwnagotchi config block.

## Requirements

Pi side:
- pwnagotchi (built/tested on the aluminum-ice fork, v1.8.5)
- `hcxpcapngtool` (hcxtools) on PATH or at `/usr/local/bin/hcxpcapngtool`
- The Pi can reach the PC at `10.0.0.1` (USB gadget network, ICS host)

PC side:
- Windows PowerShell 5.1 (built into Windows 10/11)
- hashcat 6.x in `Downloads\hashcat-6.2.6` (override with `-HashcatDir`)
- Wordlists in `OneDrive\Desktop\Wordlist-V2` (override with `-WordlistDir`):
  `Top204Thousand-WPA-probable-v2.txt`, `Top1pt2Million-WPA-probable-v2.txt`,
  `rule\rockyou-30000.rule`

## Setup

**PC first** (the installer prints the token you need for the Pi):

```powershell
# as Administrator, from the legion\ folder
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

**Then the Pi:**

```sh
# copy the plugin into the custom-plugins directory
sudo cp coco2_hashcat_bridge.py /usr/local/share/pwnagotchi/custom-plugins/
# append config.example.toml (with your token) to /etc/pwnagotchi/config.toml
sudo systemctl restart pwnagotchi
```

## What lands where (PC)

Everything lives in `%USERPROFILE%\hashcat-bridge\`:

| File | Contents |
|---|---|
| `cracked.log` | timestamped cracks (`hash:plain`, `--show` format) |
| `listener.log` | every receive / pass / crack / error |
| `bridge.potfile` | the bridge's own hashcat potfile |
| `seen.txt` | every hash ever received (dedupe) |
| `inbox\` / `done\` | queued and processed `.22000` files |
| `token.txt` | the shared bridge token |

## Security notes

- The listener only accepts hashes from the pwnagotchi: the firewall
  rule scopes port 8765 to remote address `10.0.0.2`, and every POST
  must carry the shared token in the `X-Bridge-Token` header.
- The token is generated at install time and never leaves the two
  machines — it is not in this repo.
- Hashes are spooled on the Pi (`/root/hashcat-bridge/spool.jsonl`)
  and retried on every new handshake, on ready, and whenever internet
  is detected, so a sleeping PC loses nothing.

## License

GPL3
