# pwn2pot

**pwnagotchi → hashcat, zero hands.** Capture → crack, fully automatic.

A pwnagotchi plugin plus a small Windows listener that together remove
every manual step between a handshake landing on the Pi and hashcat
finishing with it on the PC. When your pwnagotchi catches a *complete*
WPA handshake, pwn2pot converts it, ships it to your PC, and runs a
three-pass hashcat pipeline against it — every crack lands in the
potfile and in `cracked.log`. No scp, no manual conversion, no
babysitting.

```
pwnagotchi                             host PC (Windows)
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

## Features

- **Fully automatic** — handshake event → conversion → delivery → cracking
- **Only complete handshakes are forwarded** — `hcxpcapngtool` decides
- **On-disk spool on the Pi with dedupe** — retried on ready, on
  internet-available, and on every new handshake until the PC ACKs, so
  a sleeping or rebooting PC loses nothing
- **Three-pass pipeline** — quick list → full list → full list + rules,
  stopping early the moment a hash cracks
- **Token-authenticated** POSTs, and the installer scopes the Windows
  firewall rule to the pwnagotchi's IP only
- **Everything logged**; processed hashes are archived in `done\`

## Pieces

| File | What it is |
|---|---|
| `plugin/pwn2pot.py` | The pwnagotchi plugin (Python 3.7+, uses the `requests` library pwnagotchi already ships) |
| `host/hashcat_bridge_listener.ps1` | HttpListener + hashcat runner (the PC side) |
| `host/install.ps1` | One-time PC setup: token, firewall rule, logon task |
| `config.example.toml` | The pwnagotchi config block |

## Requirements

**Pi side**

- pwnagotchi (built and tested on the aluminum-ice fork, v1.8.5)
- `hcxpcapngtool` (from hcxtools) at `/usr/local/bin/hcxpcapngtool`
  (path is configurable)
- The Pi can reach the PC at `10.0.0.1` (the usual USB gadget /
  connection-sharing host address)

**PC side**

- Windows 10/11 with PowerShell 5.1 (built in)
- hashcat 6.x (default location `Downloads\hashcat-6.2.6`,
  override with `-HashcatDir`)
- Wordlists (default location `OneDrive\Desktop\Wordlist-V2`,
  override with `-WordlistDir`): the pipeline expects
  `Top204Thousand-WPA-probable-v2.txt`,
  `Top1pt2Million-WPA-probable-v2.txt` and
  `rule\rockyou-30000.rule` — the WPA-probable v2 lists, or any
  lists you rename to match

## Setup

**PC first** — the installer prints the token you need for the Pi:

```powershell
# as Administrator, from the host\ folder
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

This generates the shared token (`%USERPROFILE%\hashcat-bridge\token.txt`),
adds the firewall rule (inbound TCP 8765, remote address `10.0.0.2`
only), registers a logon task so the listener starts with Windows,
and starts it.

**Then the Pi:**

```sh
# copy the plugin into the custom-plugins directory
sudo cp pwn2pot.py /usr/local/share/pwnagotchi/custom-plugins/
# append the contents of config.example.toml — with your token pasted in —
# to /etc/pwnagotchi/config.toml, then restart
sudo systemctl restart pwnagotchi
```

**Verify**

- Pi: `grep 'pwn2pot' /var/log/pwnagotchi.log` shows
  `[pwn2pot] loaded, host url: http://10.0.0.1:8765/submit`
- PC: `%USERPROFILE%\hashcat-bridge\listener.log` shows
  `hashcat-bridge listener up on port 8765`
- The first complete handshake she catches appears in the listener
  log as `received hash for '<ssid>'` and the passes follow.

## Configuration

Plugin options (in `/etc/pwnagotchi/config.toml`):

| Option | Default | Meaning |
|---|---|---|
| `main.plugins.pwn2pot.enabled` | `false` | Turn the plugin on |
| `main.plugins.pwn2pot.host_url` | `http://10.0.0.1:8765/submit` | Where hashes are POSTed |
| `main.plugins.pwn2pot.token` | *(none)* | Shared token; must match the PC's `token.txt` |
| `main.plugins.pwn2pot.hcxpcapngtool` | `/usr/local/bin/hcxpcapngtool` | Converter path on the Pi |

## What lands where (PC)

Everything lives in `%USERPROFILE%\hashcat-bridge\`:

| File | Contents |
|---|---|
| `cracked.log` | Timestamped cracks (`hash:plain`, `--show` format) |
| `listener.log` | Every receive / pass / crack / error |
| `bridge.potfile` | The bridge's own hashcat potfile |
| `seen.txt` | Every hash ever received (dedupe) |
| `inbox\` / `done\` | Queued and processed `.22000` files |
| `token.txt` | The shared bridge token |

## Known limitations

- The listener answers a submission only **after** its hashcat passes
  finish — and a rules pass can take a while. Senders may time out
  and retry; dedupe makes retries harmless and nothing is lost. (A
  reply-first, crack-in-background change is planned.)
- The listener processes **one hash at a time**, in arrival order.
- The PC side is **Windows only** (PowerShell + HttpListener).

## Troubleshooting

- **403 from the listener** — token mismatch between the Pi's
  `config.toml` and the PC's `token.txt`.
- **Plugin loaded but silent** — normal until a *complete* handshake
  is captured; partial captures produce no traffic by design.
- **Nothing received** — check `listener.log`, confirm the scheduled
  task `hashcat-bridge` is running, and that the Pi can reach
  `10.0.0.1:8765`.

## Security notes

- The listener only accepts hashes from the pwnagotchi: the firewall
  rule scopes port 8765 to remote address `10.0.0.2`, and every POST
  must carry the shared token in the `X-Bridge-Token` header.
- The token is generated at install time and never leaves the two
  machines — it is **not** in this repo. The value in
  `config.example.toml` is a placeholder; never commit your real one.
- This is a home-LAN tool for your own hardware and your own
  captures. Use it only on networks you own or are authorised to test.

## License

GPL-3.0
