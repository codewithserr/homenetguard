# Dashboard Terminal — Design Spec
**Date:** 2026-05-20
**Status:** Approved

## Overview

Embedded command terminal in the HomeNetGuard dashboard. Slide-up overlay panel accessible from any page. Executes two categories of commands: HomeNetGuard app actions (mapped to existing APIs) and whitelisted network utilities (via subprocess, no shell). Context-aware: clicking any IP/MAC/domain in the UI pre-fills the terminal. Tab autocomplete pulls live IPs/MACs/domains from the database.

---

## Architecture

```
Browser                          Server (Flask)
──────────────────────────────   ──────────────────────────────────
Terminal UI (overlay panel)
  │
  ├─ CommandParser (JS)           WebSocket namespace /terminal
  │   "block 1.2.3.4" ────────→  {cmd:"block", args:["1.2.3.4"]}
  │   typed {cmd, args}              │
  │                                  ├─ AppCommandRouter
  │                                  │    block/unblock → FirewallManager
  │                                  │    quarantine/release → QuarantineManager
  │                                  │    sinkhole/unsinkhole → DNSSinkhole
  │                                  │    flows/alerts/whois → DB queries
  │                                  │
  │                                  └─ NetUtilRunner (whitelist)
  │                                       ping/nslookup/nmap/dig/traceroute
  │                                       subprocess(args_list, shell=False)
  │                                       streaming stdout → WS events
  │
  ├─ Autocomplete (HTTP)         GET /api/v1/terminal/suggest?q=192&type=ip
  │                              → ["192.168.1.1", "192.168.1.108"]
  │
  └─ Click-to-fill (JS events)
       IP/MAC/domain click → window.hngTerminal.fill("whois <value>")
```

Flask-SocketIO is already present (`socket.io.min.js` in vendor). The server never passes raw strings to a shell — always `subprocess(list, shell=False)`.

---

## Command Set

### App Commands (instant response via existing APIs)

| Command | Action | Backend |
|---------|--------|---------|
| `block <ip> [reason]` | Add firewall rule | POST /api/v2/firewall/rules |
| `unblock <ip\|rule_id>` | Remove firewall rule | DELETE /api/v2/firewall/rules/<id> |
| `quarantine <mac>` | Quarantine device | POST /api/v2/devices/<mac>/quarantine |
| `release <mac>` | Release from quarantine | DELETE /api/v2/devices/<mac>/quarantine |
| `sinkhole <domain>` | Add domain to sinkhole | POST /api/v2/sinkhole/rules |
| `unsinkhole <domain>` | Remove from sinkhole | DELETE /api/v2/sinkhole/rules |
| `flows <ip>` | Recent flows for IP | DB query |
| `alerts [ip]` | Active alerts (optional IP filter) | DB query |
| `whois <ip>` | Geo + reputation + org info | GeoLookup + Reputation |
| `devices` | List known devices | DB query |
| `help` | List all commands with syntax | local |

### Network Utilities (streaming subprocess, whitelisted)

| Command | Binary | Allowed Flags | Timeout |
|---------|--------|---------------|---------|
| `ping <host> [-c N]` | ping | -c max 10 | 15s |
| `dig <domain> [type]` | dig | A, AAAA, MX, TXT, NS | 15s |
| `nslookup <domain>` | nslookup | — | 15s |
| `traceroute <host>` | traceroute | — | 30s |
| `nmap <ip> [-sn\|-sV\|-p ports]` | nmap | closed whitelist, /32 IPs only | 60s |

---

## UI Design

```
┌─────────────────────────────────────────────────────────┐  ← drag handle
│ HNG TERMINAL          [ping] [block] [nmap] [help]  [✕] │  ← header + quick-cmds
├─────────────────────────────────────────────────────────┤
│ HNG> block 192.168.1.5                                  │
│ ✓ Rule added — id:42 · IP blocked: 192.168.1.5         │
│                                                          │
│ HNG> ping 8.8.8.8 -c 4                                  │
│ PING 8.8.8.8 (8.8.8.8): 56 data bytes                  │
│ 64 bytes from 8.8.8.8: icmp_seq=0 ttl=117 time=12ms   │
│ ...                                                      │
│                                                         ▼│
├─────────────────────────────────────────────────────────┤
│ HNG> █                                                  │  ← input line
└─────────────────────────────────────────────────────────┘
```

**Interactions:**
- `Ctrl+`` ` or click `CMD_SEARCH` in navbar → slide-up (40% viewport height)
- `Escape` → close
- `↑ / ↓` → command history (localStorage, last 50)
- `Tab` → autocomplete argument with IPs/MACs/domains from DB
- Quick-cmd buttons in header for frequent actions
- Output colors: green=success, red=error, yellow=warning, grey=streaming stdout
- Click any IP/MAC/domain in any dashboard table → opens terminal + pre-fills `whois <value>`

---

## New Files

```
homenetguard/dashboard/terminal.py              # WebSocket handler + command routing
homenetguard/dashboard/static/css/terminal.css  # overlay panel styles
homenetguard/dashboard/static/js/terminal.js    # parser, WS client, UI, autocomplete
homenetguard/dashboard/templates/partials/terminal.html  # panel HTML (included in base.html)
```

**Modified files:**
```
homenetguard/dashboard/app.py          # register SocketIO terminal namespace
homenetguard/dashboard/routes.py       # add /api/v1/terminal/suggest endpoint
homenetguard/dashboard/templates/base.html  # include terminal partial + terminal.js/css
README.md                              # Terminal section + keyboard shortcuts
docs/                                  # New page: terminal command reference
```

---

## Server Module Structure

`homenetguard/dashboard/terminal.py`:

```python
class CommandParser:
    # Validates raw string → {cmd, args}
    # Rejects: &&, ||, ;, |, >, $(), backticks
    # Returns ParseError for unknown commands

class AppCommandRouter:
    # Dispatches typed command objects to existing managers/DB
    # Returns structured result dict

class NetUtilRunner:
    # Executes whitelisted subprocess commands
    # Yields stdout lines for streaming
    # shell=False, args as list, timeout enforced

class TerminalSocketHandler:
    # SocketIO event handlers for /terminal namespace
    # terminal:exec → routes to AppCommandRouter or NetUtilRunner
    # Streams terminal:out events, ends with terminal:done
```

---

## WebSocket Protocol

```
client → terminal:exec   {cmd: "ping", args: ["8.8.8.8", "-c", "4"]}
server → terminal:out    {line: "PING 8.8.8.8...", type: "stdout"}
server → terminal:out    {line: "64 bytes...",     type: "stdout"}
server → terminal:done   {code: 0, duration: 1.2}

# On error:
server → terminal:out    {line: "Unknown command: foo", type: "error"}
server → terminal:done   {code: 1, duration: 0.0}
```

---

## Security

| Layer | Control |
|-------|---------|
| JS Parser | Rejects shell metacharacters before sending to server |
| Server whitelist | `cmd` validated against known-good set before any execution |
| subprocess | `shell=False`, args as list, no inherited env vars |
| Timeout | `subprocess.run(..., timeout=N)` — process killed on exceed |
| Rate limit | Max 10 commands/min per session (Flask-Limiter) |
| nmap scope | Only /32 IPs accepted, flag whitelist enforced |
| Autocomplete | DB query with parameterized SQL, user input never interpolated |

---

## Documentation Updates

- **README.md** — new "Terminal" section: how to open, keyboard shortcuts, command list summary
- **docs/** — new article "Terminal de Comandos": full command reference, usage examples, security model explanation, click-to-fill guide
