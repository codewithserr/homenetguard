# HomeNetGuard — Development Guide

## Architecture

Flask dashboard + SQLite storage + Scapy packet capture. Python 3.13.

```
homenetguard/
  capture/      # Packet sniffer, PCAP reader, interface detection
  analysis/     # DPI, DNS, TLS fingerprinting, beaconing, anomaly, geo, reputation
  network/      # Device scanner, flow correlator, gateway monitor
  active/       # Firewall, DNS sinkhole, quarantine, rate limiter
  intelligence/ # Threat feeds, MITRE mapper, compliance checker
  alerts/       # Email/Telegram notifiers
  storage/      # SQLite DB, repository, models
  dashboard/    # Flask app, routes, templates, static assets
  export/       # REST API (flask-restx), SIEM exporter
  reports/      # HTML/PDF report generation
```

## Running

```bash
pip install -e .
homenetguard --help
homenetguard monitor --interface en0
# Dashboard at http://localhost:5000
```

## Tests

```bash
pytest tests/ -v
```

Python 3.13 quirk: `cgi` module removed. Any test or code using it must be replaced.

## Dashboard Pages

| Route | Template | Description |
|-------|----------|-------------|
| `/` | index.html | Overview: metrics, map, protocol chart |
| `/alerts` | alerts.html | Security alerts |
| `/flows` | flows.html | Flow explorer |
| `/dns` | dns.html | DNS analysis |
| `/reports` | reports.html | Report generation |
| `/config` | config.html | Configuration viewer |
| `/devices` | devices.html | Device inventory |
| `/firewall` | firewall.html | IP blocking rules |
| `/intelligence` | intelligence.html | MITRE ATT&CK, threat feeds, DNS sinkhole |
| `/forensics` | forensics.html | IP/MAC timeline |
| `/wifi` | wifi.html | WiFi monitoring |
| `/learn` | learn.html | Educational content (see below) |
| `/api/docs` | flask-restx Swagger UI | REST API documentation |

## Learn Section

`/learn` and `/learn/<topic-id>` — educational documentation integrated into the dashboard.

### Purpose

Users can learn networking and security concepts in context of what HomeNetGuard shows them. Each page in the UI has small `?` icon links (`class="learn-link"`) that open the relevant topic in the Learn section.

### Structure

All content lives client-side in `templates/learn.html` inside the `TOPICS` JS object. No backend queries needed — static educational content.

```
/learn                    → welcome screen, topic list in sidebar
/learn/<topic-id>         → same page, auto-selects that topic
```

### Topic Format

Each entry in `TOPICS`:

```js
"topic-id": {
  title: "Short name",
  subtitle: "Full description",
  category: "Protocols|Networking|Detection|Security",
  appPage: "/flows",          // link to relevant dashboard page
  appLabel: "See flows →",    // link label
  standards: ["RFC 793"],     // shown as chips at bottom
  levels: {
    beginner: `<h3>...</h3><p>...</p>`,      // HTML string
    intermediate: `...`,
    advanced: `...`
  }
}
```

### Categories

- **Protocols**: TCP, UDP, ICMP, DNS, TLS/SSL
- **Networking**: IP Addresses, MAC Addresses, OSI Model, Network Flows
- **Detection**: Packet Capture, DPI, OS Fingerprinting, Beaconing Detection, Anomaly Detection
- **Security**: Firewall, DNS Sinkhole, MITRE ATT&CK, Threat Feeds, IP Reputation, Quarantine

### Adding New Topics

1. Add entry to `TOPICS` in `learn.html`
2. Choose a category from `CATEGORIES` array (or add a new one to both `CATEGORIES` and the `TOPICS` entries)
3. Write content at all 3 levels — beginner: what is it + in the app; intermediate: how it works; advanced: internals + edge cases
4. Optionally add a `learn-link` `?` icon in the relevant template pointing to `/learn/<topic-id>`

### Inline Learn Links

Add contextual links from UI elements to topic pages:

```html
<th>PROTO <a href="/learn/tcp" class="learn-link" title="Learn about protocols">?</a></th>
```

CSS class `learn-link` is defined in `static/css/dashboard.css`. The `title` attribute shows on hover as a tooltip.

### Current Inline Links

| Template | Element | Learn Topic |
|----------|---------|-------------|
| flows.html | PROTO column | `/learn/tcp` |
| flows.html | SRC IP column | `/learn/ip-addresses` |
| flows.html | BYTES column | `/learn/network-flows` |
| flows.html | SRC GEO column | `/learn/ip-reputation` |
| dns.html | Page title | `/learn/dns` |
| alerts.html | Page title | `/learn/anomaly-detection` |
| devices.html | MAC column | `/learn/mac-addresses` |
| devices.html | IP column | `/learn/ip-addresses` |
| devices.html | OS GUESS column | `/learn/os-fingerprint` |
| firewall.html | Page title | `/learn/firewall` |
| intelligence.html | MITRE ATT&CK panel | `/learn/mitre-attack` |
| intelligence.html | THREAT FEEDS panel | `/learn/threat-feeds` |
| intelligence.html | DNS SINKHOLE panel | `/learn/dns-sinkhole` |

---

## Cyber Academy — Sección Educativa (v2)

### Qué es
Sección educativa completa accesible en `/learn`. 60 tópicos de ciberseguridad organizados en 6 categorías y 3 niveles de dificultad. Cada artículo conecta el concepto con datos reales de la red del usuario.

### Estructura de ficheros
```
dashboard/
├── templates/learn/
│   ├── index.html          # Índice con grid de tópicos, filtros, rutas de aprendizaje
│   └── topic.html          # Artículo individual (2 columnas: contenido + sidebar)
├── static/
│   ├── css/learn.css       # Estilos de la sección (variables CSS existentes)
│   ├── js/learn.js         # Tooltips, progreso localStorage
│   └── data/
│       └── curriculum.json # Todo el contenido educativo
```

### Rutas Flask
| Ruta | Template | Descripción |
|------|----------|-------------|
| `GET /learn` | learn/index.html | Índice completo |
| `GET /learn/<slug>` | learn/topic.html | Artículo individual |
| `GET /learn/path/<id>` | redirect → primer tópico | Ruta de aprendizaje |
| `GET /api/v1/learn/topics` | JSON | Curriculum completo |
| `GET /api/v1/learn/tooltip/<term>` | JSON | Definición corta para tooltips |

### Categorías del curriculum (6)
| Label | Key | Tópicos |
|-------|-----|---------|
| A | fundamentals | 14 (OSI, TCP/IP, IP, subredes, gateway, DNS, MAC/ARP, handshake, puertos, NAT, ICMP, BGP, IPv6, OSI) |
| B | security_protocols | 10 (TLS, SSH, certificados, VPN, firewalls, IDS/IPS, criptografía, Zero Trust, PKI, DoH/DoT) |
| C | threats | 16 (port scan, malware, phishing, DDoS, MITM, ARP spoofing, DNS poisoning, C2, exfiltración, cryptojacking, ransomware, APT, supply chain, LotL, zero-day, lateral movement) |
| D | analysis | 8 (logs, packet capture, NetFlow, threat hunting, IOCs, MITRE ATT&CK, SIEM, forense) |
| E | defense | 8 (CIA triad, defense in depth, least privilege, segmentación, hardening, vuln management, Zero Trust home, threat modeling) |
| F | tools | 4 (Scapy, Nmap, Wireshark, build-your-detector) |

### Schema de un tópico en curriculum.json
```json
{
  "id": "tcp-protocol",
  "slug": "tcp-protocol",
  "title": "TCP — Transmission Control Protocol",
  "category": "fundamentals",
  "level": "beginner|intermediate|advanced",
  "estimated_minutes": 8,
  "ui_terms": ["TCP", "SYN"],
  "prerequisites": ["other-slug"],
  "next_topics": ["other-slug"],
  "standards": ["RFC 793"],
  "mitre_techniques": ["T1046"],
  "sections": [
    { "type": "concept",      "title": "¿Qué es?",        "content": "..." },
    { "type": "live_example", "title": "En tu red ahora", "query": "SELECT COUNT(*) FROM flows WHERE protocol='TCP'", "description": "..." },
    { "type": "security",     "title": "Seguridad",       "content": "...", "mitre_techniques": ["T1046"] },
    { "type": "deeper",       "title": "Más profundo",    "content": "...", "references": ["RFC 793"] }
  ]
}
```

### Cómo añadir un nuevo tópico
1. Añadir entrada en `curriculum.json` siguiendo el schema
2. Si el término aparece en la UI, añadirlo a `TOOLTIP_TERMS` en `learn.js`
3. Si el término se renderiza dinámicamente en JS (flows, alerts), añadir `data-learn-term="${valor}"` al elemento HTML y llamar `window.initLearnTooltips()` tras el render
4. Opcionalmente añadirlo a una `learning_path` existente

### Sistema de live data
La ruta `/learn/<slug>` ejecuta la query `live_example.query` de cada sección tipo `live_example` via `_run_live_query()` en routes.py. Solo acepta SELECT sin parámetros de usuario. El resultado (primer campo, primera fila) se pasa al template como `live_data[i]`.

### Progreso del usuario
Almacenado en `localStorage` bajo clave `hng_learn_progress`. Formato: `{"completed": ["tcp-protocol", ...]}`. Sin backend. El botón "Marcar como leído" en cada artículo actualiza el localStorage.

### Tooltips
`learn.js` escanea elementos `[data-learn-term]` al cargar el DOM e inyecta un icono ⓘ con tooltip CSS. Para contenido dinámico (tablas JS), llamar `window.initLearnTooltips()` tras cada render.
