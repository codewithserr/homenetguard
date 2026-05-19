# Docs Section Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `/docs` section to the HomeNetGuard dashboard with 32 articles across 6 sections, client-side search, scroll spy TOC, and copy buttons.

**Architecture:** Static JSON data file (`docs_content.json`) holds all article content as HTML strings. Flask routes load + serve the JSON; templates render it. Search runs client-side in `docs.js`. No new DB tables, no changes to existing routes or models.

**Tech Stack:** Flask Blueprint (existing `bp`), Jinja2 templates extending `base.html`, vanilla JS, CSS custom properties matching existing `variables.css`.

---

## File Map

| Action | Path | Purpose |
|--------|------|---------|
| Create | `homenetguard/dashboard/static/data/docs_content.json` | All 32 articles, sections, metadata |
| Create | `homenetguard/dashboard/static/css/docs.css` | Docs-only styles |
| Create | `homenetguard/dashboard/static/js/docs.js` | Search, scroll spy, copy buttons |
| Create | `homenetguard/dashboard/templates/docs/index.html` | `/docs` landing page |
| Create | `homenetguard/dashboard/templates/docs/section.html` | Section article list |
| Create | `homenetguard/dashboard/templates/docs/article.html` | Individual article |
| Modify | `homenetguard/dashboard/routes.py` | Add 4 new routes + `_load_docs()` helper |
| Modify | `homenetguard/dashboard/templates/base.html` | Add Docs nav item before Academy |
| Create | `tests/unit/test_docs_routes.py` | Route tests for all docs URLs |

---

## Task 1: `docs_content.json` — data model and all 32 articles

**Files:**
- Create: `homenetguard/dashboard/static/data/docs_content.json`

- [ ] **Step 1: Write the JSON skeleton**

```json
{
  "version": "1.0.0",
  "updated_at": "2026-05-19",
  "sections": [
    {
      "id": "getting-started",
      "title": "Getting Started",
      "icon": "play-circle",
      "description": "Installation, configuration, and first launch",
      "articles": []
    },
    {
      "id": "user-guide",
      "title": "User Guide",
      "icon": "book-open",
      "description": "Every dashboard view explained",
      "articles": []
    },
    {
      "id": "cli-reference",
      "title": "CLI Reference",
      "icon": "terminal",
      "description": "All commands, flags, and examples",
      "articles": []
    },
    {
      "id": "advanced",
      "title": "Advanced Configuration",
      "icon": "settings",
      "description": "DNS sinkhole, firewall, ML, SIEM, notifications",
      "articles": []
    },
    {
      "id": "technical",
      "title": "Technical Docs",
      "icon": "cpu",
      "description": "Architecture, DB schema, detection internals, API",
      "articles": []
    },
    {
      "id": "troubleshooting",
      "title": "Troubleshooting",
      "icon": "alert-circle",
      "description": "Common problems and solutions",
      "articles": []
    }
  ]
}
```

Each article object schema:
```json
{
  "id": "what-is-homenetguard",
  "title": "¿Qué es HomeNetGuard?",
  "description": "Visión general, casos de uso y arquitectura",
  "tags": ["overview", "architecture"],
  "updated_at": "2026-05-19",
  "content": "<h2>...</h2><p>...</p>"
}
```

- [ ] **Step 2: Add Section 1 — Getting Started (5 articles)**

Add to `sections[0].articles`. Article IDs and content:

**Article 1.1** — `"id": "what-is-homenetguard"`, `"title": "¿Qué es HomeNetGuard?"`
```html
<h2>¿Qué es HomeNetGuard?</h2>
<p>HomeNetGuard es una herramienta de monitorización y seguridad de red para uso doméstico y personal. Captura paquetes en tiempo real, analiza flujos, detecta amenazas y presenta todo en un dashboard web.</p>
<h3>Arquitectura por capas</h3>
<pre class="docs-code">┌─────────────────────────────────────────────────────┐
│                  PRESENTACIÓN                       │
│   CLI (Click)  │  TUI (Rich)  │  Dashboard (Flask)  │
├─────────────────────────────────────────────────────┤
│                   ANÁLISIS                          │
│   DPI  │  TLS Fingerprint  │  ML Anomaly           │
├─────────────────────────────────────────────────────┤
│                 PERSISTENCIA                        │
│           SQLite  │  PCAP Files                    │
├─────────────────────────────────────────────────────┤
│                   CAPTURA                           │
│        Scapy Sniffer  │  Device Scanner             │
└─────────────────────────────────────────────────────┘</pre>
<h3>Casos de uso</h3>
<ul>
<li>Monitorización continua en casa</li>
<li>Auditoría de redes WiFi con permiso</li>
<li>Aprendizaje de ciberseguridad</li>
<li>Detección de amenazas domésticas</li>
</ul>
<h3>Qué hace</h3>
<ul>
<li>Captura paquetes en la interfaz de red</li>
<li>Analiza flujos y detecta amenazas</li>
<li>Genera alertas y reportes</li>
<li>Gestiona firewall y DNS sinkhole</li>
</ul>
<h3>Qué NO hace</h3>
<ul>
<li>No es un antivirus</li>
<li>No protege contra amenazas en el dispositivo</li>
<li>No monitoriza tráfico cifrado end-to-end</li>
</ul>
<div class="docs-warning">⚠ Solo usar en redes propias o con permiso explícito del propietario.</div>
```

**Article 1.2** — `"id": "installation"`, `"title": "Instalación y requisitos"`
```html
<h2>Instalación y requisitos</h2>
<h3>Sistemas operativos</h3>
<p>Linux (Ubuntu 20.04+, Debian 11+, Arch) y macOS 12+.</p>
<h3>Requisitos de hardware</h3>
<ul><li>Mínimo 2 GB RAM</li><li>10 GB disco para capturas</li></ul>
<h3>Dependencias</h3>
<p>Python 3.11+, tshark, libpcap, iptables (Linux) o pf (macOS).</p>
<h3>Instalación paso a paso</h3>
<pre class="docs-code">git clone https://github.com/[usuario]/homenetguard
cd homenetguard
python -m venv venv &amp;&amp; source venv/bin/activate
pip install -r requirements.txt
bash scripts/install_system_deps.sh
bash scripts/download_geoip.sh
cp config/config.example.yaml config/config.yaml</pre>
<h3>Verificación</h3>
<pre class="docs-code">homenetguard status</pre>
<h3>Problemas comunes</h3>
<table class="docs-table">
<thead><tr><th>Error</th><th>Causa</th><th>Solución</th></tr></thead>
<tbody>
<tr><td>Permission denied</td><td>Sin CAP_NET_RAW</td><td>Ejecutar con sudo</td></tr>
<tr><td>Module not found: scapy</td><td>venv no activado</td><td>source venv/bin/activate</td></tr>
<tr><td>tshark: command not found</td><td>No instalado</td><td>apt install tshark</td></tr>
</tbody></table>
```

**Article 1.3** — `"id": "initial-config"`, `"title": "Configuración inicial"`
```html
<h2>Configuración inicial</h2>
<p>Toda la configuración vive en <code>config/config.yaml</code>. Variables sensibles van en <code>.env</code>.</p>
<h3>Configuración mínima</h3>
<pre class="docs-code">network:
  interface: auto   # auto-detecta la interfaz activa

storage:
  db_path: data/homenetguard.db
  retention_days: 30

dashboard:
  host: 127.0.0.1
  port: 5000</pre>
<h3>API keys (en .env)</h3>
<pre class="docs-code">ABUSEIPDB_API_KEY=tu_clave_aqui
VIRUSTOTAL_API_KEY=tu_clave_aqui
HNG_API_KEY=clave_para_api_rest</pre>
<div class="docs-note">ℹ Las API keys nunca deben ir en config.yaml — van en .env para no exponerlas en el repositorio.</div>
<h3>Detectar interfaz automáticamente</h3>
<pre class="docs-code">homenetguard config --detect-interface</pre>
```

**Article 1.4** — `"id": "first-launch"`, `"title": "Primer arranque"`
```html
<h2>Primer arranque</h2>
<pre class="docs-code">sudo homenetguard start --interface en0</pre>
<p>En los primeros 60 segundos HomeNetGuard detecta la interfaz, inicializa la DB y abre el dashboard.</p>
<h3>Acceso al dashboard</h3>
<p>Abre <code>http://127.0.0.1:5000</code> en el navegador.</p>
<h3>Indicador de captura</h3>
<p>El LED verde pulsante en el topbar indica captura activa. El label muestra <strong>● MONITORING</strong>.</p>
<h3>Detener la monitorización</h3>
<pre class="docs-code">homenetguard stop</pre>
<p>O clic en el botón <strong>■ STOP</strong> en el topbar del dashboard.</p>
```

**Article 1.5** — `"id": "permissions-security"`, `"title": "Permisos y seguridad"`
```html
<h2>Permisos y seguridad</h2>
<p>HomeNetGuard necesita <code>CAP_NET_RAW</code> para capturar paquetes.</p>
<h3>Opción A: sudo (más simple)</h3>
<pre class="docs-code">sudo homenetguard start</pre>
<h3>Opción B: capabilities de Linux (más seguro)</h3>
<pre class="docs-code">sudo setcap cap_net_raw+eip $(which python3)</pre>
<h3>macOS</h3>
<pre class="docs-code">sudo dseditgroup -o edit -a $USER -t user access_bpf</pre>
<h3>Seguridad del dashboard</h3>
<ul>
<li>Solo escucha en 127.0.0.1 — nunca expuesto a la red</li>
<li>API key requerida para el servidor REST</li>
<li>Todos los datos se almacenan localmente</li>
</ul>
<div class="docs-note">ℹ Ningún dato sale del equipo salvo consultas a APIs externas configuradas explícitamente (AbuseIPDB, VirusTotal).</div>
```

- [ ] **Step 3: Add Section 2 — User Guide (13 articles)**

Add to `sections[1].articles`. Complete content for each:

**Article 2.1** — `"id": "overview-view"`, `"title": "Overview — Vista principal"`
```html
<h2>Overview — Vista principal</h2>
<p>La vista principal muestra el estado en tiempo real de la red.</p>
<h3>KPI cards</h3>
<table class="docs-table">
<thead><tr><th>Card</th><th>Qué mide</th><th>Normal</th></tr></thead>
<tbody>
<tr><td>Paquetes/seg</td><td>Throughput instantáneo</td><td>&lt; 1000 pps en red doméstica</td></tr>
<tr><td>Amenazas activas</td><td>Alertas sin reconocer</td><td>0</td></tr>
<tr><td>IPs únicas</td><td>Hosts distintos en la última hora</td><td>Depende del tamaño de la red</td></tr>
<tr><td>Bytes</td><td>Tráfico total en la sesión</td><td>—</td></tr>
</tbody></table>
<h3>Mapa de geolocalización</h3>
<p>Marcadores coloreados por estado: verde (normal), amarillo (sospechoso), rojo (malicioso). El tamaño es proporcional al volumen de bytes.</p>
<h3>Tabla de flujos</h3>
<p>Columnas: TIMESTAMP, SRC IP, DST IP, PROTO, PORTS, BYTES, APP, GEO, STATUS. Filas rojas = flujo marcado como amenaza.</p>
<h3>Ticker de alertas</h3>
<p>La barra superior muestra las últimas alertas no reconocidas desfilando.</p>
```

**Article 2.2** — `"id": "alerts-view"`, `"title": "Alerts — Gestión de alertas"`
```html
<h2>Alerts — Gestión de alertas</h2>
<h3>Tipos de alerta</h3>
<table class="docs-table">
<thead><tr><th>Tipo</th><th>Descripción</th><th>Severidad típica</th></tr></thead>
<tbody>
<tr><td>port_scan</td><td>Escaneo de puertos detectado</td><td>HIGH</td></tr>
<tr><td>beaconing</td><td>Comunicación periódica sospechosa</td><td>MEDIUM</td></tr>
<tr><td>flood</td><td>Tráfico masivo desde una IP</td><td>HIGH</td></tr>
<tr><td>blacklisted_ip</td><td>Conexión a IP en lista negra</td><td>CRITICAL</td></tr>
<tr><td>dns_anomaly</td><td>Consulta DNS sospechosa</td><td>MEDIUM</td></tr>
<tr><td>arp_spoofing</td><td>Posible ataque MitM ARP</td><td>HIGH</td></tr>
<tr><td>cryptomining</td><td>Tráfico a pool de minería</td><td>HIGH</td></tr>
<tr><td>tls_anomaly</td><td>Certificado o JA3 sospechoso</td><td>MEDIUM</td></tr>
<tr><td>new_device</td><td>Dispositivo desconocido en la red</td><td>LOW</td></tr>
</tbody></table>
<h3>Severidades</h3>
<ul>
<li><strong>CRITICAL:</strong> Acción inmediata. Aislar el dispositivo afectado.</li>
<li><strong>HIGH:</strong> Investigar en las próximas horas.</li>
<li><strong>MEDIUM:</strong> Revisar en el día.</li>
<li><strong>LOW:</strong> Informativo, no urgente.</li>
</ul>
<h3>Filtros</h3>
<p>Filtra por tipo, severidad, fecha e IP usando los controles de la parte superior.</p>
<h3>Flujo ante CRITICAL</h3>
<ol>
<li>Ver la alerta y anotar src_ip y dst_ip</li>
<li>Ir a Forensics y buscar src_ip</li>
<li>Si el dispositivo es de la red local, ponerlo en cuarentena desde Devices</li>
<li>Bloquear dst_ip en Firewall</li>
<li>Reconocer la alerta cuando el incidente esté resuelto</li>
</ol>
```

**Article 2.3** — `"id": "flows-view"`, `"title": "Flows — Explorador de flujos"`
```html
<h2>Flows — Explorador de flujos</h2>
<p>Un flujo agrupa todos los paquetes entre el mismo par src_ip:port → dst_ip:port con el mismo protocolo.</p>
<h3>Filtros disponibles</h3>
<ul>
<li>IP origen o destino</li>
<li>Protocolo (TCP, UDP, ICMP…)</li>
<li>Puerto</li>
<li>Rango de fechas</li>
<li>Protocolo de aplicación (HTTP, DNS, TLS…)</li>
<li>Volumen de bytes mínimo</li>
</ul>
<h3>Drawer de detalle de IP</h3>
<p>Clic en cualquier IP abre un panel lateral con: reputación AbuseIPDB, país y ciudad, historial de sesiones.</p>
<h3>Señales de tráfico sospechoso</h3>
<ul>
<li>IPs de países inusuales para el usuario</li>
<li>Puertos no estándar (no 80/443/22/53)</li>
<li>Volúmenes muy altos o muy regulares (beaconing)</li>
<li>Protocolos inesperados a la misma IP</li>
</ul>
```

**Article 2.4** — `"id": "dns-view"`, `"title": "DNS — Análisis de consultas"`
```html
<h2>DNS — Análisis de consultas</h2>
<p>DNS es el protocolo más explotado para C2, tunneling y phishing. Monitorizarlo revela actividad maliciosa antes que cualquier otro indicador.</p>
<h3>Columna Entropy</h3>
<p>Mide la entropía de Shannon del nombre de dominio.</p>
<ul>
<li>&lt; 3.0 → normal</li>
<li>3.0 – 3.5 → observar</li>
<li>&gt; 3.5 → posible DNS tunneling</li>
</ul>
<h3>Dominios en rojo</h3>
<p>El dominio está en una lista de bloqueo OSINT activa. Investigar qué dispositivo hace la consulta.</p>
<h3>Consultas NXDOMAIN</h3>
<p>Muchas NXDOMAIN seguidas desde el mismo dispositivo suele indicar malware intentando conectarse a dominios C2 caídos o DGA (Domain Generation Algorithm).</p>
<h3>Añadir al sinkhole</h3>
<p>Clic en el icono 🚫 junto a cualquier dominio para añadirlo al DNS sinkhole y bloquear todas las consultas futuras.</p>
```

**Article 2.5** — `"id": "reports-view"`, `"title": "Reports — Centro de informes"`
```html
<h2>Reports — Centro de informes</h2>
<h3>Tipos de informe</h3>
<table class="docs-table">
<thead><tr><th>Tipo</th><th>Contenido</th><th>Uso recomendado</th></tr></thead>
<tbody>
<tr><td>Daily</td><td>Resumen del día: flujos, alertas, top IPs</td><td>Revisión diaria</td></tr>
<tr><td>Weekly</td><td>Tendencias semanales</td><td>Reunión de seguridad</td></tr>
<tr><td>Forensic</td><td>Timeline de un incidente para una IP/MAC</td><td>Investigación post-incidente</td></tr>
<tr><td>Compliance</td><td>Puntuación de cumplimiento y recomendaciones</td><td>Auditoría</td></tr>
</tbody></table>
<h3>Generación</h3>
<p>Clic en <strong>New Report</strong> → seleccionar tipo, rango de fechas y formato (HTML o PDF) → Generate.</p>
<h3>Informe Forensic</h3>
<p>Requiere IP o MAC. Genera un timeline completo de todos los eventos del dispositivo en el período seleccionado.</p>
```

**Article 2.6** — `"id": "config-view"`, `"title": "Config — Configuración"`
```html
<h2>Config — Configuración</h2>
<p>Vista de solo lectura de la configuración activa. Para editar, modifica <code>config/config.yaml</code> y reinicia.</p>
<h3>Parámetros principales</h3>
<table class="docs-table">
<thead><tr><th>Sección</th><th>Parámetro</th><th>Tipo</th><th>Descripción</th></tr></thead>
<tbody>
<tr><td>network</td><td>interface</td><td>string</td><td>Interfaz de captura (auto para detección automática)</td></tr>
<tr><td>network</td><td>capture_filter</td><td>string</td><td>Filtro BPF, p.ej. "not port 22"</td></tr>
<tr><td>storage</td><td>retention_days</td><td>int</td><td>Días que se guardan los datos</td></tr>
<tr><td>storage</td><td>db_path</td><td>string</td><td>Ruta al fichero SQLite</td></tr>
<tr><td>dashboard</td><td>port</td><td>int</td><td>Puerto del servidor web (defecto 5000)</td></tr>
<tr><td>detection</td><td>port_scan.threshold</td><td>int</td><td>Puertos distintos antes de alertar</td></tr>
<tr><td>firewall</td><td>auto_block</td><td>bool</td><td>Bloquear automáticamente IPs críticas</td></tr>
<tr><td>sinkhole</td><td>enabled</td><td>bool</td><td>Activar el servidor DNS sinkhole</td></tr>
<tr><td>ml</td><td>threshold</td><td>float</td><td>Umbral de anomaly_score para alertar (0.0–1.0)</td></tr>
</tbody></table>
<div class="docs-note">ℹ Las API keys se muestran como *** por seguridad.</div>
```

**Article 2.7** — `"id": "devices-view"`, `"title": "Devices — Inventario"`
```html
<h2>Devices — Inventario de dispositivos</h2>
<p>HomeNetGuard descubre dispositivos mediante ARP scan pasivo y activo.</p>
<h3>Estados</h3>
<table class="docs-table">
<thead><tr><th>Estado</th><th>Color</th><th>Significado</th></tr></thead>
<tbody>
<tr><td>Trusted</td><td>Verde</td><td>Dispositivo conocido y autorizado</td></tr>
<tr><td>Unknown</td><td>Amarillo</td><td>Visto en la red pero no verificado</td></tr>
<tr><td>Quarantined</td><td>Rojo</td><td>Tráfico bloqueado excepto al gateway</td></tr>
</tbody></table>
<h3>OS Fingerprinting</h3>
<p>Detección pasiva de sistema operativo por características TCP/IP (TTL, tamaño de ventana, opciones TCP). Precisión ~70%. Si el OS detectado es incorrecto, es porque el dispositivo usa valores por defecto no estándar.</p>
<h3>Alerta new_device</h3>
<p>Se genera cuando aparece una MAC nueva en la red. Márcalo como Trusted si lo reconoces, o ponlo en cuarentena si es desconocido.</p>
```

**Article 2.8** — `"id": "firewall-view"`, `"title": "Firewall — Gestión de reglas"`
```html
<h2>Firewall — Gestión de reglas</h2>
<p>El firewall de HomeNetGuard usa iptables/nftables en Linux y pf en macOS. Es adicional al firewall del router, no lo reemplaza.</p>
<h3>Tipos de regla</h3>
<table class="docs-table">
<thead><tr><th>Tipo</th><th>Ejemplo</th><th>Cuándo usar</th></tr></thead>
<tbody>
<tr><td>block_ip</td><td>1.2.3.4</td><td>IP individual sospechosa</td></tr>
<tr><td>block_cidr</td><td>10.0.0.0/8</td><td>Rango de IPs</td></tr>
<tr><td>block_port</td><td>6881</td><td>Protocolo peligroso (BitTorrent, etc.)</td></tr>
<tr><td>block_country</td><td>CN, RU</td><td>Bloqueo geográfico</td></tr>
</tbody></table>
<h3>Reglas automáticas</h3>
<p>Con <code>auto_block: true</code> en config.yaml, las IPs que generan alertas CRITICAL se bloquean automáticamente. Revisar regularmente estas reglas.</p>
<div class="docs-warning">⚠ Las IPs locales (192.168.x.x) y el gateway nunca pueden bloquearse. La lista <code>protected_ips</code> en config.yaml garantiza esto.</div>
```

**Article 2.9** — `"id": "intelligence-view"`, `"title": "Intelligence — Threat Intelligence"`
```html
<h2>Intelligence — Threat Intelligence</h2>
<h3>Matriz MITRE ATT&amp;CK</h3>
<p>Las celdas coloreadas indican tácticas y técnicas detectadas en tu red. El color indica la frecuencia: más oscuro = más ocurrencias.</p>
<h3>Feeds OSINT</h3>
<table class="docs-table">
<thead><tr><th>Feed</th><th>Contenido</th><th>Actualización</th></tr></thead>
<tbody>
<tr><td>Feodo Tracker</td><td>IPs de botnets bancarias</td><td>Diaria</td></tr>
<tr><td>Abuse.ch SSL Blacklist</td><td>Certificados SSL maliciosos</td><td>Diaria</td></tr>
<tr><td>URLhaus</td><td>URLs de distribución de malware</td><td>Cada hora</td></tr>
</tbody></table>
<h3>JA3 Hashes</h3>
<p>Fingerprint del cliente TLS. Un JA3 conocido-malicioso indica que el software que inicia la conexión ha sido visto en malware, aunque la IP destino sea legítima.</p>
<h3>AbuseIPDB</h3>
<p>Un <code>abuse_score</code> &gt; 50 es motivo de investigación. &gt; 80 justifica bloqueo inmediato.</p>
```

**Article 2.10** — `"id": "forensics-view"`, `"title": "Forensics — Análisis forense"`
```html
<h2>Forensics — Análisis forense</h2>
<p>Usa esta vista para investigar un dispositivo o IP tras una alerta grave.</p>
<h3>Búsqueda</h3>
<p>Busca por IP (para hosts externos) o MAC (para dispositivos de la red local). La búsqueda por MAC incluye historial de IPs asignadas.</p>
<h3>Ejemplo de investigación</h3>
<ol>
<li>Alerta CRITICAL de <code>blacklisted_ip</code> con src_ip = 192.168.1.50</li>
<li>Ir a Forensics → buscar <code>192.168.1.50</code></li>
<li>Ver el timeline: cuándo empezó la comunicación, con qué IPs</li>
<li>Ver qué dominios DNS consultó antes de la conexión sospechosa</li>
<li>Identificar el dispositivo por MAC y su vendor</li>
<li>Poner el dispositivo en cuarentena desde Devices</li>
<li>Generar informe Forensic del período para documentar el incidente</li>
</ol>
<h3>Pivoting</h3>
<p>Clic en cualquier evento del timeline → ver flujos relacionados y alertas del mismo período.</p>
```

**Article 2.11** — `"id": "wifi-view"`, `"title": "WiFi — Análisis de redes"`
```html
<h2>WiFi — Análisis de redes</h2>
<div class="docs-warning">⚠ Requiere tarjeta WiFi con soporte de modo monitor. Solo usar en redes propias.</div>
<h3>Activar el scanner</h3>
<pre class="docs-code">wifi:
  enabled: true
  interface: wlan0mon</pre>
<h3>Calidad de señal</h3>
<table class="docs-table">
<thead><tr><th>dBm</th><th>Calidad</th></tr></thead>
<tbody>
<tr><td>&gt; -50</td><td>Excelente</td></tr>
<tr><td>-50 a -60</td><td>Buena</td></tr>
<tr><td>-60 a -70</td><td>Aceptable</td></tr>
<tr><td>&lt; -70</td><td>Débil</td></tr>
</tbody></table>
<h3>Evil Twin</h3>
<p>Red con el mismo SSID que tu router pero diferente BSSID. HomeNetGuard alerta cuando detecta dos redes con el mismo nombre. Desconectar de inmediato si aparece.</p>
<h3>Cifrado débil</h3>
<p>WEP y WPA-TKIP son vulnerables. Si tu router usa alguno, cambia a WPA2-AES o WPA3 en la configuración del router.</p>
```

**Article 2.12** — `"id": "academy-view"`, `"title": "Academy — Sección educativa"`
```html
<h2>Academy — Sección educativa</h2>
<p>La sección Academy (<a href="/learn">/learn</a>) contiene 60 tópicos de ciberseguridad en 6 categorías y 3 niveles de dificultad.</p>
<h3>Rutas de aprendizaje</h3>
<p>Itinerarios guiados que ordenan los tópicos por tema: Fundamentos de Red, Defensa Doméstica, etc.</p>
<h3>Progreso</h3>
<p>El progreso se guarda en <code>localStorage</code> del navegador bajo la clave <code>hng_learn_progress</code>. Sin backend, sin cuenta.</p>
<h3>Tooltips ⓘ</h3>
<p>Los iconos ⓘ en la UI abren una definición rápida del término. Clic en el enlace del tooltip va al artículo completo en Academy.</p>
```

**Article 2.13** — `"id": "api-docs-view"`, `"title": "API Docs — REST API"`
```html
<h2>API Docs — REST API</h2>
<p>URL base: <code>http://127.0.0.1:8080/api/v1</code></p>
<h3>Autenticación</h3>
<pre class="docs-code">curl -H "X-API-Key: $HNG_API_KEY" http://127.0.0.1:8080/api/v1/alerts</pre>
<h3>Ejemplos</h3>
<pre class="docs-code"># Alertas HIGH no reconocidas
curl -H "X-API-Key: $HNG_API_KEY" \
  "http://127.0.0.1:8080/api/v1/alerts?severity=high&amp;acknowledged=false"

# Bloquear una IP
curl -X POST -H "X-API-Key: $HNG_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"type":"block_ip","target":"1.2.3.4","reason":"Suspicious"}' \
  "http://127.0.0.1:8080/api/v1/firewall/rules"</pre>
<h3>Swagger UI</h3>
<p>Documentación interactiva en <a href="/api/docs">/api/docs</a>. Permite probar endpoints directamente desde el navegador.</p>
<h3>Errores comunes</h3>
<table class="docs-table">
<thead><tr><th>Código</th><th>Significado</th></tr></thead>
<tbody>
<tr><td>401</td><td>API key inválida o ausente</td></tr>
<tr><td>429</td><td>Rate limit excedido</td></tr>
<tr><td>500</td><td>Error interno — revisar logs</td></tr>
</tbody></table>
```

- [ ] **Step 4: Add Section 3 — CLI Reference (1 article)**

**Article 3.1** — `"id": "cli-reference"`, `"title": "Referencia completa de la CLI"`
```html
<h2>Referencia completa de la CLI</h2>
<h3>homenetguard start</h3>
<pre class="docs-code">homenetguard start [--interface IF] [--duration SECS] [--output PATH]
                   [--no-dashboard] [--no-tui]
                   [--enable-sinkhole] [--enable-firewall]</pre>
<h3>homenetguard status</h3>
<pre class="docs-code">$ homenetguard status
┌─────────────────────────────────────────────┐
│  HomeNetGuard v1.0.0 — System Status        │
├─────────────────────────────────────────────┤
│  Interface:     wlan0 (auto-detected)       │
│  Capture:       ● ACTIVE (00:14:32)         │
│  Dashboard:     ● http://127.0.0.1:5000     │
│  API Server:    ● http://127.0.0.1:8080     │
│  DNS Sinkhole:  ○ DISABLED                  │
│  ML Model:      ✓ TRAINED (2024-01-15)      │
│  Flows today:   14,823                      │
│  Alerts today:  3 (1 HIGH, 2 MEDIUM)        │
└─────────────────────────────────────────────┘</pre>
<h3>homenetguard analyze</h3>
<pre class="docs-code">homenetguard analyze --file PATH [--report] [--dpi] [--ml]</pre>
<h3>homenetguard report</h3>
<pre class="docs-code">homenetguard report [--type daily|weekly|forensic|compliance|custom]
                    [--from YYYY-MM-DD] [--to YYYY-MM-DD]
                    [--ip IP] [--mac MAC]
                    [--format html|pdf|both] [--output PATH]</pre>
<h3>Gestión de dispositivos</h3>
<pre class="docs-code">homenetguard devices scan
homenetguard devices list
homenetguard devices trust MAC
homenetguard devices quarantine MAC</pre>
<h3>Gestión del firewall</h3>
<pre class="docs-code">homenetguard firewall list
homenetguard firewall block-ip IP [--reason TEXT]
homenetguard firewall block-range CIDR
homenetguard firewall block-port PORT
homenetguard firewall block-country CODE
homenetguard firewall unblock ID
homenetguard firewall flush</pre>
<h3>DNS Sinkhole</h3>
<pre class="docs-code">homenetguard sinkhole start [--port PORT] [--upstream IP]
homenetguard sinkhole stop
homenetguard sinkhole add DOMAIN
homenetguard sinkhole remove DOMAIN
homenetguard sinkhole list</pre>
<h3>Machine Learning</h3>
<pre class="docs-code">homenetguard ml train [--days N]
homenetguard ml status
homenetguard ml threshold FLOAT</pre>
<h3>Feeds y alertas</h3>
<pre class="docs-code">homenetguard feeds update
homenetguard alerts list [--severity] [--type]
homenetguard alerts acknowledge ID
homenetguard alerts export</pre>
<h3>Exportación SIEM</h3>
<pre class="docs-code">homenetguard export --siem [splunk|elastic|graylog]
                    [--from DATE] [--to DATE] [--format cef|json]</pre>
```

- [ ] **Step 5: Add Section 4 — Advanced (6 articles)**

**Article 4.1** — `"id": "dns-sinkhole-config"`, `"title": "DNS Sinkhole — configuración"`
```html
<h2>DNS Sinkhole — configuración y uso</h2>
<p>El DNS sinkhole intercepta consultas DNS y devuelve 0.0.0.0 para dominios maliciosos, impidiendo la conexión.</p>
<h3>Activar</h3>
<pre class="docs-code">sinkhole:
  enabled: true
  port: 5353
  upstream_dns: 8.8.8.8</pre>
<pre class="docs-code">sudo homenetguard start --enable-sinkhole</pre>
<h3>Configurar como DNS del sistema</h3>
<p><strong>Linux (NetworkManager):</strong></p>
<pre class="docs-code">nmcli con mod "Wired connection 1" ipv4.dns "127.0.0.1"
nmcli con up "Wired connection 1"</pre>
<p><strong>macOS:</strong> System Preferences → Network → Advanced → DNS → añadir 127.0.0.1</p>
<p><strong>Router (para toda la red):</strong> Cambiar DNS primario a la IP del equipo con HomeNetGuard en la configuración DHCP del router.</p>
<h3>Estadísticas</h3>
<pre class="docs-code">homenetguard sinkhole list</pre>
<div class="docs-warning">⚠ El sinkhole no funciona con DoH (DNS-over-HTTPS) ni DoT (DNS-over-TLS). El tráfico DNS cifrado no puede interceptarse.</div>
```

**Article 4.2** — `"id": "firewall-advanced"`, `"title": "Firewall — configuración avanzada"`
```html
<h2>Firewall integrado — configuración avanzada</h2>
<h3>Cadenas iptables</h3>
<pre class="docs-code">sudo iptables -L HNG_INPUT -n --line-numbers
sudo iptables -L HNG_OUTPUT -n --line-numbers</pre>
<h3>Auto-block</h3>
<pre class="docs-code">firewall:
  auto_block: true
  auto_block_severity: critical   # solo bloquear CRITICAL</pre>
<div class="docs-warning">⚠ Con auto_block activo, un falso positivo CRITICAL puede bloquear tráfico legítimo. Solo activar si los detectores están bien calibrados.</div>
<h3>Bloqueo por país</h3>
<pre class="docs-code">homenetguard firewall block-country CN
homenetguard firewall block-country RU</pre>
<h3>Persistencia de reglas</h3>
<pre class="docs-code"># Debian/Ubuntu
sudo apt install iptables-persistent
sudo netfilter-persistent save</pre>
<h3>Backup y restore</h3>
<pre class="docs-code">sudo iptables-save > hng_rules_backup.txt
sudo iptables-restore < hng_rules_backup.txt</pre>
```

**Article 4.3** — `"id": "machine-learning"`, `"title": "Machine Learning — detección de anomalías"`
```html
<h2>Machine Learning — detección de anomalías</h2>
<p>HomeNetGuard usa un modelo Isolation Forest entrenado sobre el comportamiento normal de la red.</p>
<h3>Features del modelo</h3>
<ul>
<li>bytes por flujo</li>
<li>duración del flujo</li>
<li>puertos destino únicos por IP (ventana 5 min)</li>
<li>frecuencia de conexiones (beaconing score)</li>
<li>entropía del nombre de dominio DNS</li>
<li>proporción de flujos a IPs públicas vs privadas</li>
</ul>
<h3>Entrenamiento</h3>
<pre class="docs-code">homenetguard ml train --days 7</pre>
<p>Mínimo 3 días de datos. Recomendado 7. El modelo se guarda en <code>data/models/isolation_forest.pkl</code>.</p>
<h3>Interpretar anomaly_score</h3>
<ul>
<li>0.0 – 0.5 → normal</li>
<li>0.5 – 0.7 → inusual, observar</li>
<li>0.7 – 1.0 → anómalo, investigar</li>
</ul>
<h3>Ajustar umbral</h3>
<pre class="docs-code">homenetguard ml threshold 0.75</pre>
<p>Umbral más alto = menos falsos positivos, más falsos negativos. Ajustar según la calidad del entrenamiento.</p>
<h3>Cuándo re-entrenar</h3>
<p>Si cambias de router, añades dispositivos fijos nuevos, o el patrón de uso de la red cambia significativamente.</p>
```

**Article 4.4** — `"id": "siem-export"`, `"title": "Exportación a SIEM"`
```html
<h2>Exportación a SIEM</h2>
<h3>Splunk</h3>
<pre class="docs-code">siem:
  enabled: true
  backend: splunk
  host: 192.168.1.100
  port: 514
  protocol: udp
  format: cef</pre>
<h3>Elasticsearch + Kibana</h3>
<pre class="docs-code">siem:
  enabled: true
  backend: elastic
  host: localhost
  port: 9200
  protocol: http
  format: json</pre>
<p>En Kibana: Management → Index Patterns → crear patrón <code>homenetguard-*</code>.</p>
<h3>Graylog</h3>
<pre class="docs-code">siem:
  enabled: true
  backend: graylog
  host: localhost
  port: 12201
  protocol: udp
  format: gelf</pre>
<h3>Exportación histórica</h3>
<pre class="docs-code">homenetguard export --siem elastic --from 2024-01-01 --to 2024-01-31 --format json</pre>
<h3>Formato CEF</h3>
<pre class="docs-code">CEF:0|HomeNetGuard|HNG|1.0|port_scan|Port scan detected|7|src=1.2.3.4 dst=192.168.1.1 dpt=22</pre>
```

**Article 4.5** — `"id": "notifications"`, `"title": "Notificaciones y alertas externas"`
```html
<h2>Notificaciones y alertas externas</h2>
<h3>Email</h3>
<pre class="docs-code">alerts:
  email:
    enabled: true
    smtp_host: smtp.gmail.com
    smtp_port: 587
    username: tu@gmail.com
    min_severity: critical</pre>
<div class="docs-note">ℹ La contraseña SMTP va en .env como SMTP_PASSWORD.</div>
<h3>Telegram</h3>
<ol>
<li>Crear bot con @BotFather en Telegram → obtener token</li>
<li>Enviar un mensaje al bot → obtener chat_id via <code>https://api.telegram.org/bot{TOKEN}/getUpdates</code></li>
<li>Añadir al .env:
<pre class="docs-code">TELEGRAM_BOT_TOKEN=1234567890:ABCdef...
TELEGRAM_CHAT_ID=-1001234567890</pre></li>
</ol>
<h3>Apprise (Slack, Discord, Webhook)</h3>
<pre class="docs-code">alerts:
  apprise:
    enabled: true
    urls:
      - "slack://TokenA/TokenB/TokenC/#canal"
      - "discord://webhook_id/webhook_token"
    min_severity: medium</pre>
<h3>Test de notificaciones</h3>
<pre class="docs-code">homenetguard alerts test</pre>
```

**Article 4.6** — `"id": "data-retention"`, `"title": "Retención de datos y mantenimiento"`
```html
<h2>Retención de datos y mantenimiento</h2>
<h3>Dónde se almacenan los datos</h3>
<table class="docs-table">
<thead><tr><th>Tipo</th><th>Ruta</th><th>Tamaño típico</th></tr></thead>
<tbody>
<tr><td>Base de datos</td><td>data/homenetguard.db</td><td>10–500 MB según retención</td></tr>
<tr><td>Capturas PCAP</td><td>data/captures/</td><td>Variable</td></tr>
<tr><td>Logs</td><td>logs/homenetguard.log</td><td>~10 MB/semana</td></tr>
<tr><td>Modelos ML</td><td>data/models/</td><td>~5 MB</td></tr>
<tr><td>Informes</td><td>data/reports/</td><td>~1 MB/informe</td></tr>
</tbody></table>
<h3>Retención automática</h3>
<pre class="docs-code">storage:
  retention_days: 30   # Elimina datos más antiguos automáticamente</pre>
<h3>Limpieza manual</h3>
<pre class="docs-code">make clean
homenetguard purge --older-than 30</pre>
<h3>Backup de la DB</h3>
<pre class="docs-code">sqlite3 data/homenetguard.db ".backup backup_$(date +%Y%m%d).db"</pre>
<h3>Optimización SQLite</h3>
<pre class="docs-code">sqlite3 data/homenetguard.db "VACUUM; ANALYZE;"</pre>
```

- [ ] **Step 6: Add Section 5 — Technical (6 articles)**

**Article 5.1** — `"id": "architecture"`, `"title": "Arquitectura del sistema"`
```html
<h2>Arquitectura del sistema</h2>
<pre class="docs-code">┌─────────────────────────────────────────────────────┐
│                  PRESENTACIÓN                       │
│   CLI (Click)  │  TUI (Rich)  │  Dashboard (Flask)  │
│   API REST (Flask-RESTX)  │  Informes (Jinja2)     │
├─────────────────────────────────────────────────────┤
│               SERVICIOS ACTIVOS                     │
│   Firewall  │  DNS Sinkhole  │  Rate Limiter        │
│   Quarantine Manager                                │
├─────────────────────────────────────────────────────┤
│                   ANÁLISIS                          │
│   Traffic Analyzer  │  Threat Detector              │
│   DPI  │  TLS Fingerprint  │  OS Fingerprint        │
│   Beaconing  │  Cryptomining  │  ML Anomaly         │
├─────────────────────────────────────────────────────┤
│                 PERSISTENCIA                        │
│   SQLite  │  PCAP Files  │  ML Models               │
├─────────────────────────────────────────────────────┤
│                   CAPTURA                           │
│   Scapy Sniffer  │  PyShark  │  Device Scanner      │
│   Gateway Monitor  │  WiFi Scanner                  │
└─────────────────────────────────────────────────────┘</pre>
<h3>Flujo de datos</h3>
<ol>
<li>Scapy captura el paquete en la interfaz</li>
<li>El paquete pasa por el pipeline de análisis (DPI, TLS, OS fingerprint)</li>
<li>Se almacena como flujo en SQLite</li>
<li>Los detectores de amenazas analizan el flujo</li>
<li>Si se detecta una amenaza, se crea una alerta y se notifica</li>
<li>El dashboard muestra el flujo y la alerta en tiempo real via Socket.IO</li>
</ol>
<h3>Threading model</h3>
<ul>
<li>Hilo principal: Flask dashboard + Socket.IO</li>
<li>Daemon threads: sniffer, detectores, feed updater, device scanner</li>
</ul>
```

**Article 5.2** — `"id": "database-schema"`, `"title": "Esquema de base de datos"`
```html
<h2>Esquema de base de datos</h2>
<h3>Tablas principales</h3>
<table class="docs-table">
<thead><tr><th>Tabla</th><th>Descripción</th><th>Registros típicos</th></tr></thead>
<tbody>
<tr><td>flows</td><td>Flujos de red capturados</td><td>Millones</td></tr>
<tr><td>alerts</td><td>Alertas de seguridad</td><td>Miles</td></tr>
<tr><td>dns_queries</td><td>Consultas DNS</td><td>Cientos de miles</td></tr>
<tr><td>devices</td><td>Dispositivos de la red</td><td>Decenas</td></tr>
<tr><td>device_ip_history</td><td>Historial de IPs por MAC</td><td>Cientos</td></tr>
<tr><td>ip_reputation</td><td>Caché de reputación de IPs</td><td>Miles</td></tr>
<tr><td>firewall_rules</td><td>Reglas del firewall</td><td>Decenas</td></tr>
<tr><td>sinkhole_rules</td><td>Dominios bloqueados</td><td>Miles</td></tr>
<tr><td>reports</td><td>Metadatos de informes generados</td><td>Decenas</td></tr>
</tbody></table>
<h3>Consultas directas</h3>
<pre class="docs-code">sqlite3 data/homenetguard.db
.tables
.schema flows
SELECT * FROM alerts WHERE severity='critical' LIMIT 10;
SELECT src_ip, COUNT(*) as cnt FROM flows
  GROUP BY src_ip ORDER BY cnt DESC LIMIT 10;</pre>
```

**Article 5.3** — `"id": "detection-system"`, `"title": "Sistema de detección de amenazas"`
```html
<h2>Sistema de detección de amenazas</h2>
<h3>Port Scan</h3>
<p>Ventana deslizante de 60s. Si una IP contacta &gt; N puertos distintos del mismo destino, se genera una alerta. N configurable en <code>detection.port_scan.threshold</code>.</p>
<h3>Beaconing</h3>
<p>Analiza la desviación estándar de los intervalos entre conexiones a la misma IP. Baja desviación + intervalos regulares = comportamiento automatizado (C2).</p>
<h3>Flood</h3>
<p>Contador de bytes por IP en ventana temporal. Superar el umbral (<code>detection.flood.bytes_threshold</code>) genera alerta HIGH.</p>
<h3>ARP Spoofing</h3>
<p>Tabla IP↔MAC en memoria. Si una IP cambia de MAC, se genera alerta HIGH (posible MitM).</p>
<h3>DNS Anomaly</h3>
<p>Entropía de Shannon de subdominios &gt; umbral. Detección de DGA y DNS tunneling.</p>
<h3>TLS Anomaly</h3>
<p>Comparación de JA3 hash del cliente contra lista de hashes conocidos maliciosos.</p>
<h3>Cryptomining</h3>
<p>Matching de puertos Stratum (3333, 4444, 14444) y dominios de mining pools conocidos.</p>
<h3>ML Anomaly</h3>
<p>Isolation Forest sobre un vector de features por ventana de 5 minutos. Score &gt; threshold → alerta MEDIUM.</p>
```

**Article 5.4** — `"id": "api-technical"`, `"title": "API REST — referencia técnica"`
```html
<h2>API REST — referencia técnica</h2>
<p>URL base: <code>http://127.0.0.1:8080/api/v1</code>. Autenticación: header <code>X-API-Key</code>.</p>
<h3>Endpoints principales</h3>
<table class="docs-table">
<thead><tr><th>Método</th><th>Ruta</th><th>Descripción</th></tr></thead>
<tbody>
<tr><td>GET</td><td>/api/stats</td><td>Estadísticas del sistema</td></tr>
<tr><td>GET</td><td>/api/flows</td><td>Flujos recientes (limit, offset)</td></tr>
<tr><td>GET</td><td>/api/alerts</td><td>Alertas (severity, type)</td></tr>
<tr><td>POST</td><td>/api/alerts/{id}/acknowledge</td><td>Reconocer alerta</td></tr>
<tr><td>GET</td><td>/api/v2/devices</td><td>Lista de dispositivos</td></tr>
<tr><td>POST</td><td>/api/v2/devices/{mac}/trust</td><td>Marcar dispositivo como trusted</td></tr>
<tr><td>POST</td><td>/api/v2/devices/{mac}/quarantine</td><td>Poner en cuarentena</td></tr>
<tr><td>GET</td><td>/api/v2/firewall/rules</td><td>Reglas del firewall</td></tr>
<tr><td>POST</td><td>/api/v2/firewall/rules</td><td>Añadir regla</td></tr>
<tr><td>DELETE</td><td>/api/v2/firewall/rules/{id}</td><td>Eliminar regla</td></tr>
<tr><td>GET</td><td>/api/v2/sinkhole/rules</td><td>Dominios bloqueados</td></tr>
<tr><td>POST</td><td>/api/v2/sinkhole/rules</td><td>Añadir dominio</td></tr>
<tr><td>GET</td><td>/api/v2/forensics</td><td>Timeline forense por IP o MAC</td></tr>
<tr><td>GET</td><td>/api/v2/intelligence/mitre</td><td>Datos MITRE ATT&amp;CK</td></tr>
</tbody></table>
<h3>Códigos de error</h3>
<table class="docs-table">
<thead><tr><th>Código</th><th>Significado</th></tr></thead>
<tbody>
<tr><td>400</td><td>Parámetros inválidos</td></tr>
<tr><td>401</td><td>API key inválida</td></tr>
<tr><td>404</td><td>Recurso no encontrado</td></tr>
<tr><td>429</td><td>Rate limit excedido</td></tr>
<tr><td>500</td><td>Error interno</td></tr>
</tbody></table>
```

**Article 5.5** — `"id": "project-structure"`, `"title": "Estructura del proyecto"`
```html
<h2>Estructura del proyecto</h2>
<pre class="docs-code">homenetguard/
├── capture/          # Captura de paquetes (Scapy, PyShark)
│   ├── sniffer.py    # Sniffer principal
│   ├── pcap_reader.py
│   └── interface_detector.py
├── analysis/         # Análisis de tráfico y DPI
│   ├── traffic_analyzer.py
│   ├── threat_detector.py
│   ├── dpi_analyzer.py
│   ├── dns_analyzer.py
│   ├── tls_fingerprint.py
│   ├── os_fingerprint.py
│   ├── beaconing_detector.py
│   ├── anomaly_detector.py
│   ├── geo_lookup.py
│   └── reputation.py
├── active/           # Acciones defensivas
│   ├── firewall.py
│   ├── dns_sinkhole.py
│   ├── quarantine.py
│   └── rate_limiter.py
├── intelligence/     # Threat intelligence
│   ├── feed_manager.py
│   ├── mitre_mapper.py
│   └── compliance_checker.py
├── storage/          # Persistencia
│   ├── database.py
│   └── repository.py
├── dashboard/        # Flask web app
│   ├── app.py
│   ├── routes.py
│   ├── events.py     # Socket.IO events
│   ├── templates/
│   └── static/
├── reports/          # Generación de informes
└── alerts/           # Notificadores externos</pre>
<h3>Tests</h3>
<pre class="docs-code">pytest tests/ -v
pytest tests/ --cov=homenetguard --cov-report=html</pre>
<h3>Linting</h3>
<pre class="docs-code">ruff check .
mypy homenetguard/</pre>
```

**Article 5.6** — `"id": "contributing"`, `"title": "Cómo contribuir"`
```html
<h2>Cómo contribuir</h2>
<h3>Proceso</h3>
<ol>
<li>Fork del repositorio en GitHub</li>
<li>Crear branch: <code>git checkout -b feature/mi-feature</code></li>
<li>Implementar con tests</li>
<li>Asegurarse de que pasan todos los tests: <code>pytest tests/ -v</code></li>
<li>Abrir PR describiendo el cambio</li>
</ol>
<h3>Naming de branches</h3>
<ul>
<li><code>feature/</code> — nueva funcionalidad</li>
<li><code>fix/</code> — corrección de bug</li>
<li><code>docs/</code> — documentación</li>
</ul>
<h3>Conventional Commits</h3>
<pre class="docs-code">feat: add WiFi evil twin detection
fix: handle NXDOMAIN responses in dns_analyzer
docs: add sinkhole configuration guide</pre>
<h3>Añadir un detector nuevo</h3>
<ol>
<li>Crear <code>homenetguard/analysis/mi_detector.py</code> con clase <code>MiDetector</code></li>
<li>Implementar método <code>analyze(flow: dict) -&gt; Alert | None</code></li>
<li>Registrar en <code>threat_detector.py</code></li>
<li>Añadir tests en <code>tests/unit/test_mi_detector.py</code></li>
<li>Documentar en Docs: añadir artículo o sección en el artículo de detección</li>
</ol>
<h3>Licencia</h3>
<p>MIT. Permite uso, modificación y distribución libre, incluyendo uso comercial, con atribución.</p>
```

- [ ] **Step 7: Add Section 6 — Troubleshooting (1 article)**

**Article 6.1** — `"id": "troubleshooting"`, `"title": "Solución de problemas"`
```html
<h2>Solución de problemas</h2>
<table class="docs-table">
<thead><tr><th>Problema</th><th>Causa probable</th><th>Solución</th></tr></thead>
<tbody>
<tr><td>Permission denied al arrancar</td><td>Sin CAP_NET_RAW</td><td>sudo homenetguard start</td></tr>
<tr><td>No se captura tráfico</td><td>Interfaz incorrecta</td><td>homenetguard config --detect-interface</td></tr>
<tr><td>Dashboard no carga</td><td>Puerto 5000 ocupado</td><td>Cambiar port en config.yaml</td></tr>
<tr><td>DB crece demasiado</td><td>retention_days alto</td><td>Reducir retention_days y ejecutar purge</td></tr>
<tr><td>Muchos falsos positivos</td><td>Umbrales bajos</td><td>Ajustar threshold en detection.*</td></tr>
<tr><td>ML no detecta anomalías</td><td>Modelo no entrenado</td><td>homenetguard ml train</td></tr>
<tr><td>DNS sinkhole no bloquea</td><td>No es el DNS del sistema</td><td>Configurar 127.0.0.1 como DNS primario</td></tr>
<tr><td>Feeds no se actualizan</td><td>Sin acceso a Internet</td><td>Verificar conectividad</td></tr>
<tr><td>Alto consumo de CPU</td><td>Interfaz de alto volumen</td><td>Añadir capture_filter en config.yaml</td></tr>
<tr><td>Alertas no llegan a Telegram</td><td>Token o chat_id incorrectos</td><td>Verificar .env, homenetguard alerts test</td></tr>
</tbody></table>
<h3>Logs</h3>
<pre class="docs-code">tail -f logs/homenetguard.log</pre>
<h3>Modo DEBUG</h3>
<pre class="docs-code">logging:
  level: DEBUG</pre>
<h3>Reportar un bug</h3>
<p>Incluir en el issue: versión de HomeNetGuard (<code>homenetguard --version</code>), OS, interfaz de red, primeras 50 líneas del log con nivel DEBUG, y pasos para reproducir.</p>
```

- [ ] **Step 8: Verify all 32 article IDs are present**

Count in the JSON:
- Section 1: 5 articles (what-is-homenetguard, installation, initial-config, first-launch, permissions-security)
- Section 2: 13 articles (overview-view through api-docs-view)
- Section 3: 1 article (cli-reference)
- Section 4: 6 articles (dns-sinkhole-config through data-retention)
- Section 5: 6 articles (architecture through contributing)
- Section 6: 1 article (troubleshooting)
Total: 32 ✓

- [ ] **Step 9: Commit**

```bash
git add homenetguard/dashboard/static/data/docs_content.json
git commit -m "feat: add docs_content.json with 32 articles across 6 sections"
```

---

## Task 2: `docs.css` — styles

**Files:**
- Create: `homenetguard/dashboard/static/css/docs.css`

- [ ] **Step 1: Write docs.css**

```css
/* ── Docs layout ─────────────────────────────────────── */
.docs-layout {
  display: grid;
  grid-template-columns: 240px 1fr;
  gap: 0;
  min-height: calc(100vh - 56px);
}

.docs-nav {
  background: var(--bg-base);
  border-right: 1px solid var(--bg-border);
  padding: 24px 0;
  position: sticky;
  top: 56px;
  height: calc(100vh - 56px);
  overflow-y: auto;
}

.docs-nav-section {
  padding: 8px 20px 4px;
  font-size: 10px;
  letter-spacing: 2px;
  text-transform: uppercase;
  color: var(--text-muted);
  font-family: 'Inter', sans-serif;
}

.docs-nav-item {
  display: block;
  padding: 7px 20px;
  color: var(--text-secondary);
  text-decoration: none;
  font-size: 13px;
  border-left: 2px solid transparent;
  transition: all 0.15s;
}

.docs-nav-item:hover {
  color: var(--text-primary);
  background: var(--bg-elevated);
}

.docs-nav-item.active {
  color: var(--accent-primary);
  border-left-color: var(--accent-primary);
  background: var(--accent-glow);
}

/* ── Content ─────────────────────────────────────────── */
.docs-content {
  padding: 40px 48px;
  max-width: 860px;
}

.docs-content h1 {
  font-family: 'Orbitron', monospace;
  font-size: 22px;
  color: var(--text-primary);
  margin-bottom: 8px;
}

.docs-content h2 {
  font-size: 16px;
  color: var(--accent-cyan);
  border-bottom: 1px solid var(--bg-border);
  padding-bottom: 8px;
  margin-top: 40px;
  margin-bottom: 16px;
}

.docs-content h3 {
  font-size: 14px;
  color: var(--text-primary);
  margin-top: 24px;
  margin-bottom: 8px;
}

.docs-content p, .docs-content li {
  font-size: 13px;
  color: var(--text-secondary);
  line-height: 1.7;
}

.docs-content ul, .docs-content ol {
  padding-left: 20px;
  margin: 8px 0 16px;
}

.docs-content a { color: var(--accent-cyan); }
.docs-content code {
  font-family: 'JetBrains Mono', monospace;
  font-size: 11px;
  background: var(--bg-elevated);
  padding: 1px 5px;
  border: 1px solid var(--bg-border);
}

/* ── Code blocks ─────────────────────────────────────── */
.docs-code {
  background: var(--bg-base);
  border: 1px solid var(--bg-border);
  border-left: 3px solid var(--accent-primary);
  padding: 16px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  color: var(--text-mono, var(--text-primary));
  overflow-x: auto;
  position: relative;
  margin: 12px 0;
  white-space: pre;
}

.docs-code-copy {
  position: absolute;
  top: 8px;
  right: 8px;
  font-size: 10px;
  color: var(--text-muted);
  cursor: pointer;
  font-family: 'Inter', sans-serif;
  background: var(--bg-elevated);
  border: 1px solid var(--bg-border);
  padding: 2px 6px;
  transition: color 0.15s;
}

.docs-code-copy:hover { color: var(--text-primary); }

/* ── Callouts ────────────────────────────────────────── */
.docs-note {
  border-left: 3px solid var(--accent-cyan);
  background: var(--accent-cyan-glow, rgba(0, 212, 255, 0.06));
  padding: 12px 16px;
  margin: 16px 0;
  font-size: 13px;
  color: var(--text-secondary);
}

.docs-warning {
  border-left: 3px solid var(--severity-medium, #ffcc00);
  background: rgba(255, 204, 0, 0.08);
  padding: 12px 16px;
  margin: 16px 0;
  font-size: 13px;
  color: var(--text-secondary);
}

.docs-danger {
  border-left: 3px solid var(--severity-critical, #ff3b5c);
  background: rgba(255, 59, 92, 0.08);
  padding: 12px 16px;
  margin: 16px 0;
  font-size: 13px;
  color: var(--text-secondary);
}

/* ── Table ───────────────────────────────────────────── */
.docs-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
  margin: 16px 0;
}

.docs-table th {
  background: var(--bg-elevated);
  color: var(--text-secondary);
  padding: 8px 12px;
  text-align: left;
  font-weight: 600;
  border-bottom: 1px solid var(--bg-border);
}

.docs-table td {
  padding: 8px 12px;
  border-bottom: 1px solid var(--bg-border);
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  color: var(--text-secondary);
}

.docs-table tr:hover td { background: var(--bg-elevated); }

/* ── TOC ─────────────────────────────────────────────── */
.docs-toc {
  position: sticky;
  top: 80px;
  max-height: calc(100vh - 100px);
  overflow-y: auto;
  padding: 16px;
  border-left: 1px solid var(--bg-border);
  font-size: 12px;
  min-width: 180px;
}

.docs-toc-title {
  font-size: 10px;
  letter-spacing: 2px;
  text-transform: uppercase;
  color: var(--text-muted);
  margin-bottom: 8px;
}

.docs-toc-link {
  display: block;
  padding: 4px 0 4px 8px;
  color: var(--text-muted);
  text-decoration: none;
  border-left: 1px solid transparent;
  font-size: 12px;
  transition: all 0.15s;
}

.docs-toc-link:hover { color: var(--text-secondary); }
.docs-toc-link.active {
  color: var(--accent-cyan);
  border-left-color: var(--accent-cyan);
}

/* ── Misc ────────────────────────────────────────────── */
.docs-version {
  font-size: 10px;
  padding: 2px 6px;
  background: var(--bg-elevated);
  border: 1px solid var(--bg-border);
  color: var(--text-muted);
  font-family: 'JetBrains Mono', monospace;
}

.docs-breadcrumb {
  font-size: 12px;
  color: var(--text-muted);
  margin-bottom: 24px;
  font-family: 'Inter', sans-serif;
}

.docs-breadcrumb a { color: var(--accent-cyan); text-decoration: none; }
.docs-breadcrumb span { margin: 0 6px; }

/* ── Index page cards ────────────────────────────────── */
.docs-index-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
  gap: 16px;
  margin: 24px 0;
}

.docs-index-card {
  background: var(--bg-elevated);
  border: 1px solid var(--bg-border);
  padding: 20px;
  text-decoration: none;
  transition: border-color 0.15s;
  display: block;
}

.docs-index-card:hover { border-color: var(--accent-primary); }

.docs-index-card-title {
  font-size: 13px;
  color: var(--text-primary);
  font-weight: 600;
  margin-bottom: 6px;
}

.docs-index-card-desc {
  font-size: 12px;
  color: var(--text-muted);
}

.docs-index-card-count {
  font-size: 10px;
  color: var(--accent-primary);
  margin-top: 8px;
  font-family: 'JetBrains Mono', monospace;
}

/* ── Search ──────────────────────────────────────────── */
.docs-search-wrap {
  margin: 24px 0;
  position: relative;
}

.docs-search-input {
  width: 100%;
  padding: 10px 16px;
  background: var(--bg-elevated);
  border: 1px solid var(--bg-border);
  color: var(--text-primary);
  font-size: 13px;
  font-family: 'Inter', sans-serif;
  box-sizing: border-box;
}

.docs-search-input:focus {
  outline: none;
  border-color: var(--accent-primary);
}

.docs-search-results {
  position: absolute;
  top: 100%;
  left: 0;
  right: 0;
  background: var(--bg-elevated);
  border: 1px solid var(--bg-border);
  border-top: none;
  max-height: 320px;
  overflow-y: auto;
  z-index: 100;
  display: none;
}

.docs-search-results.visible { display: block; }

.docs-search-result {
  display: block;
  padding: 10px 16px;
  text-decoration: none;
  border-bottom: 1px solid var(--bg-border);
  transition: background 0.1s;
}

.docs-search-result:hover { background: var(--bg-base); }

.docs-search-result-title {
  font-size: 13px;
  color: var(--text-primary);
}

.docs-search-result-section {
  font-size: 11px;
  color: var(--text-muted);
  margin-top: 2px;
}

.docs-search-result-desc {
  font-size: 11px;
  color: var(--text-muted);
  margin-top: 2px;
}

.docs-search-no-results {
  padding: 16px;
  font-size: 13px;
  color: var(--text-muted);
  text-align: center;
}
```

- [ ] **Step 2: Commit**

```bash
git add homenetguard/dashboard/static/css/docs.css
git commit -m "feat: add docs.css for docs section styling"
```

---

## Task 3: `docs.js` — client-side behavior

**Files:**
- Create: `homenetguard/dashboard/static/js/docs.js`

- [ ] **Step 1: Write docs.js**

```javascript
/* docs.js — search, scroll spy, copy buttons */

(function () {
  'use strict';

  let _docsData = null;

  async function loadDocs() {
    if (_docsData) return _docsData;
    const res = await fetch('/api/v1/docs/content');
    _docsData = await res.json();
    return _docsData;
  }

  // ── Search ──────────────────────────────────────────────────
  function initSearch() {
    const input = document.getElementById('docs-search-input');
    const results = document.getElementById('docs-search-results');
    if (!input || !results) return;

    input.addEventListener('input', async function () {
      const q = this.value.trim().toLowerCase();
      if (q.length < 2) {
        results.classList.remove('visible');
        return;
      }

      const data = await loadDocs();
      const matches = [];
      for (const section of data.sections) {
        for (const article of section.articles) {
          const inTitle = article.title.toLowerCase().includes(q);
          const inDesc = (article.description || '').toLowerCase().includes(q);
          const inTags = (article.tags || []).some(t => t.includes(q));
          if (inTitle || inDesc || inTags) {
            matches.push({ section, article });
            if (matches.length >= 8) break;
          }
        }
        if (matches.length >= 8) break;
      }

      if (matches.length === 0) {
        results.innerHTML = '<div class="docs-search-no-results">No results found</div>';
      } else {
        results.innerHTML = matches.map(({ section, article }) => `
          <a class="docs-search-result" href="/docs/${section.id}/${article.id}">
            <div class="docs-search-result-title">${article.title}</div>
            <div class="docs-search-result-section">${section.title}</div>
            ${article.description ? `<div class="docs-search-result-desc">${article.description}</div>` : ''}
          </a>
        `).join('');
      }
      results.classList.add('visible');
    });

    document.addEventListener('click', function (e) {
      if (!input.contains(e.target) && !results.contains(e.target)) {
        results.classList.remove('visible');
      }
    });
  }

  // ── Scroll spy ───────────────────────────────────────────────
  function initScrollSpy() {
    const tocLinks = document.querySelectorAll('.docs-toc-link');
    if (!tocLinks.length) return;

    const headings = Array.from(document.querySelectorAll('.docs-content h2, .docs-content h3'));

    function onScroll() {
      let current = null;
      for (const h of headings) {
        if (h.getBoundingClientRect().top <= 120) current = h.id;
      }
      tocLinks.forEach(link => {
        link.classList.toggle('active', link.getAttribute('href') === '#' + current);
      });
    }

    window.addEventListener('scroll', onScroll, { passive: true });
    onScroll();
  }

  // ── Nav active item ──────────────────────────────────────────
  function initNavActive() {
    const current = window.location.pathname;
    document.querySelectorAll('.docs-nav-item').forEach(link => {
      if (link.getAttribute('href') === current) {
        link.classList.add('active');
      }
    });
  }

  // ── Copy buttons ─────────────────────────────────────────────
  function initCopyButtons() {
    document.querySelectorAll('pre.docs-code, .docs-code').forEach(block => {
      if (block.querySelector('.docs-code-copy')) return;
      const btn = document.createElement('span');
      btn.className = 'docs-code-copy';
      btn.textContent = 'Copy';
      btn.addEventListener('click', function () {
        const text = block.innerText.replace(/\nCopy$/, '').trim();
        navigator.clipboard.writeText(text).then(() => {
          btn.textContent = 'Copied!';
          setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
        });
      });
      block.style.position = 'relative';
      block.appendChild(btn);
    });
  }

  // ── Auto-generate heading IDs for TOC ───────────────────────
  function initHeadingIds() {
    document.querySelectorAll('.docs-content h2, .docs-content h3').forEach(h => {
      if (!h.id) {
        h.id = h.textContent.trim().toLowerCase()
          .replace(/[^a-z0-9\s-]/g, '')
          .replace(/\s+/g, '-');
      }
    });
  }

  // ── Init ─────────────────────────────────────────────────────
  document.addEventListener('DOMContentLoaded', function () {
    initHeadingIds();
    initSearch();
    initScrollSpy();
    initNavActive();
    initCopyButtons();
  });
})();
```

- [ ] **Step 2: Commit**

```bash
git add homenetguard/dashboard/static/js/docs.js
git commit -m "feat: add docs.js with search, scroll spy, and copy buttons"
```

---

## Task 4: Flask routes

**Files:**
- Modify: `homenetguard/dashboard/routes.py`

- [ ] **Step 1: Add `_load_docs()` helper and routes**

After the `_load_curriculum` block (line ~25 in routes.py), add:

```python
# ─── Docs loader ─────────────────────────────────────
_DOCS_PATH = Path(__file__).parent / "static" / "data" / "docs_content.json"
_docs_cache: dict | None = None

def _load_docs() -> dict:
    global _docs_cache
    if _docs_cache is None:
        try:
            with open(_DOCS_PATH, encoding="utf-8") as f:
                _docs_cache = json.load(f)
        except Exception:
            _docs_cache = {"sections": [], "version": "1.0.0"}
    return _docs_cache

def _find_docs_article(section_id: str, article_id: str) -> tuple[dict | None, dict | None]:
    docs = _load_docs()
    section = next((s for s in docs.get("sections", []) if s["id"] == section_id), None)
    if not section:
        return None, None
    article = next((a for a in section.get("articles", []) if a["id"] == article_id), None)
    return section, article
```

After the `/wifi` route (around line 108), add the docs routes:

```python
# ─── Docs routes ─────────────────────────────────────────────

@bp.route("/docs")
def docs_index():
    docs = _load_docs()
    return render_template("docs/index.html", docs=docs)


@bp.route("/docs/<section_id>")
def docs_section(section_id: str):
    docs = _load_docs()
    section = next((s for s in docs.get("sections", []) if s["id"] == section_id), None)
    if not section:
        return render_template("docs/index.html", docs=docs)
    return render_template("docs/section.html", docs=docs, section=section)


@bp.route("/docs/<section_id>/<article_id>")
def docs_article(section_id: str, article_id: str):
    docs = _load_docs()
    section, article = _find_docs_article(section_id, article_id)
    if not article:
        return render_template("docs/index.html", docs=docs)
    # prev/next within section
    articles = section.get("articles", [])
    idx = next((i for i, a in enumerate(articles) if a["id"] == article_id), None)
    prev_article = articles[idx - 1] if idx and idx > 0 else None
    next_article = articles[idx + 1] if idx is not None and idx < len(articles) - 1 else None
    return render_template(
        "docs/article.html",
        docs=docs,
        section=section,
        article=article,
        prev_article=prev_article,
        next_article=next_article,
    )


@bp.route("/api/v1/docs/content")
def api_docs_content():
    return jsonify(_load_docs())


@bp.route("/api/v1/docs/search")
def api_docs_search():
    q = request.args.get("q", "").lower().strip()
    docs = _load_docs()
    results = []
    for section in docs.get("sections", []):
        for article in section.get("articles", []):
            if (q in article["title"].lower()
                    or q in (article.get("description") or "").lower()
                    or any(q in t for t in article.get("tags", []))):
                results.append({
                    "section_id": section["id"],
                    "section_title": section["title"],
                    "article_id": article["id"],
                    "title": article["title"],
                    "description": article.get("description", ""),
                    "url": f"/docs/{section['id']}/{article['id']}",
                })
    return jsonify(results[:10])
```

- [ ] **Step 2: Commit**

```bash
git add homenetguard/dashboard/routes.py
git commit -m "feat: add /docs routes and _load_docs() helper"
```

---

## Task 5: Templates

**Files:**
- Create: `homenetguard/dashboard/templates/docs/index.html`
- Create: `homenetguard/dashboard/templates/docs/section.html`
- Create: `homenetguard/dashboard/templates/docs/article.html`

- [ ] **Step 1: Create `docs/index.html`**

```html
{% extends "base.html" %}
{% block title %}Documentation — HomeNetGuard{% endblock %}
{% block content %}
<link rel="stylesheet" href="{{ url_for('static', filename='css/docs.css') }}">

<div class="page-header">
  <span class="page-title">DOCUMENTATION</span>
  <span class="docs-version">v{{ docs.version }}</span>
</div>

<div style="padding: 0 32px 40px;">
  <div class="docs-search-wrap">
    <input id="docs-search-input" class="docs-search-input"
           type="search" placeholder="Search documentation…" autocomplete="off">
    <div id="docs-search-results" class="docs-search-results"></div>
  </div>

  <div class="docs-index-grid">
    {% for section in docs.sections %}
    <a class="docs-index-card" href="/docs/{{ section.id }}">
      <div class="docs-index-card-title">{{ section.title }}</div>
      <div class="docs-index-card-desc">{{ section.description }}</div>
      <div class="docs-index-card-count">{{ section.articles|length }} articles</div>
    </a>
    {% endfor %}
  </div>

  <div style="margin-top: 40px;">
    <div style="font-size:0.65rem;letter-spacing:0.12em;color:var(--text-muted);text-transform:uppercase;margin-bottom:12px;">QUICK START</div>
    <div style="display:flex;flex-direction:column;gap:4px;">
      <a href="/docs/getting-started/what-is-homenetguard" style="color:var(--accent-cyan);font-size:13px;text-decoration:none;">→ ¿Qué es HomeNetGuard?</a>
      <a href="/docs/getting-started/installation" style="color:var(--accent-cyan);font-size:13px;text-decoration:none;">→ Instalación y requisitos</a>
      <a href="/docs/getting-started/first-launch" style="color:var(--accent-cyan);font-size:13px;text-decoration:none;">→ Primer arranque</a>
      <a href="/docs/cli-reference/cli-reference" style="color:var(--accent-cyan);font-size:13px;text-decoration:none;">→ Referencia de la CLI</a>
      <a href="/docs/troubleshooting/troubleshooting" style="color:var(--accent-cyan);font-size:13px;text-decoration:none;">→ Solución de problemas</a>
    </div>
  </div>
</div>

<script src="{{ url_for('static', filename='js/docs.js') }}" defer></script>
{% endblock %}
```

- [ ] **Step 2: Create `docs/section.html`**

```html
{% extends "base.html" %}
{% block title %}{{ section.title }} — HomeNetGuard Docs{% endblock %}
{% block content %}
<link rel="stylesheet" href="{{ url_for('static', filename='css/docs.css') }}">

<div class="docs-layout">
  <!-- Left nav -->
  <nav class="docs-nav">
    {% for s in docs.sections %}
    <div class="docs-nav-section">{{ s.title }}</div>
    {% for article in s.articles %}
    <a class="docs-nav-item {% if s.id == section.id and article.id == (request.view_args.get('article_id','')) %}active{% endif %}"
       href="/docs/{{ s.id }}/{{ article.id }}">{{ article.title }}</a>
    {% endfor %}
    {% endfor %}
  </nav>

  <!-- Main content -->
  <div class="docs-content">
    <div class="docs-breadcrumb">
      <a href="/docs">Docs</a><span>›</span>{{ section.title }}
    </div>
    <h1>{{ section.title }}</h1>
    <p style="color:var(--text-muted);font-size:13px;margin-bottom:32px;">{{ section.description }}</p>

    <div style="display:flex;flex-direction:column;gap:12px;">
      {% for article in section.articles %}
      <a href="/docs/{{ section.id }}/{{ article.id }}"
         style="display:block;background:var(--bg-elevated);border:1px solid var(--bg-border);padding:16px 20px;text-decoration:none;transition:border-color 0.15s;">
        <div style="font-size:13px;color:var(--text-primary);font-weight:600;margin-bottom:4px;">{{ article.title }}</div>
        {% if article.description %}
        <div style="font-size:12px;color:var(--text-muted);">{{ article.description }}</div>
        {% endif %}
      </a>
      {% endfor %}
    </div>
  </div>
</div>

<script src="{{ url_for('static', filename='js/docs.js') }}" defer></script>
{% endblock %}
```

- [ ] **Step 3: Create `docs/article.html`**

```html
{% extends "base.html" %}
{% block title %}{{ article.title }} — HomeNetGuard Docs{% endblock %}
{% block content %}
<link rel="stylesheet" href="{{ url_for('static', filename='css/docs.css') }}">

<div class="docs-layout">
  <!-- Left nav -->
  <nav class="docs-nav">
    <div style="padding:8px 20px 12px;">
      <input id="docs-search-input" class="docs-search-input"
             type="search" placeholder="Search…" autocomplete="off" style="font-size:12px;padding:6px 10px;">
      <div id="docs-search-results" class="docs-search-results"></div>
    </div>
    {% for s in docs.sections %}
    <div class="docs-nav-section">{{ s.title }}</div>
    {% for a in s.articles %}
    <a class="docs-nav-item {% if s.id == section.id and a.id == article.id %}active{% endif %}"
       href="/docs/{{ s.id }}/{{ a.id }}">{{ a.title }}</a>
    {% endfor %}
    {% endfor %}
  </nav>

  <!-- Article + TOC wrapper -->
  <div style="display:grid;grid-template-columns:1fr 200px;align-items:start;">
    <div class="docs-content">
      <div class="docs-breadcrumb">
        <a href="/docs">Docs</a><span>›</span>
        <a href="/docs/{{ section.id }}">{{ section.title }}</a><span>›</span>
        {{ article.title }}
      </div>

      {{ article.content | safe }}

      <!-- Prev / Next navigation -->
      <div style="display:flex;justify-content:space-between;margin-top:48px;padding-top:16px;border-top:1px solid var(--bg-border);">
        {% if prev_article %}
        <a href="/docs/{{ section.id }}/{{ prev_article.id }}"
           style="color:var(--accent-cyan);font-size:13px;text-decoration:none;">← {{ prev_article.title }}</a>
        {% else %}<span></span>{% endif %}
        {% if next_article %}
        <a href="/docs/{{ section.id }}/{{ next_article.id }}"
           style="color:var(--accent-cyan);font-size:13px;text-decoration:none;">{{ next_article.title }} →</a>
        {% endif %}
      </div>

      {% if article.updated_at %}
      <div style="margin-top:24px;font-size:11px;color:var(--text-muted);">Updated {{ article.updated_at }}</div>
      {% endif %}
    </div>

    <!-- Sticky TOC -->
    <div class="docs-toc">
      <div class="docs-toc-title">On this page</div>
      <div id="docs-toc-links"></div>
    </div>
  </div>
</div>

<script src="{{ url_for('static', filename='js/docs.js') }}" defer></script>
<script>
document.addEventListener('DOMContentLoaded', function () {
  const container = document.getElementById('docs-toc-links');
  if (!container) return;
  document.querySelectorAll('.docs-content h2, .docs-content h3').forEach(h => {
    const link = document.createElement('a');
    link.className = 'docs-toc-link' + (h.tagName === 'H3' ? ' toc-h3' : '');
    link.href = '#' + h.id;
    link.textContent = h.textContent;
    if (h.tagName === 'H3') link.style.paddingLeft = '16px';
    container.appendChild(link);
  });
});
</script>
{% endblock %}
```

- [ ] **Step 4: Commit**

```bash
git add homenetguard/dashboard/templates/docs/
git commit -m "feat: add docs templates (index, section, article)"
```

---

## Task 6: Sidebar item

**Files:**
- Modify: `homenetguard/dashboard/templates/base.html`

- [ ] **Step 1: Add Docs nav item before Academy**

In `base.html`, find the line:
```html
      <a href="/learn" class="nav-item {% if request.path.startswith('/learn') %}active{% endif %}">
```

Insert immediately before it:
```html
      <a href="/docs" class="nav-item {% if request.path.startswith('/docs') %}active{% endif %}">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><line x1="8" y1="9" x2="10" y2="9"/></svg>
        Docs
      </a>
```

- [ ] **Step 2: Commit**

```bash
git add homenetguard/dashboard/templates/base.html
git commit -m "feat: add Docs item to sidebar nav"
```

---

## Task 7: Tests

**Files:**
- Create: `tests/unit/test_docs_routes.py`

- [ ] **Step 1: Write failing tests**

```python
import pytest
from homenetguard.storage import database
from homenetguard.dashboard.app import create_app


@pytest.fixture
def cfg(tmp_path):
    return {
        "storage": {"db_path": str(tmp_path / "test.db"), "reports_path": str(tmp_path / "reports")},
        "dashboard": {"host": "127.0.0.1", "port": 5000, "auto_open_browser": False},
        "geoip": {"enabled": False},
        "threat_intelligence": {"abuseipdb": {"enabled": False}, "virustotal": {"enabled": False}},
        "alerts": {"email": {"enabled": False}, "telegram": {"enabled": False}},
        "logging": {"level": "ERROR", "file": str(tmp_path / "test.log")},
    }


@pytest.fixture
def client(cfg, tmp_path):
    database.init_db(str(tmp_path / "test.db"))
    app = create_app(cfg)
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_docs_index_returns_200(client):
    res = client.get("/docs")
    assert res.status_code == 200


def test_docs_getting_started_section(client):
    res = client.get("/docs/getting-started")
    assert res.status_code == 200


def test_docs_article_what_is(client):
    res = client.get("/docs/getting-started/what-is-homenetguard")
    assert res.status_code == 200


def test_docs_article_installation(client):
    res = client.get("/docs/getting-started/installation")
    assert res.status_code == 200


def test_docs_article_cli_reference(client):
    res = client.get("/docs/cli-reference/cli-reference")
    assert res.status_code == 200


def test_docs_article_troubleshooting(client):
    res = client.get("/docs/troubleshooting/troubleshooting")
    assert res.status_code == 200


def test_docs_unknown_article_returns_index(client):
    res = client.get("/docs/getting-started/nonexistent-article")
    assert res.status_code == 200


def test_docs_unknown_section_returns_index(client):
    res = client.get("/docs/nonexistent-section")
    assert res.status_code == 200


def test_api_docs_content_returns_json(client):
    res = client.get("/api/v1/docs/content")
    assert res.status_code == 200
    data = res.get_json()
    assert "sections" in data
    assert len(data["sections"]) == 6


def test_api_docs_search(client):
    res = client.get("/api/v1/docs/search?q=firewall")
    assert res.status_code == 200
    data = res.get_json()
    assert isinstance(data, list)


def test_docs_index_contains_all_sections(client):
    res = client.get("/docs")
    html = res.data.decode()
    assert "Getting Started" in html
    assert "User Guide" in html
    assert "CLI Reference" in html
    assert "Troubleshooting" in html


def test_docs_nav_item_active_on_docs_page(client):
    res = client.get("/docs")
    html = res.data.decode()
    assert 'href="/docs"' in html
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/Sergio/Documents/01-Proyectos/01-SW/homeNetGuard
pytest tests/unit/test_docs_routes.py -v
```

Expected: multiple FAILs with `404` or `ImportError` (routes not added yet).

- [ ] **Step 3: Run all tests to ensure baseline passes**

```bash
pytest tests/ -v
```

Expected: existing tests pass, new docs tests fail.

- [ ] **Step 4: After implementing Tasks 1–6, run docs tests again**

```bash
pytest tests/unit/test_docs_routes.py -v
```

Expected: all 13 tests PASS.

- [ ] **Step 5: Run full test suite**

```bash
pytest tests/ -v
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add tests/unit/test_docs_routes.py
git commit -m "test: add docs route tests"
```

---

## Verification Checklist

- [ ] `/docs` returns 200 and shows 6 section cards
- [ ] `/docs/getting-started` lists 5 articles
- [ ] `/docs/getting-started/what-is-homenetguard` renders article content
- [ ] All 32 article URLs return 200 (no 404)
- [ ] Search input in nav filters articles in real time
- [ ] Copy buttons appear on all `pre.docs-code` blocks
- [ ] Scroll spy updates TOC active item on scroll
- [ ] "Docs" nav item appears between Config/WiFi group and Academy in sidebar
- [ ] "Docs" nav item has active class when on any `/docs/*` page
- [ ] `pytest tests/ -v` — all pre-existing tests pass
