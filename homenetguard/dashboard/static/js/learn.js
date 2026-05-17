/**
 * learn.js — Cyber Academy tooltip system + progress helpers
 * No modifica ningún JS existente. Se carga en todas las páginas
 * pero solo actúa cuando encuentra elementos data-learn-term.
 */

const TOOLTIP_TERMS = {
  "TCP":          { slug: "tcp-protocol",          short: "Protocolo orientado a conexión. Garantiza entrega ordenada de datos mediante el three-way handshake (SYN→SYN-ACK→ACK)." },
  "UDP":          { slug: "udp-protocol",          short: "Protocolo sin conexión. Más rápido que TCP, sin garantía de entrega. Usado en DNS, NTP y streaming." },
  "DNS":          { slug: "dns-fundamentals",      short: "Sistema de resolución de nombres de dominio a IPs. Escucha en puerto 53/UDP. El protocolo más explotado para C2." },
  "ARP":          { slug: "mac-arp",               short: "Mapea IPs a MACs en la red local. Sin autenticación — vulnerable a ARP spoofing para ataques MITM." },
  "TLS":          { slug: "tls-ssl",               short: "Protocolo de cifrado en tránsito. Protege HTTPS (puerto 443). TLS 1.3 es la versión actual." },
  "HTTPS":        { slug: "tls-ssl",               short: "HTTP cifrado con TLS. El candado no garantiza que el servidor sea legítimo — solo que el tráfico está cifrado." },
  "ICMP":         { slug: "icmp",                  short: "Mensajes de control de red. Usado por ping (echo) y traceroute (TTL exceeded). Puede usarse para tunneling." },
  "SSH":          { slug: "ssh-protocol",          short: "Acceso remoto seguro (puerto 22). Brute force en SSH es ataque muy común. Prefiere claves sobre contraseñas." },
  "JA3":          { slug: "tls-ssl",               short: "Fingerprint del cliente TLS: hash MD5 de versión, cipher suites y extensiones. Identifica aplicaciones aunque el tráfico esté cifrado." },
  "port_scan":    { slug: "port-scanning",         short: "Reconocimiento de puertos abiertos en un host. HomeNetGuard alerta si se escanean 15+ puertos en 60 segundos." },
  "beaconing":    { slug: "c2-beaconing",          short: "Comunicación periódica de malware con servidor C2. Intervalos regulares con jitter mínimo son la señal clave." },
  "flood":        { slug: "ddos",                  short: "Ataque DoS por saturación de tráfico. Tipos: SYN flood, UDP flood, HTTP flood." },
  "arp_spoof":    { slug: "arp-spoofing",          short: "Falsificación de la tabla ARP para interceptar tráfico de red local (MITM)." },
  "arp_spoofing": { slug: "arp-spoofing",          short: "Falsificación de la tabla ARP para interceptar tráfico de red local (MITM)." },
  "cryptomining": { slug: "cryptojacking",         short: "Minería no autorizada de criptomonedas usando recursos del sistema. Protocolo Stratum en puertos 3333/14444." },
  "MITRE":        { slug: "mitre-attack",          short: "Framework de tácticas y técnicas de ciberataques reales. Cubre 14 tácticas y 200+ técnicas con casos reales." },
  "IOC":          { slug: "iocs",                  short: "Indicator of Compromise: IP, dominio, hash, JA3 u otro artefacto observable de actividad maliciosa." },
  "SMB":          { slug: "lateral-movement",      short: "Server Message Block (puerto 445). Protocolo de compartición de archivos Windows. Vector común de movimiento lateral." },
  "CVE":          { slug: "vulnerability-management", short: "Identificador estándar de vulnerabilidades. Formato CVE-YYYY-NNNNN. Cada CVE tiene un score CVSS de 0-10." },
  "VLAN":         { slug: "network-segmentation",  short: "Virtual LAN — segmentación lógica de la red sin hardware extra. Clave para aislar IoT del resto de la red." },
  "CIDR":         { slug: "subnets-cidr",          short: "Notación de subredes. /24 = 254 hosts, /16 = 65534 hosts. Ejemplo: 192.168.1.0/24." },
  "ASN":          { slug: "bgp-routing",           short: "Autonomous System Number. Identifica el operador de un bloque de IPs. AS13335=Cloudflare, AS15169=Google." },
  "NAT":          { slug: "nat",                   short: "Permite que múltiples dispositivos compartan una IP pública. NAT no es seguridad — es solo traducción de direcciones." },
  "VPN":          { slug: "vpn",                   short: "Red Privada Virtual. Cifra y tuneliza el tráfico. WireGuard (UDP 51820) y OpenVPN (UDP 1194) son los más comunes." },
  "lateral":      { slug: "lateral-movement",      short: "Movimiento de un atacante dentro de la red comprometida. Se desplaza de sistema en sistema usando Pass-the-Hash o RDP." },
  "exfiltration": { slug: "data-exfiltration",     short: "Robo de datos hacia el exterior. Técnicas: DNS tunneling, HTTPS covert channel, timing channels." },
  "dns_tunnel":   { slug: "data-exfiltration",     short: "Exfiltración de datos codificados dentro de consultas DNS. HomeNetGuard detecta subdominios de alta entropía." },
  "quarantine":   { slug: "zero-trust",            short: "Aislamiento de red de un dispositivo sospechoso. HomeNetGuard usa iptables para bloquear todo su tráfico." },
  "compliance":   { slug: "system-hardening",      short: "Cumplimiento de estándares de seguridad (CIS Controls). El compliance score de HomeNetGuard evalúa controles básicos." },
  "anomaly":      { slug: "ids-ips",               short: "Desviación estadística del comportamiento normal. La detección por anomalías complementa la detección por firmas." },
  "fingerprint":  { slug: "tls-ssl",               short: "Identificador único derivado de características observables de un protocolo. JA3 es el fingerprint TLS más común." },
};

// ─── Tooltip injection ────────────────────────────────────────
function initTooltips() {
  document.querySelectorAll('[data-learn-term]').forEach(el => {
    // Skip if already processed
    if (el.dataset.tooltipDone) return;
    el.dataset.tooltipDone = '1';

    const term = el.getAttribute('data-learn-term');
    const info = TOOLTIP_TERMS[term];
    if (!info) return;

    // Wrap content in tooltip host
    const host = document.createElement('span');
    host.className = 'learn-tooltip-host';

    // Move existing children into host
    while (el.firstChild) host.appendChild(el.firstChild);

    // Add icon
    const icon = document.createElement('sup');
    icon.className = 'learn-tooltip-icon';
    icon.textContent = ' ⓘ';
    icon.addEventListener('click', (e) => {
      e.stopPropagation();
      e.preventDefault();
      window.location.href = `/learn/${info.slug}`;
    });

    // Add tooltip bubble
    const bubble = document.createElement('div');
    bubble.className = 'learn-tooltip-bubble';
    bubble.innerHTML = `<strong style="color:var(--text-primary)">${term}</strong><br>${info.short}<br><a href="/learn/${info.slug}" style="color:var(--accent-cyan);font-size:0.65rem;">Leer más →</a>`;

    host.appendChild(icon);
    host.appendChild(bubble);
    el.appendChild(host);
  });
}

// ─── Progress tracking ────────────────────────────────────────
const PROGRESS_KEY = 'hng_learn_progress';

function getProgress() {
  try { return JSON.parse(localStorage.getItem(PROGRESS_KEY) || '{"completed":[]}'); }
  catch { return { completed: [] }; }
}

function markCompleted(slug) {
  const p = getProgress();
  if (!p.completed.includes(slug)) p.completed.push(slug);
  localStorage.setItem(PROGRESS_KEY, JSON.stringify(p));
  _updateProgressWidgets();
}

function markIncomplete(slug) {
  const p = getProgress();
  p.completed = p.completed.filter(s => s !== slug);
  localStorage.setItem(PROGRESS_KEY, JSON.stringify(p));
  _updateProgressWidgets();
}

function isCompleted(slug) {
  return getProgress().completed.includes(slug);
}

function _updateProgressWidgets() {
  // Update any .progress-bar-fill elements on the current page
  const fills = document.querySelectorAll('[data-progress-slug]');
  fills.forEach(el => {
    const slug = el.dataset.progressSlug;
    if (isCompleted(slug)) el.classList.add('completed');
    else el.classList.remove('completed');
  });
}

// Expose globally
window.markCompleted = markCompleted;
window.markIncomplete = markIncomplete;
window.isCompleted = isCompleted;
window.getLearnProgress = getProgress;

// ─── Run after DOM ready ──────────────────────────────────────
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initTooltips);
} else {
  initTooltips();
}

// Expose globally so pages can call it after rendering tables
window.initLearnTooltips = initTooltips;
