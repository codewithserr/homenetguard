# UI Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete visual redesign — dark cyberpunk design system (neon green, JetBrains Mono + Geist, CRT effects, corner brackets) without touching any Python files.

**Architecture:** New CSS layer (tokens → effects → components → dashboard), new ui.js + charts.js, rewritten base.html layout (sidebar left + topbar), then each template rewritten preserving all Jinja2 variables and JS logic.

**Tech Stack:** Tailwind CDN, Geist + JetBrains Mono (Google Fonts), Material Symbols Outlined, Chart.js (existing vendor), Leaflet (existing vendor), Socket.IO (existing vendor).

**Critical corrections vs. spec:**
- Blueprint is `"main"` → use `url_for('main.index')`, `url_for('main.alerts_view')` etc., OR use hardcoded paths (`href="/"`) — current templates use `request.path` for active detection; keep that pattern.
- No `threats` endpoint exists → nav "Threat Center" links to `/alerts` (`main.alerts_view`).
- No `websocket.js` file — websocket code lives in `dashboard.js`; keep that reference in base.html, drop `websocket.js`.
- `learn.html` (root) is a legacy file; active learn templates are `learn/index.html` and `learn/topic.html`.

---

## File Map

**Create:**
- `homenetguard/dashboard/static/css/tokens.css`
- `homenetguard/dashboard/static/css/effects.css`
- `homenetguard/dashboard/static/css/components.css`
- `homenetguard/dashboard/static/js/ui.js`
- `homenetguard/dashboard/static/js/charts.js`

**Modify (CSS):**
- `homenetguard/dashboard/static/css/dashboard.css` — strip old vars/layout, keep only page-specific classes that remain useful
- `homenetguard/dashboard/static/css/learn.css` — update vars to new tokens
- `homenetguard/dashboard/static/css/docs.css` — update vars to new tokens

**Modify (Templates):**
- `homenetguard/dashboard/templates/base.html`
- `homenetguard/dashboard/templates/index.html`
- `homenetguard/dashboard/templates/alerts.html`
- `homenetguard/dashboard/templates/flows.html`
- `homenetguard/dashboard/templates/devices.html`
- `homenetguard/dashboard/templates/dns.html`
- `homenetguard/dashboard/templates/firewall.html`
- `homenetguard/dashboard/templates/intelligence.html`
- `homenetguard/dashboard/templates/forensics.html`
- `homenetguard/dashboard/templates/reports.html`
- `homenetguard/dashboard/templates/wifi.html`
- `homenetguard/dashboard/templates/config.html`
- `homenetguard/dashboard/templates/learn/index.html`
- `homenetguard/dashboard/templates/learn/topic.html`
- `homenetguard/dashboard/templates/docs/index.html`
- `homenetguard/dashboard/templates/docs/section.html`
- `homenetguard/dashboard/templates/docs/article.html`

---

## Task 1: Create tokens.css

**Files:**
- Create: `homenetguard/dashboard/static/css/tokens.css`

- [ ] **Step 1: Create tokens.css with the full design token set**

```css
:root {
  --surface-dim:              #131313;
  --surface:                  #131313;
  --surface-container-lowest: #0e0e0e;
  --surface-container-low:    #1c1b1b;
  --surface-container:        #201f1f;
  --surface-container-high:   #2a2a2a;
  --surface-container-highest:#353534;
  --surface-variant:          #353534;
  --surface-bright:           #3a3939;
  --surface-tint:             #00e639;
  --primary:                  #ebffe2;
  --primary-container:        #00ff41;
  --primary-fixed:            #72ff70;
  --primary-fixed-dim:        #00e639;
  --on-primary:               #003907;
  --on-primary-container:     #007117;
  --on-primary-fixed:         #002203;
  --on-primary-fixed-variant: #00530e;
  --inverse-primary:          #006e16;
  --secondary:                #98cbff;
  --secondary-container:      #00a2fd;
  --secondary-fixed:          #cfe5ff;
  --secondary-fixed-dim:      #98cbff;
  --on-secondary:             #003354;
  --on-secondary-container:   #003558;
  --on-secondary-fixed:       #001d33;
  --on-secondary-fixed-variant:#004a77;
  --error:                    #ffb4ab;
  --error-container:          #93000a;
  --on-error:                 #690005;
  --on-error-container:       #ffdad6;
  --on-surface:               #e5e2e1;
  --on-surface-variant:       #b9ccb2;
  --on-background:            #e5e2e1;
  --inverse-surface:          #e5e2e1;
  --inverse-on-surface:       #313030;
  --outline:                  #84967e;
  --outline-variant:          #3b4b37;
  --tertiary:                 #fff7f6;
  --tertiary-container:       #ffd2cd;
  --tertiary-fixed:           #ffdad6;
  --tertiary-fixed-dim:       #ffb4ab;
  --on-tertiary:              #690006;
  --on-tertiary-container:    #c40015;
  --on-tertiary-fixed:        #410002;
  --on-tertiary-fixed-variant:#93000c;
  --glow-primary:   rgba(0, 230, 57, 0.4);
  --glow-primary-sm:rgba(0, 230, 57, 0.3);
  --glow-error:     rgba(255, 180, 171, 0.3);
  --margin:   24px;
  --gutter:   16px;
  --unit:     4px;
}

.font-label-caps {
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  line-height: 1.0;
  letter-spacing: 0.1em;
  font-weight: 700;
}
.font-code-md {
  font-family: 'JetBrains Mono', monospace;
  font-size: 14px;
  line-height: 1.5;
  font-weight: 400;
}
.font-body-md  { font-family: 'Geist', sans-serif; font-size: 16px; line-height: 1.6; font-weight: 400; }
.font-body-lg  { font-family: 'Geist', sans-serif; font-size: 18px; line-height: 1.6; font-weight: 400; }
.font-headline-sm { font-family: 'Geist', sans-serif; font-size: 24px; line-height: 1.3; font-weight: 600; }
.font-headline-md { font-family: 'Geist', sans-serif; font-size: 32px; line-height: 1.2; letter-spacing: -0.01em; font-weight: 700; }
.font-headline-lg { font-family: 'Geist', sans-serif; font-size: 48px; line-height: 1.1; letter-spacing: -0.02em; font-weight: 700; }
```

- [ ] **Step 2: Verify file written correctly**

```bash
head -5 homenetguard/dashboard/static/css/tokens.css
```
Expected: `:root {`

---

## Task 2: Create effects.css

**Files:**
- Create: `homenetguard/dashboard/static/css/effects.css`

- [ ] **Step 1: Create effects.css**

```css
body {
  background-color: var(--surface-dim);
  background-image: radial-gradient(circle, #3b4b37 1px, transparent 1px);
  background-size: 24px 24px;
  color: var(--on-surface);
  overflow-x: hidden;
}

.crt-overlay {
  position: fixed;
  top: 0; left: 0; width: 100%; height: 100%;
  background:
    linear-gradient(rgba(18,16,16,0) 50%, rgba(0,0,0,0.1) 50%),
    linear-gradient(90deg, rgba(255,0,0,0.02), rgba(0,255,0,0.01), rgba(0,0,255,0.02));
  background-size: 100% 3px, 3px 100%;
  pointer-events: none;
  z-index: 9999;
  opacity: 0.15;
}

.corner-bracket { position: relative; }
.corner-bracket::before, .corner-bracket::after,
.corner-bracket .cb-bottom::before, .corner-bracket .cb-bottom::after {
  content: '';
  position: absolute;
  width: 8px; height: 8px;
  border-color: var(--surface-tint);
  pointer-events: none;
  z-index: 1;
}
.corner-bracket::before      { top: -1px; left: -1px;   border-top: 1px solid; border-left: 1px solid; }
.corner-bracket::after       { top: -1px; right: -1px;  border-top: 1px solid; border-right: 1px solid; }
.corner-bracket .cb-bottom::before { bottom: -1px; left: -1px;  border-bottom: 1px solid; border-left: 1px solid; }
.corner-bracket .cb-bottom::after  { bottom: -1px; right: -1px; border-bottom: 1px solid; border-right: 1px solid; }
.corner-bracket-subtle::before, .corner-bracket-subtle::after,
.corner-bracket-subtle .cb-bottom::before, .corner-bracket-subtle .cb-bottom::after {
  border-color: var(--outline-variant);
}

.scan-line {
  height: 2px;
  background: var(--surface-tint);
  box-shadow: 0 0 10px var(--surface-tint);
  position: absolute;
  width: 100%; top: 0;
  animation: scanline 4s linear infinite;
  opacity: 0.2;
  pointer-events: none;
  z-index: 2;
}
@keyframes scanline { 0% { top: 0%; } 100% { top: 100%; } }

.pulse-node { animation: pulse-node 2s ease-in-out infinite; }
@keyframes pulse-node {
  0%   { transform: scale(1);   opacity: 0.8; }
  50%  { transform: scale(1.5); opacity: 0.3; }
  100% { transform: scale(1);   opacity: 0.8; }
}

.terminal-cursor {
  display: inline-block;
  width: 8px; height: 1.2em;
  background: var(--surface-tint);
  animation: blink 1s step-end infinite;
  vertical-align: middle;
}
@keyframes blink { 50% { opacity: 0; } }

.glow-sm      { box-shadow: 0 0 8px  var(--glow-primary-sm); }
.glow-primary { box-shadow: 0 0 15px var(--glow-primary); }
.glow-error   { box-shadow: 0 0 12px var(--glow-error); }

@keyframes flicker {
  0%   { opacity: 0.97; } 5%  { opacity: 0.85; } 10% { opacity: 1; }
  15%  { opacity: 0.95; } 20% { opacity: 1;    } 100%{ opacity: 1; }
}
.flicker-hover:hover { animation: flicker 0.2s infinite; }

::-webkit-scrollbar       { width: 4px; height: 4px; }
::-webkit-scrollbar-track { background: var(--surface-container-lowest); }
::-webkit-scrollbar-thumb { background: var(--outline-variant); }
::-webkit-scrollbar-thumb:hover { background: var(--outline); }

::selection { background: var(--surface-tint); color: var(--on-primary); }
```

---

## Task 3: Create components.css

**Files:**
- Create: `homenetguard/dashboard/static/css/components.css`

- [ ] **Step 1: Create components.css**

```css
/* PANELS */
.panel         { background: var(--surface-container-low);  border: 1px solid var(--outline-variant); position: relative; }
.panel-dark    { background: var(--surface-container-lowest); border: 1px solid var(--outline-variant); position: relative; }
.panel-elevated{ background: var(--surface-container-high); border: 1px solid var(--outline-variant); position: relative; }

/* TABLES */
.data-table { width: 100%; text-align: left; font-family: 'JetBrains Mono', monospace; font-size: 14px; border-collapse: collapse; }
.data-table thead tr { border-bottom: 1px solid color-mix(in srgb, var(--outline-variant) 50%, transparent); }
.data-table thead th { padding: 12px 16px; font-size: 12px; letter-spacing: 0.1em; font-weight: 700; color: var(--outline); }
.data-table tbody tr { border-bottom: 1px solid color-mix(in srgb, var(--outline-variant) 20%, transparent); transition: background 0.15s; }
.data-table tbody tr:hover { background: color-mix(in srgb, var(--primary) 5%, transparent); }
.data-table tbody tr.row-danger:hover { background: color-mix(in srgb, var(--error) 5%, transparent); }
.data-table tbody td { padding: 14px 16px; color: var(--on-surface); }
.data-table .td-ip { color: color-mix(in srgb, var(--primary) 70%, transparent); }
.data-table .td-muted { color: var(--outline); }

/* legacy aliases used in existing JS-rendered HTML */
.ip-address { font-family: 'JetBrains Mono', monospace; color: color-mix(in srgb, var(--primary) 70%, transparent); }
.text-mono  { font-family: 'JetBrains Mono', monospace; color: var(--on-surface); }
.text-muted { color: var(--outline); }
.text-secondary { color: var(--on-surface-variant); }
.port       { font-family: 'JetBrains Mono', monospace; color: var(--secondary); }

/* BADGES */
.badge {
  display: inline-block; padding: 2px 8px;
  font-family: 'JetBrains Mono', monospace; font-size: 10px; font-weight: 700;
  letter-spacing: 0.05em; border: 1px solid;
}
.badge-verified   { background: color-mix(in srgb, var(--primary) 10%, transparent); color: var(--surface-tint); border-color: color-mix(in srgb, var(--primary) 20%, transparent); }
.badge-quarantined{ background: color-mix(in srgb, var(--error) 10%, transparent);   color: var(--error); border-color: color-mix(in srgb, var(--error) 20%, transparent); }
.badge-critical   { background: color-mix(in srgb, var(--error-container) 20%, transparent); color: var(--error); border-color: var(--error); box-shadow: 0 0 12px var(--glow-error); }
.badge-high       { background: rgba(255,180,0,0.1); color: #ffb400; border-color: rgba(255,180,0,0.4); }
.badge-medium     { background: rgba(255,204,0,0.1); color: #ffcc00; border-color: rgba(255,204,0,0.3); }
.badge-low        { background: color-mix(in srgb, var(--secondary) 10%, transparent); color: var(--secondary); border-color: color-mix(in srgb, var(--secondary) 30%, transparent); }
.badge-resolved   { color: var(--surface-tint); background: transparent; border-color: transparent; }
/* protocol badges (legacy names from existing JS) */
.badge-tcp  { background: color-mix(in srgb, var(--secondary) 10%, transparent); color: var(--secondary); border-color: color-mix(in srgb, var(--secondary) 30%, transparent); }
.badge-udp  { background: rgba(0,230,57,0.08); color: var(--surface-tint); border-color: rgba(0,230,57,0.2); }
.badge-icmp { background: rgba(255,180,0,0.08); color: #ffb400; border-color: rgba(255,180,0,0.2); }
.badge-dns  { background: rgba(255,204,0,0.08); color: #ffcc00; border-color: rgba(255,204,0,0.2); }

/* BUTTONS */
.btn, .btn-primary {
  padding: 8px 16px; border: 1px solid var(--surface-tint); color: var(--surface-tint);
  font-family: 'JetBrains Mono', monospace; font-size: 10px; font-weight: 700;
  letter-spacing: 0.1em; text-transform: uppercase; transition: all 0.2s; cursor: pointer;
  background: transparent; text-decoration: none; display: inline-flex; align-items: center;
}
.btn:hover, .btn-primary:hover { background: var(--surface-tint); color: var(--on-primary); box-shadow: 0 0 8px var(--glow-primary-sm); }
.btn-ghost {
  padding: 6px 12px; border: 1px solid var(--outline-variant); color: var(--outline);
  font-family: 'JetBrains Mono', monospace; font-size: 10px; font-weight: 700;
  letter-spacing: 0.1em; text-transform: uppercase; transition: all 0.2s; cursor: pointer;
  background: transparent; text-decoration: none; display: inline-flex; align-items: center;
}
.btn-ghost:hover { border-color: var(--on-surface); color: var(--on-surface); }
.btn-danger {
  padding: 6px 16px; border: 1px solid var(--error); color: var(--error);
  font-family: 'JetBrains Mono', monospace; font-size: 10px; font-weight: 700;
  letter-spacing: 0.1em; text-transform: uppercase; transition: all 0.2s; cursor: pointer;
  background: transparent; text-decoration: none; display: inline-flex; align-items: center;
}
.btn-danger:hover { background: var(--error); color: var(--on-error); }

/* TERMINAL PANEL */
.terminal-panel { background: #050505; border: 1px solid var(--outline-variant); font-family: 'JetBrains Mono', monospace; font-size: 12px; color: color-mix(in srgb, var(--surface-tint) 80%, transparent); position: relative; overflow: hidden; }
.terminal-header { background: var(--surface-container-high); border-bottom: 1px solid var(--outline-variant); padding: 8px 16px; display: flex; justify-content: space-between; align-items: center; }
.terminal-dots { display: flex; gap: 6px; }
.terminal-dot  { width: 10px; height: 10px; border-radius: 50%; }
.terminal-body { padding: 16px; overflow-y: auto; height: 100%; line-height: 1.6; }
.log-line-tint     { color: var(--surface-tint); }
.log-line-error    { color: var(--error); }
.log-line-muted    { color: color-mix(in srgb, var(--outline) 50%, transparent); }
.log-line-secondary{ color: var(--secondary); }

/* KPI CARDS */
.kpi-card { background: var(--surface-container-low); border: 1px solid var(--outline-variant); padding: 16px; position: relative; display: flex; flex-direction: column; align-items: center; }
.kpi-label { font-family: 'JetBrains Mono', monospace; font-size: 10px; letter-spacing: 0.1em; font-weight: 700; color: var(--outline); text-transform: uppercase; margin-bottom: 8px; }
.kpi-value { font-family: 'JetBrains Mono', monospace; font-size: 24px; font-weight: 700; color: var(--surface-tint); line-height: 1; }
.kpi-delta { font-family: 'JetBrains Mono', monospace; font-size: 10px; color: var(--outline); margin-top: 4px; }
.kpi-danger .kpi-value { color: var(--error); }
.kpi-warn .kpi-value   { color: #ffb400; }
.kpi-cyan .kpi-value   { color: var(--secondary); }
.kpi-bar  { width: 100%; height: 2px; background: var(--surface-variant); margin-top: 8px; }
.kpi-bar-fill { height: 100%; background: var(--surface-tint); transition: width 0.5s ease; }

/* QUICK ACTIONS */
.quick-action { display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 16px; border: 1px solid var(--outline-variant); cursor: pointer; transition: all 0.2s; gap: 8px; background: transparent; }
.quick-action:hover { border-color: var(--surface-tint); background: color-mix(in srgb, var(--surface-tint) 5%, transparent); }
.quick-action:hover .material-symbols-outlined { transform: scale(1.1); }
.quick-action .material-symbols-outlined { color: var(--surface-tint); transition: transform 0.2s; }
.quick-action span:last-child { font-family: 'JetBrains Mono', monospace; font-size: 10px; font-weight: 700; letter-spacing: 0.05em; color: var(--on-surface-variant); }

/* GAUGE */
.gauge-container { position: relative; width: 192px; height: 192px; display: flex; align-items: center; justify-content: center; }
.gauge-value  { position: absolute; display: flex; flex-direction: column; align-items: center; }
.gauge-number { font-family: 'Geist', sans-serif; font-size: 48px; font-weight: 700; line-height: 1; letter-spacing: -0.02em; color: var(--surface-tint); }
.gauge-label  { font-family: 'JetBrains Mono', monospace; font-size: 10px; letter-spacing: 0.1em; color: var(--outline); }

/* PROGRESS BAR */
.progress-bar  { width: 100%; height: 4px; background: var(--surface-container-highest); }
.progress-fill { height: 100%; background: var(--surface-tint); box-shadow: 0 0 8px rgba(0,230,57,0.6); transition: width 0.5s ease; }
/* alias used in learn templates */
.progress-bar-fill { height: 100%; background: var(--surface-tint); transition: width 0.5s ease; }
.progress-bar-fill.zero { background: var(--outline-variant); }

/* TABS */
.tab-bar  { display: flex; border-bottom: 1px solid var(--outline-variant); }
.tab-item { padding: 12px 16px; font-family: 'JetBrains Mono', monospace; font-size: 12px; font-weight: 700; letter-spacing: 0.1em; text-transform: uppercase; cursor: pointer; transition: all 0.2s; color: var(--outline); border-bottom: 2px solid transparent; margin-bottom: -1px; }
.tab-item:hover { color: var(--on-surface); }
.tab-item.active { color: var(--surface-tint); border-bottom-color: var(--surface-tint); background: color-mix(in srgb, var(--surface-tint) 5%, transparent); }

/* FILTER CONTROLS */
.filter-bar { display: flex; gap: 8px; padding: 12px 16px; flex-wrap: wrap; align-items: center; border-bottom: 1px solid var(--outline-variant); }
.filter-select { background: var(--surface-container-low); border: 1px solid var(--outline-variant); color: var(--on-surface); font-family: 'JetBrains Mono', monospace; font-size: 12px; padding: 6px 10px; outline: none; cursor: pointer; }
.filter-input  { background: var(--surface-container-low); border: 1px solid var(--outline-variant); color: var(--on-surface); font-family: 'JetBrains Mono', monospace; font-size: 12px; padding: 6px 10px; outline: none; }
.filter-input:focus, .filter-select:focus { border-color: var(--surface-tint); }

/* EMPTY STATE */
.empty-state { text-align: center; padding: 40px; color: var(--outline); font-family: 'JetBrains Mono', monospace; font-size: 12px; }
.empty-state-icon { display: block; font-size: 2rem; margin-bottom: 8px; opacity: 0.3; }

/* MODAL */
.modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.7); z-index: 200; display: flex; align-items: center; justify-content: center; }
.modal-overlay.hidden { display: none; }
.modal { background: var(--surface-container); border: 1px solid var(--outline-variant); padding: 24px; max-width: 96vw; max-height: 90vh; overflow-y: auto; min-width: 320px; }
.modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; padding-bottom: 12px; border-bottom: 1px solid var(--outline-variant); }
.modal-title { font-family: 'JetBrains Mono', monospace; font-size: 12px; font-weight: 700; letter-spacing: 0.1em; color: var(--on-surface); }
.modal-close { background: transparent; border: none; color: var(--outline); cursor: pointer; font-size: 16px; padding: 4px; }
.modal-close:hover { color: var(--on-surface); }

/* GRID HELPERS */
.grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: var(--gutter); }
.grid-4 { display: grid; grid-template-columns: repeat(4,1fr); gap: var(--gutter); }
.mt-gap { margin-top: var(--gutter); }
.table-scroll { overflow-x: auto; }

/* CHART CONTAINER */
.chart-container { position: relative; }

/* PANEL HEADER */
.panel-header { display: flex; align-items: center; justify-content: space-between; padding: 12px 16px; border-bottom: 1px solid var(--outline-variant); }
.panel-title  { font-family: 'JetBrains Mono', monospace; font-size: 11px; font-weight: 700; letter-spacing: 0.12em; color: var(--outline); text-transform: uppercase; }

/* PAGE HEADER */
.page-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: var(--gutter); }
.page-title  { font-family: 'Geist', sans-serif; font-size: 24px; font-weight: 600; color: var(--on-surface); }

/* LEARN LINK */
.learn-link { display: inline-flex; align-items: center; justify-content: center; width: 16px; height: 16px; border-radius: 50%; border: 1px solid var(--outline-variant); color: var(--outline); font-size: 10px; text-decoration: none; margin-left: 4px; transition: all 0.15s; vertical-align: middle; }
.learn-link:hover { border-color: var(--surface-tint); color: var(--surface-tint); }

/* INDICATORS */
.indicator { display: inline-block; width: 8px; height: 8px; border-radius: 50%; }
.indicator-live    { background: var(--surface-tint); box-shadow: 0 0 6px var(--glow-primary-sm); }
.indicator-offline { background: var(--outline); }
```

- [ ] **Step 2: Verify no syntax errors by checking file size**

```bash
wc -l homenetguard/dashboard/static/css/components.css
```
Expected: > 100 lines

---

## Task 4: Create ui.js and charts.js

**Files:**
- Create: `homenetguard/dashboard/static/js/ui.js`
- Create: `homenetguard/dashboard/static/js/charts.js`

- [ ] **Step 1: Create ui.js**

```javascript
document.addEventListener('DOMContentLoaded', () => {

  // Tab switching
  document.querySelectorAll('.tab-item').forEach(tab => {
    tab.addEventListener('click', () => {
      const tabBar = tab.closest('.tab-bar');
      const targetId = tab.dataset.tab;
      tabBar.querySelectorAll('.tab-item').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      const container = tabBar.nextElementSibling;
      if (container) {
        container.querySelectorAll('[data-tab-panel]').forEach(panel => {
          panel.classList.toggle('hidden', panel.dataset.tabPanel !== targetId);
        });
      }
    });
  });

  // Topbar search
  const searchInput = document.querySelector('input[placeholder="CMD_SEARCH..."]');
  if (searchInput) {
    searchInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        const q = searchInput.value.trim();
        if (q) window.location.href = `/docs?q=${encodeURIComponent(q)}`;
      }
    });
  }

  // UTC clock
  const clockEl = document.getElementById('utc-clock');
  if (clockEl) {
    const tick = () => { clockEl.textContent = new Date().toUTCString().slice(17,25) + ' UTC'; };
    tick(); setInterval(tick, 1000);
  }

  // INITIATE SCAN button
  const scanBtn = document.getElementById('btn-initiate-scan');
  if (scanBtn) {
    scanBtn.addEventListener('click', async () => {
      scanBtn.textContent = 'SCANNING...';
      scanBtn.disabled = true;
      try {
        await fetch('/api/v1/devices/scan', { method: 'POST',
          headers: { 'X-API-Key': window.HNG_API_KEY || '' }
        });
      } catch(e) { /* silent */ }
      setTimeout(() => { scanBtn.textContent = 'INITIATE SCAN'; scanBtn.disabled = false; }, 3000);
    });
  }

});
```

- [ ] **Step 2: Create charts.js**

```javascript
const HNG_CHART_THEME = {
  primary:   '#00e639',
  secondary: '#98cbff',
  error:     '#ffb4ab',
  muted:     '#3b4b37',
  text:      '#84967e',

  trafficDataset: (data) => ({
    data,
    borderColor: '#00e639',
    borderWidth: 2,
    backgroundColor: (ctx) => {
      const g = ctx.chart.ctx.createLinearGradient(0, 0, 0, ctx.chart.height);
      g.addColorStop(0, 'rgba(0,230,57,0.2)');
      g.addColorStop(1, 'rgba(0,230,57,0)');
      return g;
    },
    fill: true, tension: 0.4, pointRadius: 0, pointHoverRadius: 4,
    pointHoverBackgroundColor: '#00e639',
  }),

  secondaryDataset: (data) => ({
    data, borderColor: '#98cbff', borderWidth: 1.5,
    backgroundColor: 'rgba(152,203,255,0.05)', fill: true, tension: 0.4, pointRadius: 0,
  }),
};

if (typeof Chart !== 'undefined') {
  Chart.defaults.color          = '#84967e';
  Chart.defaults.font.family    = "'JetBrains Mono', monospace";
  Chart.defaults.font.size      = 11;
  Chart.defaults.borderColor    = '#3b4b37';
  Chart.defaults.backgroundColor = '#00e639';

  const scaleDefaults = {
    grid:  { color: '#3b4b37', lineWidth: 0.5 },
    ticks: { color: '#84967e', font: { family: "'JetBrains Mono', monospace", size: 10 } },
    border:{ color: '#3b4b37' }
  };
  Chart.defaults.scales = Chart.defaults.scales || {};
  Chart.defaults.plugins.tooltip = {
    backgroundColor: '#0e0e0e', borderColor: '#3b4b37', borderWidth: 1,
    titleColor: '#00e639', bodyColor: '#e5e2e1',
    titleFont: { family: "'JetBrains Mono', monospace", size: 11 },
    bodyFont:  { family: "'JetBrains Mono', monospace", size: 11 },
    padding: 12,
  };
  Chart.defaults.plugins.legend = { display: false };
}
```

---

## Task 5: Rewrite base.html

**Files:**
- Modify: `homenetguard/dashboard/templates/base.html`

- [ ] **Step 1: Rewrite base.html**

Key corrections vs. spec:
- Use `request.path` for active nav detection (not `request.endpoint`)
- Blueprint is "main" → use `url_for('main.index')` etc.
- No `threats` endpoint → Threat Center links to `/alerts`
- Keep `dashboard.js` reference (has websocket + chart init), add `ui.js` + `charts.js`
- Drop `websocket.js` (doesn't exist as separate file)

```html
<!DOCTYPE html>
<html class="dark" lang="es">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>HomeNetGuard | {% block title %}Mission Control{% endblock %}</title>

  <script src="https://cdn.tailwindcss.com?plugins=forms,container-queries"></script>

  <link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap" rel="stylesheet"/>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Geist:wght@400;600;700&display=swap" rel="stylesheet"/>

  <link rel="stylesheet" href="{{ url_for('static', filename='css/tokens.css') }}"/>
  <link rel="stylesheet" href="{{ url_for('static', filename='css/effects.css') }}"/>
  <link rel="stylesheet" href="{{ url_for('static', filename='css/components.css') }}"/>
  <link rel="stylesheet" href="{{ url_for('static', filename='css/dashboard.css') }}"/>
  <link rel="stylesheet" href="{{ url_for('static', filename='css/vendor/leaflet.css') }}"/>
  {% block styles %}{% endblock %}

  <script>
    tailwind.config = {
      darkMode: "class",
      theme: {
        extend: {
          colors: {
            "surface-tint": "#00e639", "surface-dim": "#131313", "surface": "#131313",
            "surface-container-lowest": "#0e0e0e", "surface-container-low": "#1c1b1b",
            "surface-container": "#201f1f", "surface-container-high": "#2a2a2a",
            "surface-container-highest": "#353534", "surface-variant": "#353534",
            "primary": "#ebffe2", "primary-container": "#00ff41", "primary-fixed": "#72ff70",
            "primary-fixed-dim": "#00e639", "on-primary": "#003907",
            "secondary": "#98cbff", "secondary-container": "#00a2fd",
            "error": "#ffb4ab", "error-container": "#93000a", "on-error": "#690005",
            "on-surface": "#e5e2e1", "on-surface-variant": "#b9ccb2",
            "outline": "#84967e", "outline-variant": "#3b4b37",
            "inverse-primary": "#006e16", "background": "#131313",
          },
          fontFamily: {
            "sans": ["Geist", "sans-serif"],
            "mono": ["JetBrains Mono", "monospace"],
          },
          spacing: { "margin": "24px", "gutter": "16px" },
        }
      }
    }
  </script>
</head>

<body class="dark overflow-x-hidden" style="font-family:'Geist',sans-serif;">

  <div class="crt-overlay"></div>

  <!-- SIDEBAR -->
  <aside style="width:256px;height:100vh;position:fixed;left:0;top:0;display:flex;flex-direction:column;padding:24px 0;background:var(--surface-dim);border-right:1px solid var(--outline-variant);z-index:60;">

    <!-- Brand -->
    <div style="padding:0 24px;margin-bottom:32px;">
      <div style="font-family:'Geist',sans-serif;font-size:20px;font-weight:700;color:var(--surface-tint);display:flex;align-items:center;gap:8px;">
        <span class="material-symbols-outlined" style="font-variation-settings:'FILL' 1;">security</span>
        HomeNetGuard
      </div>
      <div style="font-family:'JetBrains Mono',monospace;font-size:10px;letter-spacing:0.1em;color:var(--outline);margin-top:4px;">
        PROTOCOL: SECURE <span class="terminal-cursor"></span>
      </div>
    </div>

    <!-- Nav -->
    <nav style="flex:1;padding:0 8px;display:flex;flex-direction:column;gap:2px;">
      {% set nav_items = [
        ('/', 'dashboard', 'Dashboard', request.path == '/'),
        ('/alerts', 'security', 'Threat Center', request.path == '/alerts'),
        ('/flows', 'analytics', 'Analysis', request.path == '/flows'),
        ('/devices', 'devices', 'Devices', request.path == '/devices'),
        ('/dns', 'public', 'DNS', request.path == '/dns'),
        ('/firewall', 'shield', 'Firewall', request.path == '/firewall'),
        ('/intelligence', 'radar', 'Intelligence', request.path == '/intelligence'),
        ('/forensics', 'manage_search', 'Forensics', request.path == '/forensics'),
        ('/reports', 'description', 'Reports', request.path == '/reports'),
        ('/wifi', 'wifi', 'WiFi', request.path == '/wifi'),
        ('/learn', 'school', 'Edu Portal', request.path.startswith('/learn')),
        ('/docs', 'menu_book', 'Docs', request.path.startswith('/docs')),
      ] %}
      {% for href, icon, label, is_active in nav_items %}
      <a href="{{ href }}" style="display:flex;align-items:center;gap:12px;padding:10px 16px;text-decoration:none;transition:all 0.2s;
         {% if is_active %}color:var(--primary-container);border-right:2px solid var(--primary-container);background:rgba(235,255,226,0.05);
         {% else %}color:var(--on-surface-variant);border-right:2px solid transparent;{% endif %}">
        <span class="material-symbols-outlined" style="font-size:20px;">{{ icon }}</span>
        <span style="font-family:'Geist',sans-serif;font-size:15px;">{{ label }}</span>
      </a>
      {% endfor %}
    </nav>

    <!-- Scan button -->
    <div style="padding:0 16px;margin-bottom:16px;">
      <button id="btn-initiate-scan" class="glow-sm"
              style="width:100%;padding:10px;border:1px solid var(--surface-tint);color:var(--surface-tint);background:transparent;font-family:'JetBrains Mono',monospace;font-size:10px;font-weight:700;letter-spacing:0.1em;cursor:pointer;transition:all 0.2s;">
        INITIATE SCAN
      </button>
    </div>

    <!-- Secondary nav -->
    <div style="padding:0 8px;border-top:1px solid rgba(59,75,55,0.3);padding-top:12px;display:flex;flex-direction:column;gap:2px;">
      <a href="/config" style="display:flex;align-items:center;gap:12px;padding:8px 16px;text-decoration:none;color:var(--on-surface-variant);transition:colors 0.2s;">
        <span class="material-symbols-outlined" style="font-size:18px;">settings</span>
        <span style="font-family:'Geist',sans-serif;font-size:14px;">Settings</span>
      </a>
    </div>
  </aside>

  <!-- TOPBAR -->
  <header style="position:fixed;top:0;left:256px;right:0;height:64px;background:rgba(19,19,19,0.8);backdrop-filter:blur(12px);border-bottom:1px solid var(--outline-variant);z-index:50;display:flex;justify-content:space-between;align-items:center;padding:0 24px;">
    <div style="display:flex;gap:24px;align-items:center;">
      <span style="font-family:'JetBrains Mono',monospace;font-size:11px;font-weight:700;letter-spacing:0.1em;color:var(--surface-tint);display:flex;align-items:center;gap:8px;">
        <span style="width:8px;height:8px;border-radius:50%;background:var(--surface-tint);" class="pulse-node"></span>
        System: SECURE
      </span>
    </div>
    <div style="display:flex;align-items:center;gap:24px;">
      <div style="position:relative;">
        <input type="text" placeholder="CMD_SEARCH..."
               style="background:var(--surface-container-low);border:none;border-bottom:1px solid var(--outline);color:var(--primary);font-family:'JetBrains Mono',monospace;font-size:13px;padding:4px 32px 4px 12px;outline:none;width:192px;transition:all 0.2s;"
               onfocus="this.style.borderColor='var(--surface-tint)'" onblur="this.style.borderColor='var(--outline)'"/>
        <span class="material-symbols-outlined" style="position:absolute;right:8px;top:4px;font-size:16px;color:var(--outline);">search</span>
      </div>
      <span class="font-code-md" id="utc-clock" style="color:var(--outline);font-size:12px;">00:00:00 UTC</span>
      <span class="indicator indicator-live" id="connection-indicator"></span>
    </div>
  </header>

  <!-- MAIN -->
  <main style="margin-left:256px;padding-top:80px;padding-bottom:64px;padding-left:24px;padding-right:24px;min-height:100vh;">
    {% block content %}{% endblock %}
  </main>

  <!-- FOOTER -->
  <footer style="position:fixed;bottom:0;left:256px;right:0;background:var(--surface-container-lowest);border-top:1px solid rgba(59,75,55,0.3);padding:6px 24px;display:flex;justify-content:space-between;align-items:center;z-index:50;">
    <span style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--outline);">
      v{{ app_version | default('1.0.0') }}-STABLE | KERNEL: HNG_CORE_READY
    </span>
    <div style="display:flex;gap:24px;">
      <a href="/docs" style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--outline);text-decoration:none;">Docs</a>
      <a href="/api/docs" style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--outline);text-decoration:none;">API</a>
    </div>
  </footer>

  <!-- Alert Detail Modal (used by base dashboard JS) -->
  <div class="modal-overlay hidden" id="alert-modal" onclick="if(event.target===this)closeAlertModal()">
    <div class="modal">
      <div class="modal-header">
        <span class="modal-title">ALERT DETAIL</span>
        <button class="modal-close" onclick="closeAlertModal()">✕</button>
      </div>
      <div id="modal-body"></div>
    </div>
  </div>

  <!-- Vendors -->
  <script src="{{ url_for('static', filename='js/vendor/socket.io.min.js') }}"></script>
  <script src="{{ url_for('static', filename='js/vendor/chart.umd.min.js') }}" defer></script>
  <script src="{{ url_for('static', filename='js/vendor/leaflet.js') }}" defer></script>
  <!-- App JS -->
  <script src="{{ url_for('static', filename='js/charts.js') }}" defer></script>
  <script src="{{ url_for('static', filename='js/ui.js') }}" defer></script>
  <script src="{{ url_for('static', filename='js/dashboard.js') }}" defer></script>
  <script src="{{ url_for('static', filename='js/learn.js') }}" defer></script>
  {% block scripts %}{% endblock %}

</body>
</html>
```

- [ ] **Step 2: Verify Jinja2 blocks are present**

```bash
grep -c "block content\|block title\|block scripts\|block styles" homenetguard/dashboard/templates/base.html
```
Expected: 8 (each block appears twice: open + close)

---

## Task 6: Update dashboard.css

**Files:**
- Modify: `homenetguard/dashboard/static/css/dashboard.css`

- [ ] **Step 1: Replace dashboard.css — strip old vars/layout, keep page-specific overrides**

The new file imports tokens.css for variables. Keep only things not covered by components.css.

```css
/* dashboard.css — page-specific styles only; design tokens in tokens.css */
@import './tokens.css';

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html { font-size: 14px; }

/* Ticker (topbar live feed — driven by dashboard.js) */
.topbar-ticker { display: none; } /* hidden in new layout */

/* Sys stats (sidebar footer — driven by dashboard.js) */
.sys-stat { display: flex; justify-content: space-between; padding: 2px 16px; }
.sys-stat-label { font-family: 'JetBrains Mono', monospace; font-size: 10px; letter-spacing: 0.08em; color: var(--outline); }
.sys-stat-value { font-family: 'JetBrains Mono', monospace; font-size: 10px; color: var(--surface-tint); }

/* Config page specific */
.config-key   { font-family: 'JetBrains Mono', monospace; font-size: 12px; color: var(--on-surface-variant); padding: 8px 16px; }
.config-value { font-family: 'JetBrains Mono', monospace; font-size: 12px; color: var(--surface-tint); padding: 8px 16px; }
.config-section { margin-bottom: var(--gutter); }

/* Timeline (forensics) */
.timeline { position: relative; padding-left: 28px; }
.timeline::before { content:''; position:absolute; left:8px; top:0; bottom:0; width:2px; background:var(--outline-variant); }
.t-event { position: relative; margin-bottom: 12px; }
.t-event::before { content:''; position:absolute; left:-24px; top:8px; width:10px; height:10px; border-radius:50%; background:var(--surface-tint); border:2px solid var(--surface-container-low); }
.t-event.alert::before   { background: #ffb400; }
.t-event.critical::before{ background: var(--error); }
.t-event.ip_change::before{ background: var(--secondary); }
.t-card { background:var(--surface-container); border:1px solid var(--outline-variant); padding:8px 12px; }
.t-time { font-family:'JetBrains Mono',monospace; font-size:11px; color:var(--outline); }
.t-body { font-size:13px; color:var(--on-surface); margin-top:2px; }

/* Alert detail in modal */
.detail-grid { display:grid; grid-template-columns:1fr 1fr; gap:8px; }
.detail-row  { display:flex; flex-direction:column; gap:2px; padding:8px 10px; background:var(--surface-container-high); }
.detail-label{ font-size:10px; text-transform:uppercase; letter-spacing:0.1em; color:var(--outline); }
.detail-value{ font-family:'JetBrains Mono',monospace; font-size:12px; color:var(--on-surface); word-break:break-all; }
.detail-full { grid-column: span 2; }
.rep-bar  { height:6px; background:var(--surface-variant); margin-top:4px; overflow:hidden; }
.rep-fill { height:100%; transition:width 0.3s; }
.port-chip{ display:inline-block; font-family:'JetBrains Mono',monospace; font-size:10px; padding:2px 5px; background:var(--surface-container); border:1px solid var(--outline-variant); margin:2px; color:var(--on-surface-variant); }

/* Report viewer */
.report-item { display:flex; align-items:center; justify-content:space-between; padding:10px 16px; border-bottom:1px solid var(--outline-variant); cursor:pointer; transition:background 0.12s; gap:10px; }
.report-item:hover  { background:var(--surface-container); }
.report-item.active { background:var(--surface-container); border-left:3px solid var(--surface-tint); }
.report-meta  { flex:1; min-width:0; }
.report-name  { font-size:13px; color:var(--on-surface); font-weight:600; }
.report-sub   { font-size:11px; color:var(--outline); font-family:'JetBrains Mono',monospace; margin-top:2px; }
.report-actions{ display:flex; gap:6px; flex-shrink:0; }

/* Clickable rows */
.clickable-row { cursor: pointer; }

/* Severity color overrides (used inline in JS) */
:root {
  --severity-critical: var(--error);
  --severity-high:     #ffb400;
  --severity-medium:   #ffcc00;
  --severity-low:      var(--secondary);
  --accent-primary:    var(--surface-tint);
  --accent-cyan:       var(--secondary);
  --bg-base:           var(--surface-dim);
  --bg-elevated:       var(--surface-container-high);
  --bg-border:         var(--outline-variant);
  --bg-panel:          var(--surface-container-low);
  --bg-void:           var(--surface-dim);
  --text-primary:      var(--on-surface);
  --text-secondary:    var(--on-surface-variant);
  --text-muted:        var(--outline);
  --text-mono:         var(--on-surface);
}
```

---

## Task 7: Rewrite index.html (Dashboard)

**Files:**
- Modify: `homenetguard/dashboard/templates/index.html`

Preserve: all `id=` attributes used by `dashboard.js` (kpi-flows, kpi-alerts, kpi-src-ips, kpi-bytes, bps-chart, proto-chart, geo-map, alert-feed, flows-tbody, top-ips-tbody, bps-live).

- [ ] **Step 1: Rewrite index.html**

```html
{% extends "base.html" %}
{% block title %}Overview — HomeNetGuard{% endblock %}
{% block content %}

<div class="page-header">
  <div>
    <h1 class="page-title">Dashboard</h1>
    <p style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--outline);margin-top:2px;">Real-time network monitoring</p>
  </div>
</div>

<!-- KPI Row -->
<div class="grid-4" style="margin-bottom:var(--gutter);">
  <div class="kpi-card corner-bracket">
    <div class="kpi-label">FLOWS / 60MIN</div>
    <div class="kpi-value" id="kpi-flows">—</div>
    <div class="kpi-delta" id="kpi-flows-delta">Loading...</div>
    <div class="cb-bottom"></div>
  </div>
  <div class="kpi-card kpi-danger corner-bracket">
    <div class="kpi-label">ACTIVE THREATS</div>
    <div class="kpi-value" id="kpi-alerts">—</div>
    <div class="kpi-delta">Unacknowledged alerts</div>
    <div class="cb-bottom"></div>
  </div>
  <div class="kpi-card kpi-cyan corner-bracket">
    <div class="kpi-label">UNIQUE SRC IPs</div>
    <div class="kpi-value" id="kpi-src-ips">—</div>
    <div class="kpi-delta">Last 60 min</div>
    <div class="cb-bottom"></div>
  </div>
  <div class="kpi-card kpi-warn corner-bracket">
    <div class="kpi-label">TOTAL BYTES</div>
    <div class="kpi-value" id="kpi-bytes" style="font-size:1.1rem;">—</div>
    <div class="kpi-delta">Last 60 min</div>
    <div class="cb-bottom"></div>
  </div>
</div>

<!-- Charts Row -->
<div class="grid-2 mt-gap">
  <div class="panel-dark corner-bracket" style="padding:16px;position:relative;overflow:hidden;">
    <div class="scan-line"></div>
    <div class="panel-header" style="border:none;padding:0;margin-bottom:12px;">
      <span class="panel-title" style="display:flex;align-items:center;gap:8px;">
        <span style="width:6px;height:6px;background:var(--surface-tint);border-radius:50%;" class="pulse-node"></span>
        TRAFFIC (bytes/s)
      </span>
      <span style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--surface-tint);" id="bps-live">0 B/s</span>
    </div>
    <div class="chart-container" style="height:180px;"><canvas id="bps-chart"></canvas></div>
    <div class="cb-bottom"></div>
  </div>
  <div class="panel corner-bracket" style="padding:16px;">
    <div class="panel-header" style="border:none;padding:0;margin-bottom:12px;">
      <span class="panel-title">PROTOCOL DISTRIBUTION</span>
    </div>
    <div class="chart-container" style="height:180px;"><canvas id="proto-chart"></canvas></div>
    <div class="cb-bottom"></div>
  </div>
</div>

<!-- Map + Alert Feed -->
<div class="grid-2 mt-gap">
  <div class="panel corner-bracket" style="padding:16px;">
    <div class="panel-header" style="border:none;padding:0;margin-bottom:12px;">
      <span class="panel-title">GEO MAP</span>
      <span style="font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--outline);">External connections</span>
    </div>
    <div id="geo-map" style="height:260px;"></div>
    <div class="cb-bottom"></div>
  </div>
  <div class="panel corner-bracket" style="padding:16px;">
    <div class="panel-header" style="border:none;padding:0;margin-bottom:12px;">
      <span class="panel-title">ALERT FEED</span>
      <a href="/alerts" class="btn-ghost" style="font-size:10px;padding:3px 8px;">View all →</a>
    </div>
    <div id="alert-feed">
      <div class="empty-state"><span class="empty-state-icon">🛡</span>No alerts</div>
    </div>
    <div class="cb-bottom"></div>
  </div>
</div>

<!-- Live Flows + Top IPs -->
<div class="grid-2 mt-gap">
  <div class="panel corner-bracket">
    <div class="panel-header">
      <span class="panel-title">LIVE FLOWS</span>
      <a href="/flows" class="btn-ghost" style="font-size:10px;padding:3px 8px;">Explorer →</a>
    </div>
    <div class="table-scroll">
      <table class="data-table">
        <thead><tr><th>TIME</th><th>SRC IP</th><th>DST IP</th><th>PROTO</th><th>SP</th><th>DP</th><th>BYTES</th><th>OWNER</th><th>GEO</th></tr></thead>
        <tbody id="flows-tbody">
          <tr><td colspan="9" class="empty-state">Waiting for traffic...</td></tr>
        </tbody>
      </table>
    </div>
    <div class="cb-bottom"></div>
  </div>
  <div class="panel corner-bracket">
    <div class="panel-header"><span class="panel-title">TOP IPs (5 MIN)</span></div>
    <table class="data-table">
      <thead><tr><th>#</th><th>IP / OWNER</th><th>BYTES</th><th>FLOWS</th></tr></thead>
      <tbody id="top-ips-tbody">
        <tr><td colspan="4" class="empty-state">No data yet</td></tr>
      </tbody>
    </table>
    <div class="cb-bottom"></div>
  </div>
</div>

{% endblock %}
```

---

## Task 8: Rewrite alerts.html

**Files:**
- Modify: `homenetguard/dashboard/templates/alerts.html`

Preserve all JS functions, `id=` attributes, socket listener. Only change HTML structure.

- [ ] **Step 1: Rewrite the HTML portion (keep all `<script>` blocks intact)**

Replace everything from `{% extends %}` to just before the first `<style>` block with:

```html
{% extends "base.html" %}
{% block title %}Alerts — HomeNetGuard{% endblock %}
{% block content %}

<div class="page-header">
  <div>
    <h1 class="page-title">Threat Center <a href="/learn/anomaly-detection" class="learn-link" title="Learn about threat detection">?</a></h1>
  </div>
  <div style="display:flex;gap:8px;">
    <button class="btn-danger" onclick="clearAllAlerts()">Clear All</button>
    <button class="btn-ghost" onclick="exportCSV()">↓ Export CSV</button>
  </div>
</div>

<div class="grid-4" style="margin-bottom:var(--gutter);">
  <div class="kpi-card kpi-danger corner-bracket">
    <div class="kpi-label">CRITICAL</div>
    <div class="kpi-value" id="cnt-critical">—</div>
    <div class="cb-bottom"></div>
  </div>
  <div class="kpi-card kpi-warn corner-bracket">
    <div class="kpi-label">HIGH</div>
    <div class="kpi-value kpi-warn" id="cnt-high">—</div>
    <div class="cb-bottom"></div>
  </div>
  <div class="kpi-card corner-bracket">
    <div class="kpi-label">MEDIUM</div>
    <div class="kpi-value" style="color:#ffcc00;" id="cnt-medium">—</div>
    <div class="cb-bottom"></div>
  </div>
  <div class="kpi-card kpi-cyan corner-bracket">
    <div class="kpi-label">LOW</div>
    <div class="kpi-value kpi-cyan" id="cnt-low">—</div>
    <div class="cb-bottom"></div>
  </div>
</div>

<div class="panel corner-bracket">
  <div class="filter-bar">
    <select class="filter-select" id="filter-severity" onchange="loadAlerts()">
      <option value="">All severities</option>
      <option value="critical">Critical</option>
      <option value="high">High</option>
      <option value="medium">Medium</option>
      <option value="low">Low</option>
    </select>
    <select class="filter-select" id="filter-type" onchange="loadAlerts()">
      <option value="">All types</option>
      <option value="port_scan">Port Scan</option>
      <option value="flood">Flood / DoS</option>
      <option value="blacklisted_ip">Blacklisted IP</option>
      <option value="dns_anomaly">DNS Anomaly</option>
      <option value="beaconing">Beaconing</option>
      <option value="arp_spoofing">ARP Spoofing</option>
    </select>
    <select class="filter-select" id="filter-ack" onchange="loadAlerts()">
      <option value="unacked">Unacknowledged</option>
      <option value="all">All alerts</option>
    </select>
    <span class="text-muted" id="alert-count" style="align-self:center;font-size:11px;margin-left:auto;"></span>
  </div>
  <div class="table-scroll" style="max-height:65vh;">
    <table class="data-table">
      <thead>
        <tr><th>ID</th><th>TIME</th><th>TYPE</th><th>SEV</th><th>SRC IP</th><th>DST IP</th><th>DESCRIPTION</th><th>STATUS</th></tr>
      </thead>
      <tbody id="alerts-tbody">
        <tr><td colspan="8" class="empty-state">Loading...</td></tr>
      </tbody>
    </table>
  </div>
  <div class="cb-bottom"></div>
</div>

<!-- Threat Detail Modal -->
<div class="modal-overlay hidden" id="threat-modal" onclick="if(event.target===this)closeThreatModal()">
  <div class="modal" style="width:620px;max-width:96vw;">
    <div class="modal-header">
      <span class="modal-title" id="threat-modal-title">THREAT DETAIL</span>
      <div style="display:flex;gap:8px;align-items:center;">
        <button class="btn-ghost" style="font-size:10px;padding:3px 10px;" id="threat-ack-btn" onclick="ackCurrentAlert()">✓ Acknowledge</button>
        <button class="modal-close" onclick="closeThreatModal()">✕</button>
      </div>
    </div>
    <div id="threat-modal-body" style="display:flex;flex-direction:column;gap:16px;"></div>
  </div>
</div>
```

Then keep the entire original `<style>` block and `<script>` block unchanged.

---

## Task 9: Rewrite flows.html

**Files:**
- Modify: `homenetguard/dashboard/templates/flows.html`

Preserve all JS. Only restructure HTML.

- [ ] **Step 1: Rewrite flows.html**

```html
{% extends "base.html" %}
{% block title %}Flows — HomeNetGuard{% endblock %}
{% block content %}

<div class="page-header">
  <h1 class="page-title">Flow Explorer</h1>
</div>

<div class="panel corner-bracket">
  <div class="filter-bar">
    <input class="filter-input" id="f-ip" placeholder="Filter IP..." oninput="loadFlows()" style="width:180px;">
    <select class="filter-select" id="f-proto" onchange="loadFlows()">
      <option value="">All protocols</option>
      <option>TCP</option><option>UDP</option><option>ICMP</option><option>DNS</option>
    </select>
    <span class="text-muted" id="flow-count" style="align-self:center;font-size:11px;margin-left:auto;"></span>
  </div>
  <div class="table-scroll" style="max-height:70vh;">
    <table class="data-table">
      <thead>
        <tr>
          <th>TIME</th>
          <th>SRC IP <a href="/learn/ip-addresses" class="learn-link" title="Learn about IP addresses">?</a></th>
          <th>DST IP</th>
          <th>PROTO <a href="/learn/tcp" class="learn-link" title="Learn about protocols">?</a></th>
          <th>SRC PORT <a href="/learn/tcp" class="learn-link" title="Learn about ports">?</a></th>
          <th>DST PORT</th>
          <th>BYTES <a href="/learn/network-flows" class="learn-link" title="Learn about network flows">?</a></th>
          <th>DIR</th>
          <th>SRC GEO <a href="/learn/ip-reputation" class="learn-link" title="Learn about IP geo-location">?</a></th>
          <th>DST GEO</th>
        </tr>
      </thead>
      <tbody id="flows-explorer-tbody">
        <tr><td colspan="10" class="empty-state">Loading...</td></tr>
      </tbody>
    </table>
  </div>
  <div class="cb-bottom"></div>
</div>

<script>
let _allFlows = [];
async function loadFlows() {
  const res = await fetch('/api/flows?limit=500');
  _allFlows = await res.json();
  renderFlows();
}
function renderFlows() {
  const ipFilter = document.getElementById('f-ip').value.trim().toLowerCase();
  const protoFilter = document.getElementById('f-proto').value;
  let flows = _allFlows;
  if (ipFilter) flows = flows.filter(f => (f.src_ip||'').includes(ipFilter) || (f.dst_ip||'').includes(ipFilter));
  if (protoFilter) flows = flows.filter(f => f.protocol === protoFilter);
  document.getElementById('flow-count').textContent = `${flows.length} flows`;
  const tbody = document.getElementById('flows-explorer-tbody');
  if (!flows.length) { tbody.innerHTML = `<tr><td colspan="10" class="empty-state">No flows match filter</td></tr>`; return; }
  tbody.innerHTML = flows.slice(0,200).map(f => `
    <tr>
      <td class="text-mono" style="font-size:11px;">${(f.timestamp||'').slice(11,19)}</td>
      <td class="ip-address">${f.src_ip||'—'}</td>
      <td class="ip-address">${f.dst_ip||'—'}</td>
      <td><span class="badge badge-${(f.protocol||'').toLowerCase()}" data-learn-term="${f.protocol||''}">${f.protocol||'?'}</span></td>
      <td class="port">${f.src_port||'—'}</td>
      <td class="port">${f.dst_port||'—'}</td>
      <td class="text-mono">${fmtBytes(f.bytes||0)}</td>
      <td style="font-size:11px;color:var(--outline);">${f.direction||'—'}</td>
      <td style="font-size:11px;">${f.src_country||'—'}</td>
      <td style="font-size:11px;">${f.dst_country||'—'}</td>
    </tr>
  `).join('');
  if (window.initLearnTooltips) window.initLearnTooltips();
}
function fmtBytes(b) {
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b/1024).toFixed(1) + ' KB';
  return (b/1048576).toFixed(1) + ' MB';
}
loadFlows();
setInterval(loadFlows, 5000);
</script>
{% endblock %}
```

---

## Task 10: Rewrite devices.html

- [ ] **Step 1: Rewrite devices.html preserving all JS**

```html
{% extends "base.html" %}
{% block title %}Devices — HomeNetGuard{% endblock %}
{% block content %}

<div class="page-header">
  <h1 class="page-title">Devices</h1>
  <button class="btn" onclick="scanNow()">⟳ Scan Now</button>
</div>

<div class="panel corner-bracket">
  <div class="panel-header">
    <span class="panel-title">NETWORK DEVICES</span>
    <span class="text-muted" id="device-count" style="font-size:11px;"></span>
  </div>
  <div class="table-scroll" style="max-height:70vh;">
    <table class="data-table">
      <thead>
        <tr>
          <th>MAC <a href="/learn/mac-addresses" class="learn-link" title="Learn about MAC addresses">?</a></th>
          <th>VENDOR</th>
          <th>IP <a href="/learn/ip-addresses" class="learn-link" title="Learn about IP addresses">?</a></th>
          <th>OS GUESS <a href="/learn/os-fingerprint" class="learn-link" title="Learn about OS fingerprinting">?</a></th>
          <th>FIRST SEEN</th><th>LAST SEEN</th><th>STATUS</th><th>ACTIONS</th>
        </tr>
      </thead>
      <tbody id="devices-tbody"><tr><td colspan="8" class="empty-state">Loading...</td></tr></tbody>
    </table>
  </div>
  <div class="cb-bottom"></div>
</div>

<script>
async function loadDevices() {
  const res = await fetch('/api/v2/devices');
  const devices = await res.json();
  document.getElementById('device-count').textContent = `${devices.length} device${devices.length !== 1 ? 's' : ''}`;
  const tbody = document.getElementById('devices-tbody');
  if (!devices.length) { tbody.innerHTML = `<tr><td colspan="8" class="empty-state"><span class="empty-state-icon">📡</span>No devices found — run a scan first</td></tr>`; return; }
  tbody.innerHTML = devices.map(d => {
    const statusClass = d.is_quarantined ? 'badge-quarantined' : d.is_trusted ? 'badge-verified' : 'badge-low';
    const statusLabel = d.is_quarantined ? 'Quarantine' : d.is_trusted ? 'Trusted' : 'Unknown';
    return `
      <tr>
        <td class="ip-address" data-learn-term="ARP">${d.mac_address || '—'}</td>
        <td>${d.vendor || 'Unknown'}</td>
        <td class="ip-address">${d.ip_address || '—'}</td>
        <td data-learn-term="fingerprint">${d.os_guess ? `${d.os_guess} (${Math.round((d.os_confidence||0)*100)}%)` : '—'}</td>
        <td class="text-mono" style="font-size:11px;">${(d.first_seen||'').slice(0,16).replace('T',' ')}</td>
        <td class="text-mono" style="font-size:11px;">${(d.last_seen||'').slice(0,16).replace('T',' ')}</td>
        <td><span class="badge ${statusClass}">${statusLabel}</span></td>
        <td>
          <div style="display:flex;gap:4px;">
            ${!d.is_trusted ? `<button class="btn-ghost" style="font-size:10px;padding:2px 6px;" onclick="trustDevice('${d.mac_address}')">Trust</button>` : ''}
            ${!d.is_quarantined ? `<button class="btn-danger" style="font-size:10px;padding:2px 6px;" onclick="quarantineDevice('${d.mac_address}')">Quarantine</button>` : `<button class="btn-ghost" style="font-size:10px;padding:2px 6px;" onclick="releaseDevice('${d.mac_address}')">Release</button>`}
            <a href="/forensics?ip=${d.ip_address||''}" class="btn-ghost" style="font-size:10px;padding:2px 6px;">Forensics</a>
          </div>
        </td>
      </tr>`;
  }).join('');
  if (window.initLearnTooltips) window.initLearnTooltips();
}
async function trustDevice(mac) { await fetch(`/api/v2/devices/${mac}/trust`, { method: 'POST' }); loadDevices(); }
async function quarantineDevice(mac) { if (!confirm(`Quarantine ${mac}?`)) return; await fetch(`/api/v2/devices/${mac}/quarantine`, { method: 'POST' }); loadDevices(); }
async function releaseDevice(mac) { await fetch(`/api/v2/devices/${mac}/quarantine`, { method: 'DELETE' }); loadDevices(); }
async function scanNow() { alert('Run: sudo homenetguard devices scan\n(ARP scan requires elevated privileges)'); }
loadDevices();
setInterval(loadDevices, 15000);
</script>
{% endblock %}
```

---

## Task 11: Rewrite dns.html, firewall.html, intelligence.html

- [ ] **Step 1: Rewrite dns.html**

```html
{% extends "base.html" %}
{% block title %}DNS — HomeNetGuard{% endblock %}
{% block content %}

<div class="page-header">
  <h1 class="page-title">DNS Analysis <a href="/learn/dns" class="learn-link" title="Learn about DNS">?</a></h1>
</div>

<div class="grid-2" style="margin-bottom:var(--gutter);">
  <div class="panel corner-bracket">
    <div class="panel-header"><span class="panel-title">TOP DOMAINS</span></div>
    <table class="data-table">
      <thead><tr><th>#</th><th>DOMAIN</th><th>QUERIES</th></tr></thead>
      <tbody id="top-domains-tbody"><tr><td colspan="3" class="empty-state">Loading...</td></tr></tbody>
    </table>
    <div class="cb-bottom"></div>
  </div>
  <div class="panel corner-bracket">
    <div class="panel-header">
      <span class="panel-title">SUSPICIOUS DOMAINS</span>
      <span class="badge badge-medium" id="suspicious-count">0</span>
    </div>
    <div id="suspicious-list">
      <div class="empty-state"><span class="empty-state-icon">✓</span>No suspicious domains</div>
    </div>
    <div class="cb-bottom"></div>
  </div>
</div>

<div class="panel corner-bracket mt-gap">
  <div class="panel-header"><span class="panel-title">RECENT DNS QUERIES</span></div>
  <div class="table-scroll">
    <table class="data-table">
      <thead><tr><th>TIME</th><th>SRC IP</th><th>DOMAIN</th><th>TYPE</th><th>RESPONSE</th><th>STATUS</th></tr></thead>
      <tbody id="dns-tbody"><tr><td colspan="6" class="empty-state">Loading...</td></tr></tbody>
    </table>
  </div>
  <div class="cb-bottom"></div>
</div>

<script>
async function loadDNS() {
  const res = await fetch('/api/dns');
  const queries = await res.json();
  const tbody = document.getElementById('dns-tbody');
  tbody.innerHTML = queries.slice(0,200).map(q => `
    <tr class="${q.is_suspicious ? 'row-danger' : ''}">
      <td class="text-mono" style="font-size:11px;">${(q.timestamp||'').slice(11,19)}</td>
      <td class="ip-address">${q.src_ip||'—'}</td>
      <td class="text-mono" style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${q.queried_domain||'—'}</td>
      <td><span class="badge badge-tcp" data-learn-term="DNS">${q.query_type||'?'}</span></td>
      <td class="ip-address">${q.response_ip||'—'}</td>
      <td>${q.is_suspicious ? '<span class="badge badge-high">SUSPICIOUS</span>' : '<span class="badge badge-resolved">OK</span>'}</td>
    </tr>
  `).join('');
  if (window.initLearnTooltips) window.initLearnTooltips();
  const counts = {};
  queries.forEach(q => { counts[q.queried_domain] = (counts[q.queried_domain]||0)+1; });
  const top = Object.entries(counts).sort((a,b)=>b[1]-a[1]).slice(0,15);
  document.getElementById('top-domains-tbody').innerHTML = top.map(([d,c],i) => `
    <tr><td class="text-mono">${i+1}</td><td class="text-mono" style="font-size:12px;">${d}</td><td class="text-mono">${c}</td></tr>
  `).join('') || `<tr><td colspan="3" class="empty-state">No queries</td></tr>`;
  const susp = queries.filter(q => q.is_suspicious);
  document.getElementById('suspicious-count').textContent = susp.length;
  const suspList = document.getElementById('suspicious-list');
  if (!susp.length) { suspList.innerHTML = `<div class="empty-state"><span class="empty-state-icon">✓</span>None found</div>`; }
  else { suspList.innerHTML = susp.slice(0,20).map(q => `
    <div style="display:flex;justify-content:space-between;padding:10px 16px;border-bottom:1px solid var(--outline-variant);">
      <div>
        <div class="text-mono" style="font-size:12px;">${q.queried_domain}</div>
        <div class="text-muted" style="font-size:11px;">from <span class="ip-address">${q.src_ip}</span></div>
      </div>
      <span class="badge badge-medium">${q.query_type||'?'}</span>
    </div>
  `).join(''); }
}
loadDNS();
setInterval(loadDNS, 5000);
</script>
{% endblock %}
```

- [ ] **Step 2: Rewrite firewall.html**

```html
{% extends "base.html" %}
{% block title %}Firewall — HomeNetGuard{% endblock %}
{% block content %}

<div class="page-header">
  <h1 class="page-title">Firewall <a href="/learn/firewall" class="learn-link" title="Learn about firewalls">?</a></h1>
</div>

<div class="grid-2" style="align-items:start;">
  <div class="panel corner-bracket">
    <div class="panel-header">
      <span class="panel-title">ACTIVE RULES</span>
      <button class="btn-ghost" style="font-size:10px;padding:3px 8px;" onclick="loadRules()">Refresh</button>
    </div>
    <div class="table-scroll" style="max-height:50vh;">
      <table class="data-table">
        <thead><tr><th>ID</th><th>TYPE</th><th>TARGET</th><th>DIR</th><th>REASON</th><th></th></tr></thead>
        <tbody id="rules-tbody"><tr><td colspan="6" class="empty-state">Loading...</td></tr></tbody>
      </table>
    </div>
    <div class="cb-bottom"></div>
  </div>

  <div class="panel corner-bracket" style="padding:24px;">
    <div class="panel-header" style="border:none;padding:0;margin-bottom:20px;"><span class="panel-title">ADD RULE</span></div>
    <div style="display:flex;flex-direction:column;gap:16px;">
      <div>
        <label style="font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--outline);display:block;margin-bottom:6px;letter-spacing:0.08em;">TARGET IP</label>
        <input class="filter-input" id="rule-target" placeholder="e.g. 1.2.3.4" style="width:100%;">
      </div>
      <div>
        <label style="font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--outline);display:block;margin-bottom:6px;letter-spacing:0.08em;">DIRECTION</label>
        <select class="filter-select" id="rule-direction" style="width:100%;">
          <option value="both">Both</option>
          <option value="inbound">Inbound</option>
          <option value="outbound">Outbound</option>
        </select>
      </div>
      <div>
        <label style="font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--outline);display:block;margin-bottom:6px;letter-spacing:0.08em;">REASON</label>
        <input class="filter-input" id="rule-reason" placeholder="Reason for block" style="width:100%;">
      </div>
      <button class="btn-danger" onclick="addRule()" style="width:100%;justify-content:center;">Block IP</button>
    </div>
    <div class="cb-bottom"></div>
  </div>
</div>

<script>
async function loadRules() {
  const res = await fetch('/api/v2/firewall/rules');
  const rules = await res.json();
  const tbody = document.getElementById('rules-tbody');
  if (!rules.length) { tbody.innerHTML = `<tr><td colspan="6" class="empty-state">No active rules</td></tr>`; return; }
  tbody.innerHTML = rules.map(r => `
    <tr>
      <td class="text-mono">${r.id}</td>
      <td><span class="badge badge-tcp">${r.rule_type}</span></td>
      <td class="ip-address">${r.target}</td>
      <td style="font-size:12px;">${r.direction||'—'}</td>
      <td style="font-size:12px;max-width:150px;overflow:hidden;text-overflow:ellipsis;">${r.reason||'—'}</td>
      <td><button class="btn-danger" style="font-size:10px;padding:2px 6px;" onclick="deleteRule(${r.id})">✕</button></td>
    </tr>`).join('');
}
async function addRule() {
  const target = document.getElementById('rule-target').value.trim();
  const direction = document.getElementById('rule-direction').value;
  const reason = document.getElementById('rule-reason').value.trim();
  if (!target) { alert('Target IP required'); return; }
  const res = await fetch('/api/v2/firewall/rules', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({type:'ip',target,direction,reason}) });
  const data = await res.json();
  if (data.ok) { loadRules(); document.getElementById('rule-target').value = ''; }
  else alert('Error: ' + (data.error || 'unknown'));
}
async function deleteRule(id) { if (!confirm(`Delete rule #${id}?`)) return; await fetch(`/api/v2/firewall/rules/${id}`, { method: 'DELETE' }); loadRules(); }
loadRules();
</script>
{% endblock %}
```

- [ ] **Step 3: Rewrite intelligence.html — keep all JS, update HTML**

Replace HTML structure, keep entire `<script>` block unchanged:

```html
{% extends "base.html" %}
{% block title %}Intelligence — HomeNetGuard{% endblock %}
{% block content %}

<div class="page-header">
  <h1 class="page-title">Threat Intelligence</h1>
</div>

<div class="grid-2" style="align-items:start;margin-bottom:var(--gutter);">
  <div class="panel corner-bracket">
    <div class="panel-header">
      <span class="panel-title">MITRE ATT&CK <a href="/learn/mitre-attack" class="learn-link" title="Learn about MITRE ATT&CK">?</a></span>
    </div>
    <div id="mitre-matrix" style="padding:16px;">Loading...</div>
    <div class="cb-bottom"></div>
  </div>

  <div class="panel corner-bracket">
    <div class="panel-header">
      <span class="panel-title">THREAT FEEDS <a href="/learn/threat-feeds" class="learn-link" title="Learn about threat feeds">?</a></span>
      <button class="btn" style="font-size:10px;padding:3px 8px;" onclick="updateFeeds()">↻ Update All</button>
    </div>
    <div id="feeds-list" style="padding:0 16px;">Loading...</div>

    <div class="panel-header" style="margin-top:16px;"><span class="panel-title">COMPLIANCE SCORE</span></div>
    <div id="compliance-panel" style="padding:16px;">Loading...</div>
    <div class="cb-bottom"></div>
  </div>
</div>

<div class="panel corner-bracket mt-gap">
  <div class="panel-header">
    <span class="panel-title">DNS SINKHOLE RULES <a href="/learn/dns-sinkhole" class="learn-link" title="Learn about DNS sinkholes">?</a></span>
    <div style="display:flex;gap:8px;">
      <input class="filter-input" id="sink-domain" placeholder="domain.com" style="width:180px;">
      <button class="btn" style="font-size:10px;padding:3px 8px;" onclick="addSinkhole()">+ Block Domain</button>
    </div>
  </div>
  <div class="table-scroll" style="max-height:30vh;">
    <table class="data-table">
      <thead><tr><th>DOMAIN</th><th>SOURCE</th><th>HITS</th><th></th></tr></thead>
      <tbody id="sinkhole-tbody"><tr><td colspan="4" class="empty-state">No blocked domains</td></tr></tbody>
    </table>
  </div>
  <div class="cb-bottom"></div>
</div>
```

Then append the full original `<script>` block (unchanged) and close `{% endblock %}`.

---

## Task 12: Rewrite forensics.html, reports.html, wifi.html, config.html

- [ ] **Step 1: Rewrite forensics.html**

```html
{% extends "base.html" %}
{% block title %}Forensics — HomeNetGuard{% endblock %}
{% block content %}

<div class="page-header">
  <h1 class="page-title">Forensics Timeline</h1>
</div>

<div class="panel corner-bracket" style="margin-bottom:var(--gutter);">
  <div class="filter-bar">
    <input class="filter-input" id="f-ip"  placeholder="IP address..."  style="width:200px;">
    <input class="filter-input" id="f-mac" placeholder="MAC address..." style="width:200px;">
    <button class="btn" onclick="runForensics()">Search</button>
    <span class="text-muted" id="f-count" style="align-self:center;font-size:11px;margin-left:auto;"></span>
  </div>
  <div class="cb-bottom"></div>
</div>

<div id="timeline-container"></div>

<script>
async function runForensics() {
  const ip = document.getElementById('f-ip').value.trim();
  const mac = document.getElementById('f-mac').value.trim();
  if (!ip && !mac) { alert('Enter IP or MAC to search'); return; }
  const params = new URLSearchParams();
  if (ip) params.append('ip', ip);
  if (mac) params.append('mac', mac);
  const res = await fetch(`/api/v2/forensics?${params}`);
  const events = await res.json();
  document.getElementById('f-count').textContent = `${events.length} events`;
  const container = document.getElementById('timeline-container');
  if (!events.length) {
    container.innerHTML = `<div class="panel corner-bracket" style="padding:40px;"><div class="empty-state"><span class="empty-state-icon">🔍</span>No events found</div><div class="cb-bottom"></div></div>`;
    return;
  }
  const icons = { flow:'🌊', alert:'⚠️', ip_change:'🔄' };
  container.innerHTML = `
    <div class="panel corner-bracket" style="padding:24px;">
      <div class="timeline">
        ${events.slice(0,100).map(e => {
          const ts = (e.timestamp||'').slice(0,19).replace('T',' ');
          const type = e.type || 'flow';
          let body = '';
          if (type === 'flow') body = `${e.src_ip} → ${e.dst_ip} <span class="badge badge-tcp">${e.protocol||'?'}</span> ${fmtBytes(e.bytes||0)}`;
          else if (type === 'alert') body = `<span class="badge badge-${e.severity||'low'}">${e.severity}</span> ${e.alert_type} — ${(e.description||'').slice(0,80)}`;
          else if (type === 'ip_change') body = `IP changed to <span class="ip-address">${e.ip_address}</span>`;
          const cls = e.severity === 'critical' ? 'critical' : type === 'alert' ? 'alert' : type === 'ip_change' ? 'ip_change' : '';
          return `<div class="t-event ${cls}"><div class="t-card"><div class="t-time">${icons[type]||'●'} ${ts}</div><div class="t-body">${body}</div></div></div>`;
        }).join('')}
      </div>
      <div class="cb-bottom"></div>
    </div>`;
}
function fmtBytes(b) { if (b < 1024) return b+'B'; if (b < 1048576) return (b/1024).toFixed(1)+'KB'; return (b/1048576).toFixed(1)+'MB'; }
const urlParams = new URLSearchParams(window.location.search);
if (urlParams.get('ip'))  { document.getElementById('f-ip').value  = urlParams.get('ip');  runForensics(); }
if (urlParams.get('mac')) { document.getElementById('f-mac').value = urlParams.get('mac'); runForensics(); }
</script>
{% endblock %}
```

- [ ] **Step 2: Rewrite reports.html**

Keep all `<script>` logic. Replace HTML structure:

```html
{% extends "base.html" %}
{% block title %}Reports — HomeNetGuard{% endblock %}
{% block content %}

<div class="page-header">
  <h1 class="page-title">Reports</h1>
  <button class="btn" onclick="document.getElementById('new-report-modal').classList.remove('hidden')">+ Generate Report</button>
</div>

<div class="grid-2" style="align-items:start;">
  <div class="panel corner-bracket" style="min-width:0;">
    <div class="panel-header">
      <span class="panel-title">GENERATED REPORTS</span>
      <span class="text-muted" id="report-count" style="font-size:11px;"></span>
    </div>
    <div id="reports-list">
      <div class="empty-state"><span class="empty-state-icon">📋</span>No reports yet</div>
    </div>
    <div class="cb-bottom"></div>
  </div>

  <div class="panel corner-bracket" id="viewer-panel" style="min-width:0;">
    <div class="panel-header">
      <span class="panel-title" id="viewer-title">REPORT VIEWER</span>
      <div style="display:flex;gap:8px;">
        <button class="btn-ghost" id="viewer-download-btn" style="display:none;font-size:10px;padding:3px 8px;" onclick="downloadReport()">↓ Download</button>
        <button class="btn-ghost" style="font-size:10px;padding:3px 8px;" onclick="clearViewer()">✕ Close</button>
      </div>
    </div>
    <div id="viewer-placeholder" style="padding:60px;text-align:center;color:var(--outline);">
      <div style="font-size:2rem;opacity:0.2;margin-bottom:8px;">📄</div>
      <div style="font-size:12px;font-family:'JetBrains Mono',monospace;">Select a report to preview</div>
    </div>
    <iframe id="report-iframe" style="display:none;width:100%;height:75vh;border:none;background:#fff;" sandbox="allow-same-origin allow-scripts"></iframe>
    <div class="cb-bottom"></div>
  </div>
</div>

<div class="modal-overlay hidden" id="new-report-modal" onclick="if(event.target===this)this.classList.add('hidden')">
  <div class="modal" style="width:420px;">
    <div class="modal-header">
      <span class="modal-title">GENERATE REPORT</span>
      <button class="modal-close" onclick="document.getElementById('new-report-modal').classList.add('hidden')">✕</button>
    </div>
    <div style="display:flex;flex-direction:column;gap:16px;">
      <div>
        <label style="font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--outline);display:block;margin-bottom:6px;">TYPE</label>
        <select class="filter-select" id="rpt-type" style="width:100%;">
          <option value="daily">Daily (last 24h)</option>
          <option value="weekly">Weekly (last 7d)</option>
          <option value="custom">Custom period</option>
        </select>
      </div>
      <div id="custom-dates" style="display:none;gap:8px;flex-direction:column;">
        <div>
          <label style="font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--outline);display:block;margin-bottom:6px;">FROM</label>
          <input type="date" class="filter-input" id="rpt-from" style="width:100%;">
        </div>
        <div>
          <label style="font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--outline);display:block;margin-bottom:6px;">TO</label>
          <input type="date" class="filter-input" id="rpt-to" style="width:100%;">
        </div>
      </div>
      <div>
        <label style="font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--outline);display:block;margin-bottom:6px;">FORMAT</label>
        <select class="filter-select" id="rpt-format" style="width:100%;">
          <option value="html">HTML only</option>
          <option value="pdf">PDF only</option>
          <option value="both">HTML + PDF</option>
        </select>
      </div>
      <div id="gen-status" style="display:none;font-size:12px;color:var(--surface-tint);font-family:'JetBrains Mono',monospace;">⟳ Generating...</div>
      <div style="display:flex;gap:8px;">
        <button class="btn" onclick="generateReport()" style="flex:1;justify-content:center;" id="gen-btn">Generate</button>
        <button class="btn-ghost" onclick="document.getElementById('new-report-modal').classList.add('hidden')">Cancel</button>
      </div>
    </div>
  </div>
</div>
```

Then keep the original `<script>` block unchanged.

- [ ] **Step 3: Rewrite wifi.html**

```html
{% extends "base.html" %}
{% block title %}WiFi — HomeNetGuard{% endblock %}
{% block content %}

<div class="page-header">
  <h1 class="page-title">WiFi Networks</h1>
</div>

<div class="panel corner-bracket" style="padding:60px;text-align:center;">
  <div style="font-size:3rem;opacity:0.15;margin-bottom:16px;">📶</div>
  <div style="font-family:'Geist',sans-serif;font-size:16px;color:var(--on-surface-variant);margin-bottom:8px;">WiFi Scanner Not Enabled</div>
  <div style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--outline);max-width:420px;margin:0 auto;line-height:1.8;">
    Set <code style="color:var(--secondary);">wifi.enabled: true</code> and
    <code style="color:var(--secondary);">wifi.monitor_interface</code> in
    <code style="color:var(--secondary);">config/config.yaml</code>.
    <br><br>
    Requires WiFi adapter in monitor mode.
    <br>
    <strong style="color:var(--on-surface-variant);">Linux:</strong> <code style="color:var(--on-surface);">airmon-ng start wlan0</code><br>
    <strong style="color:var(--on-surface-variant);">macOS:</strong> Use Airport utility or compatible adapter
  </div>
  <div style="margin-top:24px;">
    <a href="/config" class="btn">View Config →</a>
  </div>
  <div class="cb-bottom"></div>
</div>
{% endblock %}
```

- [ ] **Step 4: Rewrite config.html**

Preserve Jinja2 macro and all `config` variable references:

```html
{% extends "base.html" %}
{% block title %}Config — HomeNetGuard{% endblock %}
{% block content %}

<div class="page-header">
  <div>
    <h1 class="page-title">Configuration</h1>
    <p style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--outline);margin-top:2px;">Read-only — edit config/config.yaml to change</p>
  </div>
</div>

{% macro render_section(title, data) %}
<div class="panel corner-bracket config-section">
  <div class="panel-header"><span class="panel-title">{{ title }}</span></div>
  <table class="data-table">
    <thead><tr><th>KEY</th><th>VALUE</th></tr></thead>
    <tbody>
    {% for k, v in data.items() %}
      {% if v is mapping %}
        <tr><td class="config-key" colspan="2" style="padding-top:10px;color:var(--on-surface-variant);">{{ k }}</td></tr>
        {% for sk, sv in v.items() %}
        <tr><td class="config-key" style="padding-left:24px;">{{ sk }}</td><td class="config-value">{{ sv }}</td></tr>
        {% endfor %}
      {% else %}
      <tr><td class="config-key">{{ k }}</td><td class="config-value">{{ v }}</td></tr>
      {% endif %}
    {% endfor %}
    </tbody>
  </table>
  <div class="cb-bottom"></div>
</div>
{% endmacro %}

<div class="grid-2">
  {% if config.get('network') %}{{ render_section('NETWORK', config.network) }}{% endif %}
  {% if config.get('storage') %}{{ render_section('STORAGE', config.storage) }}{% endif %}
  {% if config.get('dashboard') %}{{ render_section('DASHBOARD', config.dashboard) }}{% endif %}
  {% if config.get('detection') %}{{ render_section('DETECTION', config.detection) }}{% endif %}
</div>

<div class="grid-2 mt-gap">
  {% if config.get('geoip') %}{{ render_section('GEOIP', config.geoip) }}{% endif %}
  {% if config.get('logging') %}{{ render_section('LOGGING', config.logging) }}{% endif %}
</div>

<div class="panel corner-bracket mt-gap" style="padding:16px 24px;">
  <div class="panel-header" style="border:none;padding:0;margin-bottom:16px;"><span class="panel-title">INTEGRATIONS STATUS</span></div>
  <div style="display:flex;gap:24px;flex-wrap:wrap;">
    {% set ti = config.get('threat_intelligence', {}) %}
    {% set al = config.get('alerts', {}) %}
    {% for name, flag in [
      ('AbuseIPDB', ti.get('abuseipdb',{}).get('enabled')),
      ('VirusTotal', ti.get('virustotal',{}).get('enabled')),
      ('GeoIP', config.get('geoip',{}).get('enabled')),
      ('Email Alerts', al.get('email',{}).get('enabled')),
      ('Telegram Alerts', al.get('telegram',{}).get('enabled')),
    ] %}
    <div style="display:flex;align-items:center;gap:8px;">
      <span class="indicator {% if flag %}indicator-live{% else %}indicator-offline{% endif %}"></span>
      <span style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--on-surface-variant);">{{ name }}</span>
    </div>
    {% endfor %}
  </div>
  <div class="cb-bottom"></div>
</div>

{% endblock %}
```

---

## Task 13: Update learn/index.html and learn/topic.html

- [ ] **Step 1: Update learn/index.html — wrap content in new panel style**

The learn template has its own CSS via `learn.css`. Keep all JS intact. Only update the page-header and wrap containers with new classes. Replace the `<div class="page-header">` block:

```html
{% extends "base.html" %}
{% block title %}Cyber Academy — HomeNetGuard{% endblock %}
{% block content %}
<link rel="stylesheet" href="{{ url_for('static', filename='css/learn.css') }}">

<div class="page-header">
  <div>
    <h1 class="page-title">Cyber Academy</h1>
    <p style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--outline);margin-top:2px;">60 tópicos · 6 categorías · datos reales de tu red</p>
  </div>
</div>

<div class="academy-shell">
```

Then keep the rest of the original template unchanged (everything from `<!-- ── Stats + progreso global ──` to end of `{% endblock %}`).

- [ ] **Step 2: Update learn/topic.html — update page-header only**

Replace the page-header section:
```html
<div class="page-header">
  <div style="display:flex;align-items:center;gap:12px;">
    <a href="/learn" class="btn-ghost" style="font-size:10px;padding:4px 10px;">← Academy</a>
    <h1 class="page-title" style="font-size:20px;">Cyber Academy</h1>
  </div>
</div>
```

Keep everything else (article-shell, article-main, sidebar, all Jinja2 vars) unchanged.

---

## Task 14: Update docs templates

- [ ] **Step 1: Update docs/index.html**

```html
{% extends "base.html" %}
{% block title %}Documentation — HomeNetGuard{% endblock %}
{% block content %}
<link rel="stylesheet" href="{{ url_for('static', filename='css/docs.css') }}">

<div class="page-header">
  <div>
    <h1 class="page-title">Documentation</h1>
    <span style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--outline);">v{{ docs.version }}</span>
  </div>
</div>

<div style="padding: 0 0 40px;">
  <div class="docs-search-wrap">
    <input id="docs-search-input" class="docs-search-input" type="search" placeholder="Search documentation…" autocomplete="off">
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
  <div style="margin-top:40px;">
    <div style="font-family:'JetBrains Mono',monospace;font-size:10px;letter-spacing:0.12em;color:var(--outline);text-transform:uppercase;margin-bottom:12px;">QUICK START</div>
    <div style="display:flex;flex-direction:column;gap:6px;">
      <a href="/docs/getting-started/what-is-homenetguard" style="color:var(--secondary);font-size:13px;text-decoration:none;font-family:'JetBrains Mono',monospace;">→ ¿Qué es HomeNetGuard?</a>
      <a href="/docs/getting-started/installation"         style="color:var(--secondary);font-size:13px;text-decoration:none;font-family:'JetBrains Mono',monospace;">→ Instalación y requisitos</a>
      <a href="/docs/getting-started/first-launch"         style="color:var(--secondary);font-size:13px;text-decoration:none;font-family:'JetBrains Mono',monospace;">→ Primer arranque</a>
      <a href="/docs/cli-reference/cli-reference"          style="color:var(--secondary);font-size:13px;text-decoration:none;font-family:'JetBrains Mono',monospace;">→ Referencia de la CLI</a>
      <a href="/docs/troubleshooting/troubleshooting"      style="color:var(--secondary);font-size:13px;text-decoration:none;font-family:'JetBrains Mono',monospace;">→ Solución de problemas</a>
    </div>
  </div>
</div>

<script src="{{ url_for('static', filename='js/docs.js') }}" defer></script>
{% endblock %}
```

- [ ] **Step 2: Update docs/section.html and docs/article.html**

For `docs/section.html`, replace only the `page-header` area — keep `docs-layout`, `docs-nav`, `docs-content` and all Jinja2 vars intact:

```html
{% extends "base.html" %}
{% block title %}{{ section.title }} — HomeNetGuard Docs{% endblock %}
{% block content %}
<link rel="stylesheet" href="{{ url_for('static', filename='css/docs.css') }}">
<div class="docs-layout">
  <!-- rest unchanged -->
```

For `docs/article.html`, read the file first then make same minimal change to page-header if any exists.

---

## Task 15: Update learn.css and docs.css variable references

- [ ] **Step 1: Check learn.css for old var names and update to new tokens**

```bash
grep -n "var(--bg\|var(--accent\|var(--text-\|var(--severity\|Orbitron\|Inter" homenetguard/dashboard/static/css/learn.css | head -30
```

- [ ] **Step 2: Add compatibility aliases at top of learn.css**

The components.css already defines compatibility aliases (--bg-base, --text-primary, etc.) so learn.css should work without changes. Verify by checking if any unique vars exist.

```bash
grep "var(--" homenetguard/dashboard/static/css/learn.css | grep -v "bg-\|text-\|accent-\|severity-\|surface\|primary\|secondary\|outline\|error\|on-" | head -10
```

Fix any that use vars not in the alias map.

- [ ] **Step 3: Same for docs.css**

```bash
grep "var(--" homenetguard/dashboard/static/css/docs.css | grep -v "bg-\|text-\|accent-\|severity-\|surface\|primary\|secondary\|outline\|error\|on-" | head -10
```

---

## Task 16: Run tests and verify

- [ ] **Step 1: Run test suite**

```bash
cd /Users/Sergio/Documents/01-Proyectos/01-SW/homeNetGuard && pytest tests/ -v 2>&1 | tail -30
```

Expected: all tests pass (no Python files were modified).

- [ ] **Step 2: Verify no Orbitron references remain**

```bash
grep -r "Orbitron\|font-family.*Inter" homenetguard/dashboard/static/css/ homenetguard/dashboard/templates/ 2>/dev/null | grep -v "vendor/"
```

Expected: empty output.

- [ ] **Step 3: Verify all required JS IDs present in index.html**

```bash
grep -E "id=\"(kpi-flows|kpi-alerts|kpi-src-ips|kpi-bytes|bps-chart|proto-chart|geo-map|alert-feed|flows-tbody|top-ips-tbody|bps-live)\"" homenetguard/dashboard/templates/index.html | wc -l
```

Expected: 11

- [ ] **Step 4: Commit**

```bash
git add homenetguard/dashboard/static/css/ homenetguard/dashboard/static/js/ui.js homenetguard/dashboard/static/js/charts.js homenetguard/dashboard/templates/
git commit -m "feat(ui): complete visual redesign — dark cyberpunk design system

- New design tokens (tokens.css), CRT effects (effects.css), component library (components.css)
- Geist + JetBrains Mono typography, neon green accent, Material Symbols icons
- Sidebar layout with fixed topbar + footer
- All templates restyled preserving all Jinja2 vars and JS logic
- charts.js Chart.js theme, ui.js micro-interactions"
```
