/* ──────────────────────────────────────────────
   HNG Terminal — parser, WS client, UI, autocomplete
   ────────────────────────────────────────────── */

(function () {
  'use strict';

  // ── Constants ──────────────────────────────
  const SHELL_META = /[;&|><`$\\]|\$\(/;
  const APP_CMDS = new Set([
    'block','unblock','quarantine','release',
    'sinkhole','unsinkhole','flows','alerts','whois','devices','help'
  ]);
  const NET_CMDS = new Set(['ping','dig','nslookup','traceroute','nmap']);
  const ALL_CMDS = new Set([...APP_CMDS, ...NET_CMDS]);
  const MAX_HISTORY = 50;
  const HISTORY_KEY = 'hng_terminal_history';

  // ── State ──────────────────────────────────
  let _isOpen = false;
  let _socket = null;
  let _history = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
  let _historyIndex = -1;
  let _acItems = [];
  let _acIndex = -1;

  // ── DOM refs (resolved after DOMContentLoaded) ──
  let _panel, _output, _input, _acList, _backdrop;

  // ── Parser ─────────────────────────────────
  function parse(raw) {
    raw = raw.trim();
    if (!raw) return null;
    if (SHELL_META.test(raw)) throw new Error('invalid characters in input');
    const tokens = raw.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g) || [];
    if (!tokens.length) return null;
    const cmd = tokens[0].toLowerCase();
    if (!ALL_CMDS.has(cmd)) throw new Error(`unknown command: ${cmd}`);
    const args = tokens.slice(1).map(t => t.replace(/^["']|["']$/g, ''));
    if (cmd === 'block' && args.length > 1) {
      return { cmd, args: [args[0], args.slice(1).join(' ')] };
    }
    return { cmd, args };
  }

  // ── Output rendering ───────────────────────
  function appendLine(text, type) {
    type = type || 'stdout';
    const el = document.createElement('div');
    el.className = 'hng-line hng-line--' + type;
    el.textContent = text;
    _output.appendChild(el);
    _output.scrollTop = _output.scrollHeight;
  }

  function appendCmdEcho(raw) {
    appendLine('HNG> ' + raw, 'cmd');
  }

  // ── History ────────────────────────────────
  function pushHistory(cmd) {
    if (!cmd || _history[0] === cmd) return;
    _history.unshift(cmd);
    if (_history.length > MAX_HISTORY) _history.pop();
    localStorage.setItem(HISTORY_KEY, JSON.stringify(_history));
    _historyIndex = -1;
  }

  // ── Autocomplete ───────────────────────────
  function hideAc() {
    _acList.hidden = true;
    _acItems = [];
    _acIndex = -1;
  }

  function showAc(items) {
    _acList.innerHTML = '';
    _acItems = items;
    _acIndex = -1;
    items.forEach(function(item, i) {
      const el = document.createElement('div');
      el.className = 'hng-autocomplete-item';
      el.textContent = item;
      el.addEventListener('mousedown', function(e) {
        e.preventDefault();
        applyAcItem(i);
      });
      _acList.appendChild(el);
    });
    _acList.hidden = items.length === 0;
  }

  function applyAcItem(idx) {
    const item = _acItems[idx];
    if (!item) return;
    const tokens = _input.value.trim().split(/\s+/);
    tokens[tokens.length - 1] = item;
    _input.value = tokens.join(' ') + ' ';
    hideAc();
    _input.focus();
  }

  function fetchSuggestions(q, type) {
    if (q.length < 2) { hideAc(); return; }
    fetch('/api/v1/terminal/suggest?q=' + encodeURIComponent(q) + '&type=' + type)
      .then(function(res) { return res.ok ? res.json() : null; })
      .then(function(data) { if (data) showAc(data.suggestions); else hideAc(); })
      .catch(function() { hideAc(); });
  }

  function handleTabAutocomplete() {
    if (_acItems.length > 0) {
      _acIndex = (_acIndex + 1) % _acItems.length;
      document.querySelectorAll('.hng-autocomplete-item').forEach(function(el, i) {
        el.classList.toggle('is-active', i === _acIndex);
      });
      applyAcItem(_acIndex);
      return;
    }
    const val = _input.value.trim();
    const tokens = val.split(/\s+/);
    const cmd = tokens[0] ? tokens[0].toLowerCase() : '';
    const lastToken = tokens[tokens.length - 1];

    if (tokens.length === 1) {
      const matches = Array.from(ALL_CMDS).filter(function(c) { return c.startsWith(cmd); });
      if (matches.length === 1) { _input.value = matches[0] + ' '; }
      else if (matches.length > 1) { showAc(matches); }
      return;
    }

    let suggestType = 'ip';
    if (cmd === 'quarantine' || cmd === 'release') suggestType = 'mac';
    else if (cmd === 'sinkhole' || cmd === 'unsinkhole' || cmd === 'dig' || cmd === 'nslookup') suggestType = 'domain';
    fetchSuggestions(lastToken, suggestType);
  }

  // ── WebSocket ──────────────────────────────
  function ensureSocket() {
    if (_socket) return;
    _socket = io({ transports: ['websocket', 'polling'] });

    _socket.on('terminal:out', function(data) {
      appendLine(data.line, data.type);
    });

    _socket.on('terminal:done', function(data) {
      if (data.code !== 0) {
        appendLine('[exit ' + data.code + ' · ' + data.duration + 's]', 'error');
      } else {
        appendLine('[done · ' + data.duration + 's]', 'info');
      }
      _input.disabled = false;
      _input.focus();
    });
  }

  function execCommand(raw) {
    var parsed;
    try {
      parsed = parse(raw);
    } catch (e) {
      appendLine('Parse error: ' + e.message, 'error');
      return;
    }
    if (!parsed) return;

    pushHistory(raw);
    appendCmdEcho(raw);
    _input.disabled = true;
    ensureSocket();
    _socket.emit('terminal:exec', { raw: raw });
  }

  // ── Open / Close ───────────────────────────
  function open(prefill) {
    _panel.classList.add('is-open');
    _panel.setAttribute('aria-hidden', 'false');
    _backdrop.hidden = false;
    _isOpen = true;
    _input.focus();
    if (prefill !== undefined) {
      _input.value = prefill;
    }
    if (_output.children.length === 0) {
      appendLine('HomeNetGuard Terminal — type "help" for commands', 'info');
    }
  }

  function close() {
    _panel.classList.remove('is-open');
    _panel.setAttribute('aria-hidden', 'true');
    _backdrop.hidden = true;
    _isOpen = false;
    hideAc();
  }

  function toggle(prefill) {
    if (_isOpen && prefill === undefined) { close(); } else { open(prefill); }
  }

  // ── Public API ─────────────────────────────
  window.hngTerminal = {
    open: open,
    close: close,
    toggle: toggle,
    fill: function(cmd) { open(cmd); },
  };

  // ── CMD_SEARCH wiring ──────────────────────
  function wireCmdSearch() {
    const input = document.querySelector('input[placeholder="CMD_SEARCH..."]');
    if (!input) return;
    input.addEventListener('focus', function() {
      input.blur();
      toggle();
    });
  }

  // ── Keyboard shortcuts ─────────────────────
  document.addEventListener('keydown', function(e) {
    if (e.ctrlKey && e.key === '`') {
      e.preventDefault();
      toggle();
      return;
    }
    if (!_isOpen) return;
    if (e.key === 'Escape') {
      if (_acItems.length > 0) { hideAc(); } else { close(); }
    }
  });

  // ── Input event handlers ───────────────────
  function initInput() {
    _input.addEventListener('keydown', function(e) {
      if (e.key === 'Enter') {
        e.preventDefault();
        const val = _input.value.trim();
        hideAc();
        if (val) { execCommand(val); }
        _input.value = '';
        _historyIndex = -1;
        return;
      }
      if (e.key === 'Tab') {
        e.preventDefault();
        handleTabAutocomplete();
        return;
      }
      if (e.key === 'ArrowUp') {
        e.preventDefault();
        if (_history.length === 0) return;
        _historyIndex = Math.min(_historyIndex + 1, _history.length - 1);
        _input.value = _history[_historyIndex];
        return;
      }
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        if (_historyIndex <= 0) { _historyIndex = -1; _input.value = ''; return; }
        _historyIndex -= 1;
        _input.value = _historyIndex >= 0 ? _history[_historyIndex] : '';
        return;
      }
    });

    _input.addEventListener('input', function() {
      const val = _input.value;
      const tokens = val.trim().split(/\s+/);
      if (tokens.length < 2) { hideAc(); return; }
      const cmd = tokens[0].toLowerCase();
      const lastToken = tokens[tokens.length - 1];
      if (!lastToken || lastToken.length < 2) { hideAc(); return; }
      let suggestType = 'ip';
      if (cmd === 'quarantine' || cmd === 'release') suggestType = 'mac';
      else if (cmd === 'sinkhole' || cmd === 'unsinkhole' || cmd === 'dig' || cmd === 'nslookup') suggestType = 'domain';
      fetchSuggestions(lastToken, suggestType);
    });
  }

  // ── Quick-cmd buttons ──────────────────────
  function initQuickBtns() {
    document.querySelectorAll('.hng-qbtn').forEach(function(btn) {
      btn.addEventListener('click', function() {
        open(btn.dataset.cmd);
        _input.focus();
      });
    });
  }

  // ── Global click-to-fill handler ──────────
  function initClickToFill() {
    document.addEventListener('click', function(e) {
      const cell = e.target.closest('[data-hng-fill]');
      if (!cell) return;
      const cmd = cell.dataset.hngFill;
      if (cmd) window.hngTerminal.fill(cmd);
    });
  }

  // ── Init ───────────────────────────────────
  document.addEventListener('DOMContentLoaded', function() {
    _panel    = document.getElementById('hng-terminal');
    _output   = document.getElementById('hng-terminal-output');
    _input    = document.getElementById('hng-terminal-input');
    _acList   = document.getElementById('hng-autocomplete-list');
    _backdrop = document.getElementById('hng-terminal-backdrop');

    if (!_panel) return;

    document.getElementById('hng-terminal-close').addEventListener('click', close);
    _backdrop.addEventListener('click', close);

    initInput();
    initQuickBtns();
    wireCmdSearch();
    initClickToFill();
  });
})();
