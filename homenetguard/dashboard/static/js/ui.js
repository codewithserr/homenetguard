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

  // Topbar search → /docs redirect
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
    const tick = () => { clockEl.textContent = new Date().toUTCString().slice(17, 25) + ' UTC'; };
    tick();
    setInterval(tick, 1000);
  }

  // INITIATE SCAN button
  const scanBtn = document.getElementById('btn-initiate-scan');
  if (scanBtn) {
    scanBtn.addEventListener('click', async () => {
      scanBtn.textContent = 'SCANNING...';
      scanBtn.disabled = true;
      try {
        await fetch('/api/v1/devices/scan', {
          method: 'POST',
          headers: { 'X-API-Key': window.HNG_API_KEY || '' }
        });
      } catch (e) { /* silent */ }
      setTimeout(() => {
        scanBtn.textContent = 'INITIATE SCAN';
        scanBtn.disabled = false;
      }, 3000);
    });
  }

});
