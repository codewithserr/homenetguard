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

      let data;
      try {
        data = await loadDocs();
      } catch (e) {
        results.innerHTML = '<div class="docs-search-no-results">Search unavailable</div>';
        results.classList.add('visible');
        return;
      }
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
