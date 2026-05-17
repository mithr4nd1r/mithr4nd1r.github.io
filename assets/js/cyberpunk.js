/* cyberpunk.js — typewriter + glitch effects */
(function () {
  'use strict';

  // ─── Typewriter ─────────────────────────────────────────────────────────────

  function initTypewriter() {
    var el = document.getElementById('typewriter');
    if (!el) return;

    var phrases = [
      'Red Team Operator @ Sicoob',
      'OSCE³ · OSCP · GXPN',
      'My shell should pass!'
    ];

    var phraseIndex = 0;
    var charIndex = 0;
    var deleting = false;
    var pause = false;

    var TYPING_SPEED   = 55;
    var DELETING_SPEED = 28;
    var PAUSE_AFTER    = 2200;
    var PAUSE_BEFORE   = 350;

    function tick() {
      var current = phrases[phraseIndex];

      if (!deleting) {
        charIndex++;
        el.textContent = current.substring(0, charIndex);

        if (charIndex === current.length) {
          if (pause) return;
          pause = true;
          setTimeout(function () {
            pause = false;
            deleting = true;
            setTimeout(tick, DELETING_SPEED);
          }, PAUSE_AFTER);
          return;
        }
      } else {
        charIndex--;
        el.textContent = current.substring(0, charIndex);

        if (charIndex === 0) {
          deleting = false;
          phraseIndex = (phraseIndex + 1) % phrases.length;
          setTimeout(tick, PAUSE_BEFORE);
          return;
        }
      }

      setTimeout(tick, deleting ? DELETING_SPEED : TYPING_SPEED);
    }

    // Small initial delay before starting
    setTimeout(tick, 600);
  }

  // ─── Glitch on hover (optional reinforcement) ────────────────────────────────

  function initGlitchHover() {
    var glitchEls = document.querySelectorAll('.glitch');
    glitchEls.forEach(function (el) {
      if (!el.dataset.text) {
        el.dataset.text = el.textContent;
      }
    });
  }

  // ─── Sidebar toggle (mobile) ─────────────────────────────────────────────────

  function initSidebar() {
    var trigger = document.getElementById('sidebar-trigger');
    var sidebar = document.getElementById('sidebar');
    var backdrop = document.getElementById('sidebar-backdrop');

    if (!trigger || !sidebar) return;

    function openSidebar() {
      sidebar.classList.add('open');
      if (backdrop) backdrop.classList.add('active');
      document.body.setAttribute('sidebar-display', '');
    }

    function closeSidebar() {
      sidebar.classList.remove('open');
      if (backdrop) backdrop.classList.remove('active');
      document.body.removeAttribute('sidebar-display');
    }

    trigger.addEventListener('click', function () {
      if (sidebar.classList.contains('open')) {
        closeSidebar();
      } else {
        openSidebar();
      }
    });

    if (backdrop) {
      backdrop.addEventListener('click', closeSidebar);
    }
  }

  // ─── Back to top ─────────────────────────────────────────────────────────────

  function initBackToTop() {
    var btn = document.getElementById('back-to-top');
    if (!btn) return;

    window.addEventListener('scroll', function () {
      if (window.scrollY > 300) {
        btn.classList.add('show');
      } else {
        btn.classList.remove('show');
      }
    }, { passive: true });

    btn.addEventListener('click', function (e) {
      e.preventDefault();
      window.scrollTo({ top: 0, behavior: 'smooth' });
    });
  }

  // ─── Search toggle ────────────────────────────────────────────────────────────

  function initSearch() {
    var trigger = document.getElementById('search-trigger');
    var wrapper = document.getElementById('search-wrapper');
    var cancel  = document.getElementById('search-cancel');
    var input   = document.getElementById('search-input');

    if (!trigger || !wrapper) return;

    trigger.addEventListener('click', function () {
      wrapper.classList.add('active');
      cancel && cancel.classList.add('active');
      input && input.focus();
      trigger.style.display = 'none';
    });

    function closeSearch() {
      wrapper.classList.remove('active');
      cancel && cancel.classList.remove('active');
      if (input) input.value = '';
      trigger.style.display = '';
    }

    cancel && cancel.addEventListener('click', closeSearch);

    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') closeSearch();
    });
  }

  // ─── Fade in post cards ───────────────────────────────────────────────────────

  function initFadeIn() {
    if (!('IntersectionObserver' in window)) return;

    var cards = document.querySelectorAll('.post-preview, .bio-row');
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add('fade-in');
          io.unobserve(entry.target);
        }
      });
    }, { threshold: 0.1 });

    cards.forEach(function (c) { io.observe(c); });
  }

  // ─── Init ─────────────────────────────────────────────────────────────────────

  document.addEventListener('DOMContentLoaded', function () {
    initTypewriter();
    initGlitchHover();
    initSidebar();
    initBackToTop();
    initSearch();
    initFadeIn();
  });

})();
