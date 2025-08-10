(function() {
  'use strict';

  function animateProgress() {
    document.querySelectorAll('.cr-progress').forEach(function(el) {
      var bar = el.querySelector('.cr-progress-bar');
      var pct = parseFloat(el.getAttribute('data-pct')) || 0;
      // small stagger to make multiple bars animate pleasantly
      var delay = Math.min(300, Math.random() * 220);
      setTimeout(function() {
        bar.style.width = pct + '%';
      }, delay);
    });
  }

  function loadTheme() {
    var theme = localStorage.getItem('cr-theme') || 'light';
    if (theme === 'dark') {
      document.documentElement.setAttribute('data-theme', 'dark');
    } else {
      document.documentElement.removeAttribute('data-theme');
    }
  }

  function toggleTheme() {
    var isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    if (isDark) {
      document.documentElement.removeAttribute('data-theme');
      localStorage.setItem('cr-theme', 'light');
    } else {
      document.documentElement.setAttribute('data-theme', 'dark');
      localStorage.setItem('cr-theme', 'dark');
    }
  }

  document.addEventListener('DOMContentLoaded', function() {
    loadTheme();
    animateProgress();

    var btn = document.getElementById('cr-theme-toggle');
    if (btn) {
      btn.addEventListener('click', toggleTheme);
    }

    // re-animate when DOM changes (if server updates blocks live)
    var observer = new MutationObserver(function() {
      animateProgress();
    });
    var main = document.querySelector('main');
    if (main) {
      observer.observe(main, { childList: true, subtree: true });
    }
  });
})();
