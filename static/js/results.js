(function() {
  'use strict';

  function animateProgress() {
    document.querySelectorAll('.progress').forEach(function(el) {
      var bar = el.querySelector('.progress-bar');
      var pct = parseFloat(el.getAttribute('data-pct')) || 0;
      setTimeout(function() {
        bar.style.width = pct + '%';
      }, 80);
    });
  }

  function loadTheme() {
    var theme = localStorage.getItem('results-theme') || 'light';
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
      localStorage.setItem('results-theme', 'light');
    } else {
      document.documentElement.setAttribute('data-theme', 'dark');
      localStorage.setItem('results-theme', 'dark');
    }
  }

  document.addEventListener('DOMContentLoaded', function() {
    loadTheme();
    animateProgress();

    var btn = document.getElementById('theme-toggle');
    if (btn) {
      btn.addEventListener('click', function() {
        toggleTheme();
      });
    }

    var observer = new MutationObserver(function() {
      animateProgress();
    });
    observer.observe(document.querySelector('main'), { childList: true, subtree: true });
  });
})();
