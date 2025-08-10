(function() {
  'use strict';

  function showToast(message) {
    var toast = document.getElementById('md-toast');
    if (!toast) return;
    toast.textContent = message || 'Changes saved.';
    toast.hidden = false;
    toast.classList.add('show');
    setTimeout(function() {
      toast.classList.remove('show');
      setTimeout(function() { toast.hidden = true; }, 300);
    }, 2500);
  }

  document.addEventListener('DOMContentLoaded', function() {
    var form = document.getElementById('md-form');
    if (!form) return;

    form.addEventListener('submit', function(e) {
      // show a confirmation modal instead of immediately submitting
      var confirmed = confirm('Apply dashboard status changes now?');
      if (!confirmed) {
        e.preventDefault();
        return;
      }

      // allow form to submit normally; show toast after short delay
      setTimeout(function() {
        showToast('Saved successfully');
      }, 600);
    });

    // Enhance label click behavior: toggle the hidden checkbox if user clicks anywhere on the card
    document.querySelectorAll('.md-card').forEach(function(card) {
      card.addEventListener('click', function(ev) {
        // if click originates from the input or a link do nothing special
        if (ev.target.tagName === 'INPUT' || ev.target.tagName === 'A' || ev.target.closest('a')) {
          return;
        }
        var checkbox = card.querySelector('.md-checkbox');
        if (checkbox) {
          checkbox.checked = !checkbox.checked;
          // dispatch change event for accessibility
          checkbox.dispatchEvent(new Event('change', { bubbles: true }));
        }
      });
    });
  });
})();
