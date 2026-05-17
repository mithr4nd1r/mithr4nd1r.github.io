function toggleGroup(id) {
  var group = document.getElementById('group-' + id);
  if (!group) return;
  var open = group.classList.toggle('open');
  var btn = group.querySelector('.sidebar-group-label');
  if (btn) btn.setAttribute('aria-expanded', open ? 'true' : 'false');
}

(function () {
  var navBtn = document.getElementById('nav-toggle');
  var navLinks = document.getElementById('nav-links');
  if (navBtn && navLinks) {
    navBtn.addEventListener('click', function () {
      var open = navLinks.classList.toggle('open');
      navBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
      navBtn.textContent = open ? 'close' : 'menu';
    });
  }

  // mobile sidebar drawer trigger (auto-add a button if a sidebar is present)
  var sidebar = document.getElementById('sidebar');
  if (sidebar && window.matchMedia('(max-width: 900px)').matches) {
    var btn = document.createElement('button');
    btn.className = 'nav-mobile-btn sidebar-trigger';
    btn.type = 'button';
    btn.textContent = 'index';
    btn.style.cssText = 'position:fixed;bottom:18px;left:18px;z-index:160;background:#15181d;border:1px solid #2c3039;color:#e8eaef;padding:10px 16px;font-family:JetBrains Mono,monospace;font-size:0.75rem;letter-spacing:2px;text-transform:uppercase;cursor:pointer;';
    btn.addEventListener('click', function () {
      sidebar.classList.toggle('open');
      btn.textContent = sidebar.classList.contains('open') ? 'close' : 'index';
    });
    document.body.appendChild(btn);
  }
})();

window.addEventListener('pageshow', function (event) {
  if (event.persisted) {
    document.querySelectorAll('.sidebar-group').forEach(function (g) {
      g.classList.remove('open');
    });
    var active = document.querySelector('.sidebar-items a.active');
    if (active) {
      var parentGroup = active.closest('.sidebar-group');
      if (parentGroup) parentGroup.classList.add('open');
    }
  }
});
