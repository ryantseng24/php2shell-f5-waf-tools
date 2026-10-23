(function () {
  // Copy button on every code block; falls back to selecting the text when the clipboard is refused.
  document.querySelectorAll('.code').forEach(function (box) {
    var pre = box.querySelector('pre');
    var btn = document.createElement('button');
    btn.type = 'button';
    btn.textContent = '複製';
    btn.addEventListener('click', function () {
      var done = function () { btn.textContent = '已複製'; setTimeout(function () { btn.textContent = '複製'; }, 1500); };
      var fallback = function () {
        var r = document.createRange(); r.selectNodeContents(pre);
        var s = window.getSelection(); s.removeAllRanges(); s.addRange(r);
        btn.textContent = '已選取';
      };
      try { navigator.clipboard.writeText(pre.innerText).then(done, fallback); } catch (e) { fallback(); }
    });
    box.appendChild(btn);
  });

  // Click a screenshot to see it full size.
  var lb = document.getElementById('lightbox');
  if (!lb) return;
  var lbImg = lb.querySelector('img');
  document.querySelectorAll('figure button').forEach(function (b) {
    b.addEventListener('click', function () {
      var img = b.querySelector('img');
      lbImg.src = img.src; lbImg.alt = img.alt;
      lb.hidden = false;
    });
  });
  lb.addEventListener('click', function () { lb.hidden = true; });
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') lb.hidden = true; });
})();
