// Runs inside proxied pages: sends dynamic requests back through the proxy.
(function () {
  var BASE = window.__PROXY_BASE;
  var PREFIX = location.origin + '/p/';
  function px(u) {
    try {
      var a = new URL(u, BASE);
      if (!/^https?:$/.test(a.protocol)) return u;
      if (a.href.indexOf(PREFIX) === 0) return a.href;
      return PREFIX + encodeURIComponent(a.href);
    } catch (e) { return u; }
  }
  var f = window.fetch;
  window.fetch = function (input, init) {
    try {
      if (typeof input === 'string' || input instanceof URL) input = px(String(input));
      else if (input && input.url) input = new Request(px(input.url), input);
    } catch (e) {}
    return f.call(this, input, init);
  };
  var open = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (m, u) {
    arguments[1] = px(String(u));
    return open.apply(this, arguments);
  };
  var wo = window.open;
  window.open = function (u) { arguments[0] = u ? px(String(u)) : u; return wo.apply(this, arguments); };
  ['pushState', 'replaceState'].forEach(function (k) {
    var o = history[k];
    history[k] = function (s, t, u) { try { if (u) u = px(String(u)); } catch (e) {} return o.call(this, s, t, u); };
  });
  var sa = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function (n, v) {
    if (/^(src|href|action)$/i.test(n) && typeof v === 'string' && !/^(#|javascript:|data:|blob:)/i.test(v)) v = px(v);
    return sa.call(this, n, v);
  };
  document.addEventListener('submit', function (e) {
    var form = e.target;
    var a = form.getAttribute('action');
    if (a && a.indexOf('/p/') !== 0) form.setAttribute('action', a);
    else if (!a) form.setAttribute('action', px(BASE));
  }, true);
})();
