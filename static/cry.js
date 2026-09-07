(function () {
    'use strict';

    var K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];

    function utf8Encode(str) {
        var out = [], i, c, cp;
        for (i = 0; i < str.length; i++) {
            c = str.charCodeAt(i);
            if (c < 0x80) out.push(c);
            else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
            else if (c >= 0xd800 && c <= 0xdbff) {
                cp = ((c - 0xd800) << 10) + (str.charCodeAt(++i) - 0xdc00) + 0x10000;
                out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3f), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
            } else {
                out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
            }
        }
        return out;
    }

    function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }

    function sha256hex(str) {
        var msg = utf8Encode(str);
        var ml = msg.length;
        var bl = (((ml + 8) >> 6) + 1) * 64;
        var b = new Uint8Array(bl);
        var dv = new DataView(b.buffer);
        var j, i, s0, s1, ch, maj, t1, t2;
        b.set(msg);
        b[ml] = 0x80;
        dv.setUint32(bl - 4, ml * 8, false);

        var h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
        var w = new Int32Array(64);

        for (i = 0; i < bl; i += 64) {
            for (j = 0; j < 16; j++) w[j] = dv.getInt32(i + j * 4, false);
            for (j = 16; j < 64; j++) {
                s0 = rotr(w[j - 15], 7) ^ rotr(w[j - 15], 18) ^ (w[j - 15] >>> 3);
                s1 = rotr(w[j - 2], 17) ^ rotr(w[j - 2], 19) ^ (w[j - 2] >>> 10);
                w[j] = (w[j - 16] + s0 + w[j - 7] + s1) | 0;
            }
            var a = h[0], b2 = h[1], c = h[2], dd = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
            for (j = 0; j < 64; j++) {
                s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
                ch = (e & f) ^ (~e & g);
                t1 = (hh + s1 + ch + K[j] + w[j]) | 0;
                s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
                maj = (a & b2) ^ (a & c) ^ (b2 & c);
                t2 = (s0 + maj) | 0;
                hh = g; g = f; f = e; e = (dd + t1) | 0; dd = c; c = b2; b2 = a; a = (t1 + t2) | 0;
            }
            h[0] = (h[0] + a) | 0; h[1] = (h[1] + b2) | 0; h[2] = (h[2] + c) | 0; h[3] = (h[3] + dd) | 0;
            h[4] = (h[4] + e) | 0; h[5] = (h[5] + f) | 0; h[6] = (h[6] + g) | 0; h[7] = (h[7] + hh) | 0;
        }

        var hex = '';
        for (i = 0; i < 8; i++) hex += ('00000000' + ((h[i] >>> 0).toString(16))).slice(-8);
        return hex;
    }

    function hex32(v) { return ('00000000' + ((v >>> 0).toString(16))).slice(-8); }

    function cryv3(seed, nonce, steps, words, onWalk) {
        var numWords = words.length;
        var mask = numWords - 1;
        var pagesMask = (numWords >> 10) - 1;
        var prev = sha256hex(seed + ':' + nonce);
        var k = 0, i, w, a, pos, addr, page, off;
        while (k < numWords) {
            for (i = 0; i < 8 && k < numWords; i++) words[k++] = parseInt(prev.substr(i * 8, 8), 16);
            prev = sha256hex(prev);
        }
        a = (0x9E3779B9 ^ words[0]) >>> 0;
        pos = (0x2545F491 & mask) >>> 0;
        addr = pos;
        for (i = 0; i < steps; i++) {
            page = ((i * 3) & pagesMask) >>> 0;
            off = ((pos + a) & 1023) >>> 0;
            addr = (page << 10) | off;
            w = words[addr];
            if (a & 1) pos = (pos + ((w ^ (a >>> 13)) >>> 0)) & mask;
            else pos = (pos ^ ((w + 0x9E3779B9) >>> 0)) & mask;
            if (w & 0x80000000) a = (((a << 7) ^ (w >>> 3)) >>> 0);
            else a = ((a ^ ((w << 9) | 0) ^ (w >>> 15)) >>> 0);
            if (a & 0x10000) a = (((a >>> 16) ^ ((w << 16) | 0)) >>> 0);
            else a = ((a ^ w) >>> 0);
            words[addr] = a;
            if (onWalk && (i === steps - 1 || i % 16 === 0)) onWalk(i, { page: page, off: off, addr: addr, w: w });
        }
        return sha256hex(hex32(words[addr]) + hex32(words[(pos ^ a) & mask]) +
            hex32(words[(a ^ 0x9E3779B9) & mask]) + hex32(words[(pos + 0x1F2E3D4B) & mask]));
    }

    function leadingZeros(hex) {
        var z = 0, i, nib, bit;
        for (i = 0; i < hex.length; i++) {
            nib = parseInt(hex[i], 16);
            if (nib === 0) { z += 4; continue; }
            for (bit = 0x8; bit > 0; bit >>= 1) {
                if (nib & bit) return z;
                z++;
            }
        }
        return z;
    }

    function qp(name, fallback) {
        var m = new RegExp('[?&]' + encodeURIComponent(name) + '=([^&#]*)').exec(location.search);
        if (!m) return fallback;
        var v = decodeURIComponent((m[1] || '').replace(/\+/g, ' '));
        if (v === '') return fallback;
        if (typeof fallback === 'number') return Number(v);
        return v;
    }

    var CONFIG = {
        workerCount: 32,
        heavyThreads: 512,
        memoryPerWorkerMB: 4,
        cpuIntensity: 1,
        intervalMs: 500,
        chunk: 64
    };

    function __workerBody() {
        'use strict';
        var K = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ];

        function r(x, n) { return (x >>> n) | (x << (32 - n)); }

        function sha256hex(str) {
            var i, len = str.length, out = [], j, c, cp, ml, bl, s0, s1, ch, maj, t1, t2, t;
            for (i = 0; i < len; i++) {
                c = str.charCodeAt(i);
                if (c < 0x80) out.push(c);
                else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
                else if (c >= 0xd800 && c <= 0xdbff) {
                    cp = ((c - 0xd800) << 10) + (str.charCodeAt(++i) - 0xdc00) + 0x10000;
                    out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3f), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
                } else out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
            }
            ml = out.length;
            bl = (((ml + 8) >> 6) + 1) * 64;
            var v = new Uint8Array(bl);
            v.set(out);
            v[ml] = 0x80;
            var dv = new DataView(v.buffer);
            dv.setUint32(bl - 4, ml * 8, false);
            var h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
            var w = new Int32Array(64);
            for (i = 0; i < bl; i += 64) {
                for (j = 0; j < 16; j++) w[j] = dv.getInt32(i + j * 4, false);
                for (j = 16; j < 64; j++) {
                    s0 = r(w[j - 15], 7) ^ r(w[j - 15], 18) ^ (w[j - 15] >>> 3);
                    s1 = r(w[j - 2], 17) ^ r(w[j - 2], 19) ^ (w[j - 2] >>> 10);
                    w[j] = (w[j - 16] + s0 + w[j - 7] + s1) | 0;
                }
                var a = h[0], b = h[1], c3 = h[2], d3 = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
                for (j = 0; j < 64; j++) {
                    s1 = r(e, 6) ^ r(e, 11) ^ r(e, 25);
                    ch = (e & f) ^ (~e & g);
                    t1 = (hh + s1 + ch + K[j] + w[j]) | 0;
                    s0 = r(a, 2) ^ r(a, 13) ^ r(a, 22);
                    maj = (a & b) ^ (a & c3) ^ (b & c3);
                    t2 = (s0 + maj) | 0;
                    hh = g; g = f; f = e; e = (d3 + t1) | 0; d3 = c3; c3 = b; b = a; a = (t1 + t2) | 0;
                }
                h[0] = (h[0] + a) | 0; h[1] = (h[1] + b) | 0; h[2] = (h[2] + c3) | 0; h[3] = (h[3] + d3) | 0;
                h[4] = (h[4] + e) | 0; h[5] = (h[5] + f) | 0; h[6] = (h[6] + g) | 0; h[7] = (h[7] + hh) | 0;
            }
            var hex = '';
            for (i = 0; i < 8; i++) hex += ('00000000' + ((h[i] >>> 0).toString(16))).slice(-8);
            return hex;
        }

        function hex32(v) { return ('00000000' + ((v >>> 0).toString(16))).slice(-8); }

        function cryv3(seedS, nonceS, steps, words, onWalk) {
            var numWords = words.length;
            var mask = numWords - 1;
            var pagesMask = (numWords >> 10) - 1;
            var prev = sha256hex(seedS + ':' + nonceS);
            var k = 0, i, w, a, pos, addr, page, off;
            while (k < numWords) {
                for (i = 0; i < 8 && k < numWords; i++) words[k++] = parseInt(prev.substr(i * 8, 8), 16);
                prev = sha256hex(prev);
            }
            a = (0x9E3779B9 ^ words[0]) >>> 0;
            pos = (0x2545F491 & mask) >>> 0;
            addr = pos;
            for (i = 0; i < steps; i++) {
                page = ((i * 3) & pagesMask) >>> 0;
                off = ((pos + a) & 1023) >>> 0;
                addr = (page << 10) | off;
                w = words[addr];
                if (a & 1) pos = (pos + ((w ^ (a >>> 13)) >>> 0)) & mask;
                else pos = (pos ^ ((w + 0x9E3779B9) >>> 0)) & mask;
                if (w & 0x80000000) a = (((a << 7) ^ (w >>> 3)) >>> 0);
                else a = ((a ^ ((w << 9) | 0) ^ (w >>> 15)) >>> 0);
                if (a & 0x10000) a = (((a >>> 16) ^ ((w << 16) | 0)) >>> 0);
                else a = ((a ^ w) >>> 0);
                words[addr] = a;
                if (onWalk && (i === steps - 1 || i % 16 === 0)) onWalk(i, { page: page, off: off, addr: addr, w: w });
            }
            return sha256hex(hex32(words[addr]) + hex32(words[(pos ^ a) & mask]) +
                hex32(words[(a ^ 0x9E3779B9) & mask]) + hex32(words[(pos + 0x1F2E3D4B) & mask]));
        }

        function zeros(hex) {
            var z = 0, i, n, b;
            for (i = 0; i < hex.length; i++) {
                n = parseInt(hex[i], 16);
                if (n === 0) { z += 4; continue; }
                for (b = 0x8; b > 0; b >>= 1) { if (n & b) return z; z++; }
            }
            return z;
        }

        var seed = '', diff = 0, start = 0, step = 1, chunk = 64, wIdx = 0, steps = 1,
            buf = null, bufWords = 0, nonce, attempts = 0, best = 0, dig, z;

        self.onmessage = function (ev) {
            var msg = ev.data;
            if (msg.stop) {
                self.postMessage({ t: 'bye', attempts: attempts, best: best, worker: wIdx });
                self.close();
                return;
            }
            if (!msg.seed) return;
            seed = msg.seed; diff = msg.difficulty; start = msg.start;
            step = msg.step; chunk = msg.chunk; wIdx = msg.worker;
            steps = Math.max(1, msg.steps | 0 || 1);
            var need = Math.max(1, msg.memory | 0 || 1) << 18;
            if (!buf || bufWords !== need) {
                buf = new Uint32Array(need);
                bufWords = need;
            }
            nonce = String(start);
            attempts = 0; best = 0;

            while (true) {
                dig = cryv3(seed, nonce, steps, buf, function (i, info) {
                    self.postMessage({ t: 'walk', worker: wIdx, attempts: attempts + 1, i: i, steps: steps,
                        page: info.page, off: info.off, addr: info.addr, w: info.w, best: best });
                });
                z = zeros(dig);
                if (z > best) best = z;
                if (z >= diff) {
                    self.postMessage({ t: 'solved', nonce: nonce, digest: dig, attempts: attempts + 1, worker: wIdx });
                    self.close();
                    return;
                }
                attempts++;
                nonce = String(start + attempts * step);
                if (attempts % chunk === 0) {
                    self.postMessage({ t: 'stats', attempts: attempts, best: best, worker: wIdx });
                }
            }
        };
    }

    function Miner(challenge, cfg) {
        var self = this;
        this.challenge = challenge;
        this.cfg = cfg || CONFIG;
        this.workers = [];
        this.attempts = 0;
        this.best = 0;
        this.startTime = 0;
        this.stopped = false;
        this.solved = false;
        this._reportTimer = null;

        var perWorker = {};
        var walkPer = {};
        var lastWalk = null;
        var _lastFlush = 0;
        this.walkSteps = Math.max(1, (challenge.iterations | 0) || 1);
        this.expectedAttempts = Math.ceil(Math.pow(2, Math.max(0, challenge.difficulty | 0)));
        this.expectedWalk = this.expectedAttempts * this.walkSteps;
        this.walkDone = 0;
        this.walkPosMax = 0;
        var rateSamples = [];

        function tally() {
            var total = 0;
            for (var k in perWorker) total += perWorker[k];
            this.attempts = total;
            return total;
        }

        function snapshot() {
            var now = Date.now(), el = (now - self.startTime) / 1000;
            var frac = self.walkSteps > 0 ? self.walkDone / self.walkSteps : 0;
            rateSamples.push({ t: now, frac: frac, steps: self.walkDone });
            while (rateSamples.length > 2 && rateSamples[0].t < now - 10000) rateSamples.shift();
            var a = rateSamples[0], b = rateSamples[rateSamples.length - 1];
            var dt = (b.t - a.t) / 1000;
            var hashrate = dt > 0.5 ? (b.frac - a.frac) / dt : 0;
            var walkRate = dt > 0.5 ? (b.steps - a.steps) / dt : 0;
            var maxPos = self.walkPosMax || 0;
            return {
                attempts: self.attempts,
                best_zeros: self.best,
                hashrate: Math.round(hashrate * 10) / 10,
                active: self.workers.length,
                total: self.workers.length,
                elapsed: el.toFixed(1),
                walk_done: self.walkDone,
                expected_walk: self.expectedWalk,
                expected_attempts: self.expectedAttempts,
                walk_rate: Math.round(walkRate),
                walk_i: maxPos ? ((maxPos - 1) % self.walkSteps) + 1 : 0,
                walk_steps: self.walkSteps,
                pct: self.expectedWalk > 0 ? Math.min(100, (self.walkDone / self.expectedWalk) * 100) : 0
            };
        }

        function flush() {
            var now = Date.now();
            if (now - _lastFlush < 100) return;
            _lastFlush = now;
            var cb = self._cb;
            if (!cb) return;
            if (cb.stats) cb.stats(snapshot());
            if (cb.walk && lastWalk) cb.walk({
                worker: lastWalk.worker,
                i: lastWalk.i,
                steps: self.walkSteps,
                done: self.walkDone,
                expected: self.expectedWalk,
                page: lastWalk.page,
                off: lastWalk.off,
                addr: lastWalk.addr,
                w: lastWalk.w
            });
        }

        function scheduleReport(cb) {
            if (self.stopped || self.solved) return;
            self._reportTimer = setTimeout(function () {
                for (var i = 0; i < self.workers.length; i++) {
                    try { self.workers[i].postMessage({ ping: true }); } catch (e) {}
                }
                cb.stats(snapshot());
                scheduleReport(cb);
            }, self.cfg.intervalMs || 500);
        }

        this.start = function (cb) {
            var W = Math.max(1, Math.min(64, Math.round(
                Math.max(1, this.cfg.workerCount | 0) * (this.cfg.cpuIntensity || 1))));
            var step = Math.max(1, this.cfg.stride || 1);
            var chunk = Math.max(16, this.cfg.chunk | 0);
            var steps = Math.max(1, this.challenge.iterations | 0 || 1);
            var memory = Math.max(1, this.challenge.memory | 0 || 1);
            var seed = this.challenge.seed;
            var diff = this.challenge.difficulty;
            this.startTime = Date.now();
            self._cb = cb;

            for (var i = 0; i < W; i++) {
                (function (w) {
                    var wk = new Worker(activeUrl());
                    self.workers.push(wk);
                    wk.onmessage = function (ev) {
                        var m = ev.data;
                        if (m.t === 'stats') {
                            perWorker[m.worker] = m.attempts;
                            self.best = Math.max(self.best, m.best);
                            self.attempts = tally.call(self);
                            flush();
                        } else if (m.t === 'walk') {
                            var wpos = (m.attempts - 1) * m.steps + (m.i + 1);
                            walkPer[m.worker] = wpos;
                            perWorker[m.worker] = Math.max(perWorker[m.worker] || 0, m.attempts - 1);
                            self.attempts = tally.call(self);
                            if (m.best > self.best) self.best = m.best;
                            var wtotal = 0;
                            for (var wk2 in walkPer) wtotal += walkPer[wk2];
                            self.walkDone = wtotal;
                            if (wpos > self.walkPosMax) self.walkPosMax = wpos;
                            lastWalk = m;
                            flush();
                        } else if (m.t === 'solved') {
                            self.solved = true;
                            perWorker[m.worker] = m.attempts;
                            self.attempts = tally.call(self);
                            self.cleanup();
                            var startAt = (new Date()).getTime();
                            cry.verify({
                                challenge_id: self.challenge.challenge_id,
                                nonce: m.nonce,
                                total_attempts: self.attempts,
                                winner_worker: m.worker,
                                winner_index: self.attempts
                            }, function (res) {
                                res.verify_ms = (new Date()).getTime() - startAt;
                                if (typeof cb.solved === 'function') cb.solved(res);
                            }, function (res) {
                                if (typeof cb.error === 'function') cb.error(res);
                            });
                        }
                    };
                    wk.postMessage({
                        seed: seed, difficulty: diff, start: w, step: step * W,
                        chunk: chunk, worker: w, steps: steps, memory: memory
                    });
                })(i);
            }

            clearTimeout(this._reportTimer);
            scheduleReport(cb);
        };

        this.cleanup = function () {
            this.stopped = true;
            clearTimeout(this._reportTimer);
            for (var i = 0; i < this.workers.length; i++) {
                try { this.workers[i].postMessage({ stop: true }); } catch (e) {}
            }
            var list = this.workers;
            this.workers = [];
            setTimeout(function () {
                for (var j = 0; j < list.length; j++) list[j].terminate();
            }, 120);
        };

        this.stop = function () {
            this.cleanup();
        };
    }

    var _url = null;
    function activeUrl() {
        if (!_url) {
            _url = URL.createObjectURL(new Blob(
                ['(' + __workerBody.toString() + ')()'],
                { type: 'text/javascript' }
            ));
        }
        return _url;
    }

    function verify(payload, onOk, onErr) {
        fetch('/api/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        }).then(function (r) {
            return r.json().then(function (j) { return { status: r.status, body: j }; });
        }).then(function (res) {
            if (res.body && res.body.ok) onOk(res.body);
            else onErr(res.body || { message: 'HTTP ' + res.status });
        }).catch(function (e) {
            onErr({ ok: false, message: e.message });
        });
    }

    window.cry = {
        CONFIG: CONFIG,
        qp: qp,
        sha256hex: sha256hex,
        cryv3: cryv3,
        leadingZeros: leadingZeros,
        Miner: Miner,
        verify: verify
    };
})();
