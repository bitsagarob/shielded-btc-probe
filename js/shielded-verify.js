/* Shielded Bitcoin probe: decrypt real envelopes from the Bitsaga Signet in
 * the browser.
 *
 * Companion to the Rust crate shielded-probe, which implements the transfer
 * layer of "Shielded Bitcoin: Private Transfers on the Bitcoin L1"
 * (Shikhelman, Komarov, Moskvin, 24 September 2026) with the profile in its
 * PROFILE.md. This file redoes the read side of that profile: parse the
 * OP_RETURN envelope, recompute the note leaves, and decrypt outputs with a
 * viewing key. Poseidon over BLS12-381 Fr, Jubjub, the note cipher and the
 * sender-recovery AEAD are all written out with BigInt. No library, no
 * WebAssembly. WebCrypto is used only for SHA-256 and HKDF in the sender path.
 *
 * Constants (Poseidon round keys, curve coefficients, domain tags, envelope
 * layout) come from shielded-data.json, printed by `sbp export-js`. Call
 * load(data) once before anything else; selfTest(data) does that for you.
 */
(function (root) {
  "use strict";

  var P, ROUNDS, TAG, C, CURVE, SQRT;

  /* ------------------------------------------------------------------ bytes */

  function hexToBytes(hex) {
    if (typeof hex !== "string" || hex.length % 2 !== 0 || /[^0-9a-fA-F]/.test(hex)) {
      throw new Error("not hex");
    }
    var out = new Uint8Array(hex.length / 2);
    for (var i = 0; i < out.length; i++) { out[i] = parseInt(hex.substr(i * 2, 2), 16); }
    return out;
  }

  function bytesToHex(b) {
    var s = "";
    for (var i = 0; i < b.length; i++) { s += (b[i] >> 4).toString(16) + (b[i] & 15).toString(16); }
    return s;
  }

  function concat(parts) {
    var n = 0, i;
    for (i = 0; i < parts.length; i++) { n += parts[i].length; }
    var out = new Uint8Array(n), o = 0;
    for (i = 0; i < parts.length; i++) { out.set(parts[i], o); o += parts[i].length; }
    return out;
  }

  function equal(a, b) {
    if (a.length !== b.length) { return false; }
    for (var i = 0; i < a.length; i++) { if (a[i] !== b[i]) { return false; } }
    return true;
  }

  // Little-endian integer of a byte string, as arkworks stores field elements.
  function leToBig(b) {
    var v = 0n;
    for (var i = b.length - 1; i >= 0; i--) { v = (v << 8n) | BigInt(b[i]); }
    return v;
  }

  function bigToLe(v, n) {
    var out = new Uint8Array(n);
    for (var i = 0; i < n; i++) { out[i] = Number(v & 255n); v >>= 8n; }
    return out;
  }

  function u64le(b) { return leToBig(b.subarray(0, 8)); }

  /* ------------------------------------------------- field arithmetic mod r */

  function fadd(a, b) { var r = a + b; return r >= P ? r - P : r; }
  function fsub(a, b) { var r = a - b; return r < 0n ? r + P : r; }
  function fmul(a, b) { return (a * b) % P; }
  function fneg(a) { return a === 0n ? 0n : P - a; }

  function fpow(a, e) {
    var r = 1n;
    a %= P;
    while (e > 0n) {
      if (e & 1n) { r = fmul(r, a); }
      a = fmul(a, a);
      e >>= 1n;
    }
    return r;
  }

  function finv(a) {
    if (a === 0n) { throw new Error("inverse of zero"); }
    return fpow(a, P - 2n);
  }

  // Tonelli-Shanks. r - 1 = 2^32 * odd, so the plain exponent trick does not
  // apply. Returns null when n is not a square.
  function fsqrt(n) {
    if (n === 0n) { return 0n; }
    if (fpow(n, (P - 1n) / 2n) !== 1n) { return null; }
    var m = SQRT.s, c = SQRT.z, t = fpow(n, SQRT.q), r = fpow(n, (SQRT.q + 1n) / 2n);
    while (t !== 1n) {
      var i = 0, tt = t;
      while (tt !== 1n) { tt = fmul(tt, tt); i++; }
      var b = c;
      for (var k = 0; k < m - i - 1; k++) { b = fmul(b, b); }
      m = i; c = fmul(b, b); t = fmul(t, c); r = fmul(r, b);
    }
    return r;
  }

  // Canonical 32-byte little-endian field element, rejected when >= r.
  function frFromBytes(b) {
    if (b.length !== 32) { return null; }
    var v = leToBig(b);
    return v < P ? v : null;
  }

  function frToBytes(x) { return bigToLe(x, 32); }

  /* --------------------------------------------------------------- Poseidon */

  // ark-crypto-primitives 0.5 PoseidonSponge: state [capacity | rate], inputs
  // are added into the rate slots, the permutation runs lazily when the rate
  // is full, and one final permutation precedes the single squeeze.
  function permute(st) {
    var rf = C.full_rounds / 2, t = st.length, r, i, j;
    for (r = 0; r < C.full_rounds + C.partial_rounds; r++) {
      var full = r < rf || r >= rf + C.partial_rounds;
      for (i = 0; i < t; i++) { st[i] = fadd(st[i], ROUNDS.ark[r][i]); }
      for (i = 0; i < (full ? t : 1); i++) {
        var x2 = fmul(st[i], st[i]);
        st[i] = fmul(fmul(x2, x2), st[i]);
      }
      var next = [];
      for (i = 0; i < t; i++) {
        var acc = 0n;
        for (j = 0; j < t; j++) { acc = fadd(acc, fmul(ROUNDS.mds[i][j], st[j])); }
        next.push(acc);
      }
      for (i = 0; i < t; i++) { st[i] = next[i]; }
    }
  }

  function poseidon(tag, inputs) {
    var st = [], i, idx = 0;
    for (i = 0; i < C.rate + C.capacity; i++) { st.push(0n); }
    var elems = [BigInt(tag)].concat(inputs);
    for (i = 0; i < elems.length; i++) {
      if (idx === C.rate) { permute(st); idx = 0; }
      st[C.capacity + idx] = fadd(st[C.capacity + idx], elems[i]);
      idx++;
    }
    permute(st);
    return st[C.capacity];
  }

  // poseidon::hash_bytes: length first, then 31-byte little-endian chunks.
  function poseidonBytes(tag, bytes) {
    var elems = [BigInt(bytes.length)];
    for (var i = 0; i < bytes.length; i += 31) { elems.push(leToBig(bytes.subarray(i, i + 31))); }
    return poseidon(tag, elems);
  }

  /* ------------------------------------------------------------------ Jubjub */

  // Twisted Edwards a x^2 + y^2 = 1 + d x^2 y^2 in extended coordinates
  // (Hisil, Wong, Carter, Dawson 2008), so no inversion until toAffine.
  function ptIdentity() { return { X: 0n, Y: 1n, Z: 1n, T: 0n }; }
  function ptFromAffine(p) { return { X: p.x, Y: p.y, Z: 1n, T: fmul(p.x, p.y) }; }

  function ptAdd(p, q) {
    var A = fmul(p.X, q.X), B = fmul(p.Y, q.Y), Cc = fmul(fmul(p.T, CURVE.d), q.T), D = fmul(p.Z, q.Z);
    var E = fsub(fsub(fmul(fadd(p.X, p.Y), fadd(q.X, q.Y)), A), B);
    var F = fsub(D, Cc), G = fadd(D, Cc), H = fsub(B, fmul(CURVE.a, A));
    return { X: fmul(E, F), Y: fmul(G, H), Z: fmul(F, G), T: fmul(E, H) };
  }

  function ptDouble(p) {
    var A = fmul(p.X, p.X), B = fmul(p.Y, p.Y), Cc = fmul(2n, fmul(p.Z, p.Z)), D = fmul(CURVE.a, A);
    var E = fsub(fsub(fmul(fadd(p.X, p.Y), fadd(p.X, p.Y)), A), B);
    var G = fadd(D, B), F = fsub(G, Cc), H = fsub(D, B);
    return { X: fmul(E, F), Y: fmul(G, H), Z: fmul(F, G), T: fmul(E, H) };
  }

  function ptMul(k, affine) {
    var r = ptIdentity(), p = ptFromAffine(affine);
    for (var i = k.toString(2).length - 1; i >= 0; i--) {
      r = ptDouble(r);
      if ((k >> BigInt(i)) & 1n) { r = ptAdd(r, p); }
    }
    return r;
  }

  function toAffine(p) {
    var zi = finv(p.Z);
    return { x: fmul(p.X, zi), y: fmul(p.Y, zi) };
  }

  function mul(affine, k) { return toAffine(ptMul(k, affine)); }
  function ptEqual(p, q) { return p.x === q.x && p.y === q.y; }

  function onCurve(p) {
    var x2 = fmul(p.x, p.x), y2 = fmul(p.y, p.y);
    return fadd(fmul(CURVE.a, x2), y2) === fadd(1n, fmul(fmul(CURVE.d, x2), y2));
  }

  // Both x for a y, ordered (smaller, larger) as ark-ec get_xs_from_y does.
  function xsFromY(y) {
    var y2 = fmul(y, y), den = fsub(CURVE.a, fmul(y2, CURVE.d));
    if (den === 0n) { return null; }
    var x = fsqrt(fmul(fsub(1n, y2), finv(den)));
    if (x === null) { return null; }
    var nx = fneg(x);
    return x <= nx ? [x, nx] : [nx, x];
  }

  // arkworks compressed encoding: y little-endian in 32 bytes, top bit of the
  // last byte set when x is the larger of the pair (x > -x).
  function decodePoint(b) {
    if (b.length !== 32) { return null; }
    var y = leToBig(b) & ((1n << 255n) - 1n);
    if (y >= P) { return null; }
    var xs = xsFromY(y);
    if (xs === null) { return null; }
    var p = { x: xs[b[31] >> 7], y: y };
    if (!onCurve(p)) { return null; }
    var o = toAffine(ptMul(CURVE.order, p));
    return o.x === 0n && o.y === 1n ? p : null;
  }

  function encodePoint(p) {
    var out = frToBytes(p.y);
    if (p.x > fneg(p.x)) { out[31] |= 0x80; }
    return out;
  }

  /* ------------------------------------------------- keys and diversifiers */

  // Low SCALAR_BITS bits of a field element, used as a Jubjub scalar.
  function scalarFromField(x) { return x & ((1n << BigInt(C.scalar_bits)) - 1n); }

  function skView(vkIn) { return scalarFromField(poseidon(TAG.SK_VIEW, [vkIn])); }

  // DiversifyHash(d): y = Poseidon(DIVERSIFY, d) + k for the first k where
  // (y^2 - 1)(d y^2 + 1) is a square; the even x; cofactor 8 cleared.
  function diversifyHash(d) {
    var h = poseidon(TAG.DIVERSIFY, [leToBig(d)]);
    for (var k = 0; k < C.div_hash_tries; k++) {
      var y = fadd(h, BigInt(k)), y2 = fmul(y, y);
      var den = fadd(fmul(CURVE.d, y2), 1n);
      var root = fsqrt(fmul(fsub(y2, 1n), den));
      if (root === null) { continue; }
      var x = fmul(root, finv(den));
      if (x & 1n) { x = fneg(x); }
      var p = ptFromAffine({ x: x, y: y });
      return toAffine(ptDouble(ptDouble(ptDouble(p))));
    }
    return null;
  }

  function addressString(d, pkD) { return "sbp1" + bytesToHex(d) + bytesToHex(encodePoint(pkD)); }

  /* ---------------------------------------------------------- note cipher */

  function noteKey(shared, pkEph) { return poseidon(TAG.KDF, [shared.x, shared.y, pkEph.x, pkEph.y]); }

  // Poseidon stream cipher plus Poseidon MAC, then the paper's 16.1 check
  // that pk_eph really is [sk_eph(r_seed)] G_d.
  function decryptWithKey(key, ct, pkEph) {
    if (poseidon(TAG.MAC, [key, ct.c0, ct.c1]) !== ct.tag) { return null; }
    var m0 = fsub(ct.c0, poseidon(TAG.STREAM, [key, 0n]));
    var m1 = fsub(ct.c1, poseidon(TAG.STREAM, [key, 1n]));
    if (m0 >> BigInt(8 * (8 + C.diversifier_len))) { return null; }
    var packed = bigToLe(m0, 8 + C.diversifier_len);
    var d = packed.subarray(8), gd = diversifyHash(d);
    if (gd === null) { return null; }
    var skEph = scalarFromField(poseidon(TAG.EPH, [m1]));
    if (!ptEqual(mul(gd, skEph), pkEph)) { return null; }
    return { v: u64le(packed), d: d, rSeed: m1 };
  }

  function decryptAsRecipient(env, vkInHex) {
    var sv = skView(frFromBytesStrict(vkInHex)), notes = [], j;
    if (env.kind === "mint") {
      var gd = diversifyHash(env.d);
      if (gd !== null && ptEqual(mul(gd, sv), env.pkD)) {
        notes.push({ j: 0, v: null, d: env.d, rSeed: env.rSeed });
      }
      return notes;
    }
    for (j = 0; j < env.pkEph.length; j++) {
      var n = decryptWithKey(noteKey(mul(env.pkEph[j], sv), env.pkEph[j]), env.ct[j], env.pkEph[j]);
      if (n !== null) { n.j = j; notes.push(n); }
    }
    return notes;
  }

  function frFromBytesStrict(hex) {
    var x = frFromBytes(hexToBytes(hex));
    if (x === null) { throw new Error("not a canonical field element"); }
    return x;
  }

  /* ------------------------------------- sender recovery: ct_out (16.2) */

  var subtle = (root.crypto || {}).subtle;

  function hkdf(ikm, salt, info, n) {
    return subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]).then(function (k) {
      return subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: salt, info: info }, k, n * 8);
    }).then(function (bits) { return new Uint8Array(bits); });
  }

  function ascii(s) {
    var out = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) { out[i] = s.charCodeAt(i); }
    return out;
  }

  // RFC 8439 ChaCha20 block function.
  function chachaBlock(key, nonce, counter) {
    var s = new Uint32Array(16), x = new Uint32Array(16), i;
    s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
    var kv = new DataView(key.buffer, key.byteOffset), nv = new DataView(nonce.buffer, nonce.byteOffset);
    for (i = 0; i < 8; i++) { s[4 + i] = kv.getUint32(4 * i, true); }
    s[12] = counter;
    for (i = 0; i < 3; i++) { s[13 + i] = nv.getUint32(4 * i, true); }
    x.set(s);
    function rotl(v, n) { return ((v << n) | (v >>> (32 - n))) >>> 0; }
    function qr(a, b, c, d) {
      x[a] = (x[a] + x[b]) >>> 0; x[d] = rotl(x[d] ^ x[a], 16);
      x[c] = (x[c] + x[d]) >>> 0; x[b] = rotl(x[b] ^ x[c], 12);
      x[a] = (x[a] + x[b]) >>> 0; x[d] = rotl(x[d] ^ x[a], 8);
      x[c] = (x[c] + x[d]) >>> 0; x[b] = rotl(x[b] ^ x[c], 7);
    }
    for (i = 0; i < 10; i++) {
      qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15);
      qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14);
    }
    var out = new Uint8Array(64), ov = new DataView(out.buffer);
    for (i = 0; i < 16; i++) { ov.setUint32(4 * i, (x[i] + s[i]) >>> 0, true); }
    return out;
  }

  function chacha20(key, nonce, counter, data) {
    var out = new Uint8Array(data.length);
    for (var i = 0; i < data.length; i += 64) {
      var ks = chachaBlock(key, nonce, counter + i / 64);
      for (var j = 0; j < 64 && i + j < data.length; j++) { out[i + j] = data[i + j] ^ ks[j]; }
    }
    return out;
  }

  function poly1305(key, msg) {
    var r = leToBig(key.subarray(0, 16)) & 0x0ffffffc0ffffffc0ffffffc0fffffffn;
    var s = leToBig(key.subarray(16, 32)), p = (1n << 130n) - 5n, acc = 0n;
    for (var i = 0; i < msg.length; i += 16) {
      var block = msg.subarray(i, Math.min(i + 16, msg.length));
      acc = ((acc + leToBig(block) + (1n << BigInt(8 * block.length))) * r) % p;
    }
    return bigToLe((acc + s) & ((1n << 128n) - 1n), 16);
  }

  function pad16(b) { return new Uint8Array((16 - b.length % 16) % 16); }

  // ChaCha20-Poly1305 open (RFC 8439 section 2.8). Null on a bad tag.
  function aeadOpen(key, nonce, aad, ctAndTag) {
    if (ctAndTag.length < 16) { return null; }
    var ct = ctAndTag.subarray(0, ctAndTag.length - 16), tag = ctAndTag.subarray(ctAndTag.length - 16);
    var polyKey = chachaBlock(key, nonce, 0).subarray(0, 32);
    var mac = poly1305(polyKey, concat([aad, pad16(aad), ct, pad16(ct),
      bigToLe(BigInt(aad.length), 8), bigToLe(BigInt(ct.length), 8)]));
    return equal(mac, tag) ? chacha20(key, nonce, 1, ct) : null;
  }

  // Sender side: ct_out holds (pk_d, sk_eph) per output under ChaCha20-Poly1305,
  // keyed by HKDF(salt = binding, ikm = vk_out). The binding is the SHA-256 of
  // the fixed output data and is also the associated data. The wallet in the
  // crate additionally requires one nullifier to be its own, which needs sk_nf;
  // here the AEAD tag under vk_out is the whole test.
  function decryptAsSender(env, vkOutHex) {
    if (env.kind !== "transfer") { return Promise.resolve([]); }
    var vkOut = hexToBytes(vkOutHex), parts = [new Uint8Array([env.pkEph.length])], j;
    for (j = 0; j < env.pkEph.length; j++) { parts.push(encodePoint(env.pkEph[j])); }
    for (j = 0; j < env.ct.length; j++) { parts.push(ctToBytes(env.ct[j])); }
    var binding;
    return subtle.digest("SHA-256", concat(parts)).then(function (h) {
      binding = new Uint8Array(h);
      return Promise.all([hkdf(vkOut, binding, ascii("sbp/ctout/key"), 32),
        hkdf(vkOut, binding, ascii("sbp/ctout/nonce"), 12)]);
    }).then(function (kn) {
      var pt = aeadOpen(kn[0], kn[1], binding, env.ctOut), notes = [];
      if (pt === null || pt.length % 64 !== 0) { return notes; }
      for (j = 0; j < env.pkEph.length && 64 * j < pt.length; j++) {
        var pkD = decodePoint(pt.subarray(64 * j, 64 * j + 32));
        if (pkD === null) { continue; }
        var skEph = leToBig(pt.subarray(64 * j + 32, 64 * j + 64)) % CURVE.order;
        var n = decryptWithKey(noteKey(mul(pkD, skEph), env.pkEph[j]), env.ct[j], env.pkEph[j]);
        if (n !== null) { n.j = j; n.to = addressString(n.d, pkD); notes.push(n); }
      }
      return notes;
    });
  }

  /* --------------------------------------------------------------- envelope */

  function Reader(bytes) { this.b = bytes; this.i = 0; }
  Reader.prototype.take = function (n) {
    if (this.i + n > this.b.length) { throw new Error("envelope truncated"); }
    var out = this.b.subarray(this.i, this.i + n);
    this.i += n;
    return out;
  };
  Reader.prototype.u8 = function () { return this.take(1)[0]; };

  // Minimal CompactSize (A.5), as envelope::Reader::compact_size: one byte
  // below 253, 0xfd + u16, 0xfe + u32; a wider form than needed is rejected
  // and 0xff never occurs in an envelope.
  Reader.prototype.compactSize = function () {
    var first = this.u8(), n, min;
    if (first === 0xff) { throw new Error("non-minimal CompactSize"); }
    if (first === 0xfe) { n = Number(leToBig(this.take(4))); min = 0x10000; }
    else if (first === 0xfd) { n = Number(leToBig(this.take(2))); min = 253; }
    else { n = first; min = 0; }
    if (n < min) { throw new Error("non-minimal CompactSize"); }
    return n;
  };

  function compactSize(n) {
    if (n <= 252) { return new Uint8Array([n]); }
    if (n <= 0xffff) { return concat([new Uint8Array([0xfd]), bigToLe(BigInt(n), 2)]); }
    return concat([new Uint8Array([0xfe]), bigToLe(BigInt(n), 4)]);
  }

  function ctFromBytes(b) {
    var c0 = frFromBytes(b.subarray(0, 32)), c1 = frFromBytes(b.subarray(32, 64)), t = frFromBytes(b.subarray(64));
    if (c0 === null || c1 === null || t === null) { throw new Error("bad ciphertext"); }
    return { c0: c0, c1: c1, tag: t };
  }

  function ctToBytes(ct) { return concat([frToBytes(ct.c0), frToBytes(ct.c1), frToBytes(ct.tag)]); }

  function header(kind) { return concat([C.magic, new Uint8Array([C.version, kind, 0])]); }

  // Canonical body, everything but the proof: what h_body covers.
  function transferBody(t) {
    var parts = [header(C.kind_transfer), bigToLe(BigInt(t.hAnchor), 4), compactSize(t.nf.length), compactSize(t.pkEph.length)], i;
    for (i = 0; i < t.nf.length; i++) { parts.push(frToBytes(t.nf[i])); }
    for (i = 0; i < t.pkEph.length; i++) { parts.push(encodePoint(t.pkEph[i])); }
    for (i = 0; i < t.ct.length; i++) { parts.push(ctToBytes(t.ct[i])); }
    parts.push(t.ctOut);
    if (t.payout === null) {
      parts.push(new Uint8Array([0]));
    } else {
      parts.push(compactSize(8 + t.payout.scriptPubkey.length), bigToLe(t.payout.amount, 8), t.payout.scriptPubkey);
    }
    return concat(parts);
  }

  // Strict parse as envelope::Envelope::parse: null when the magic is absent,
  // an Error when the bytes claim to be an envelope and are not canonical.
  function parseEnvelope(bytes) {
    if (bytes.length < 6 || !equal(bytes.subarray(0, 3), C.magic)) { return null; }
    if (bytes[3] !== C.version) { throw new Error("unknown version " + bytes[3]); }
    if (bytes[5] !== 0) { throw new Error("reserved header byte set"); }
    var r = new Reader(bytes), env, i;
    r.take(6);
    if (bytes[4] === C.kind_transfer) {
      env = { kind: "transfer", hAnchor: Number(leToBig(r.take(4))), nf: [], pkEph: [], ct: [] };
      if (r.compactSize() !== C.n_in) { throw new Error("unsupported input count"); }
      if (r.compactSize() !== C.n_out) { throw new Error("unsupported output count"); }
      for (i = 0; i < C.n_in; i++) {
        var nf = frFromBytes(r.take(32));
        if (nf === null) { throw new Error("non-canonical nullifier"); }
        env.nf.push(nf);
      }
      for (i = 0; i < C.n_out; i++) {
        var pk = decodePoint(r.take(32));
        if (pk === null) { throw new Error("bad pk_eph"); }
        env.pkEph.push(pk);
      }
      for (i = 0; i < C.n_out; i++) { env.ct.push(ctFromBytes(r.take(C.ciphertext_len))); }
      env.ctOut = r.take(C.ct_out_len);
      var plen = r.compactSize();
      env.payout = null;
      if (plen !== 0) {
        if (plen <= 8) { throw new Error("payout too short"); }
        env.payout = { amount: u64le(r.take(8)), scriptPubkey: r.take(plen - 8) };
      }
      env.proof = r.take(C.proof_len);
      env.body = transferBody(env);
    } else if (bytes[4] === C.kind_mint) {
      env = { kind: "mint", d: r.take(C.diversifier_len) };
      env.pkD = decodePoint(r.take(32));
      if (env.pkD === null) { throw new Error("bad pk_d"); }
      env.rSeed = frFromBytes(r.take(32));
      if (env.rSeed === null) { throw new Error("non-canonical r_seed"); }
      env.body = concat([header(C.kind_mint), env.d, encodePoint(env.pkD), frToBytes(env.rSeed)]);
    } else {
      throw new Error("unknown envelope kind " + bytes[4]);
    }
    if (r.i !== bytes.length) { throw new Error("trailing bytes after envelope"); }
    var again = env.kind === "transfer" ? concat([env.body, env.proof]) : env.body;
    if (!equal(again, bytes)) { throw new Error("non-canonical envelope encoding"); }
    env.bytes = bytes;
    return env;
  }

  // H_body(const_salt || canonical body), section 13.3, as envelope::h_body:
  // the 16 salt bytes are prefixed before the length-prefixed 31-byte chunking.
  function hBody(env) { return poseidonBytes(TAG.BODY, concat([C.const_salt, env.body])); }

  // H_leaf(const_salt, h_body, j, pk_eph, ct_note, h_aux) of section 9, as
  // note::leaf: const_salt read as a little-endian field element, h_aux = aux_null.
  function leaf(hb, j, pkEph, ct) {
    return poseidon(TAG.LEAF, [leToBig(C.const_salt), hb, BigInt(j), pkEph.x, pkEph.y, ct.c0, ct.c1, ct.tag, C.aux_null]);
  }

  function mintLeaf(v, d, pkD, rSeed) {
    return poseidon(TAG.MINT_LEAF, [BigInt(v), leToBig(d), pkD.x, pkD.y, rSeed]);
  }

  /* --------------------------------------------------- carrier transactions */

  Reader.prototype.varint = function () {
    var n = this.u8();
    if (n < 0xfd) { return n; }
    return Number(leToBig(this.take(n === 0xfd ? 2 : n === 0xfe ? 4 : 8)));
  };

  function parseTx(hex) {
    var r = new Reader(hexToBytes(hex));
    var version = r.take(4), segwit = false, nIn = r.varint(), vin = [], vout = [], i, j;
    if (nIn === 0) {
      if (r.u8() !== 1) { throw new Error("unknown segwit flag"); }
      segwit = true;
      nIn = r.varint();
    }
    for (i = 0; i < nIn; i++) { vin.push({ prevout: r.take(36), script: r.take(r.varint()), sequence: r.take(4) }); }
    var nOut = r.varint();
    for (i = 0; i < nOut; i++) { vout.push({ value: u64le(r.take(8)), script: r.take(r.varint()) }); }
    if (segwit) {
      for (i = 0; i < nIn; i++) { var items = r.varint(); for (j = 0; j < items; j++) { r.take(r.varint()); } }
    }
    var locktime = r.take(4);
    if (r.i !== r.b.length) { throw new Error("trailing bytes after the transaction"); }
    return { version: version, vin: vin, vout: vout, locktime: locktime };
  }

  // Pushes of an OP_RETURN script after the opcode, each flagged for minimal
  // encoding the way rust-bitcoin's instructions_minimal judges it.
  function pushes(s) {
    var out = [], i = 1;
    while (i < s.length) {
      var op = s[i], n, minimal = true;
      i += 1;
      if (op > 0x4e) { out.push({ data: null, minimal: true }); continue; }
      if (op < 0x4c) { n = op; }
      else if (op === 0x4c) { n = s[i]; i += 1; minimal = n >= 0x4c; }
      else if (op === 0x4d) { n = s[i] | (s[i + 1] << 8); i += 2; minimal = n > 0xff; }
      else { n = s[i] | (s[i + 1] << 8) | (s[i + 2] << 16) | (s[i + 3] * 16777216); i += 4; minimal = n > 0xffff; }
      if (i + n > s.length) { throw new Error("truncated push in a script"); }
      var data = s.subarray(i, i + n);
      if (n === 1 && (data[0] === 0x81 || (data[0] >= 1 && data[0] <= 16))) { minimal = false; }
      out.push({ data: data, minimal: minimal });
      i += n;
    }
    return out;
  }

  // chain::op_return_payload: exactly one OP_RETURN output with one minimal
  // push. Anything else that starts with the magic is a fault, not a skip.
  function opReturnPayload(tx) {
    var outs = [], i;
    for (i = 0; i < tx.vout.length; i++) {
      var s = tx.vout[i].script;
      if (s.length > 0 && s[0] === 0x6a) { outs.push(s); }
    }
    var claims = false;
    for (i = 0; i < outs.length; i++) {
      var first = pushes(outs[i])[0];
      if (first && first.data && first.data.length >= 3 && equal(first.data.subarray(0, 3), C.magic)) { claims = true; }
    }
    function fault(why) { if (claims) { throw new Error(why); } return null; }
    if (outs.length === 0) { return null; }
    if (outs.length > 1) { return fault("more than one OP_RETURN output"); }
    var ps = pushes(outs[0]);
    if (ps.length === 0 || ps[0].data === null) { return fault("OP_RETURN without a push"); }
    if (!ps[0].minimal) { return fault("non-minimal push"); }
    if (ps.length > 1) { return fault("extra data after the envelope push"); }
    return ps[0].data;
  }

  var API_BASE = "https://signet.bitsaga.be/api";

  function fetchTx(txid) {
    return fetch(API_BASE + "/tx-proof?txid=" + encodeURIComponent(txid)).then(function (res) {
      if (!res.ok) { throw new Error("tx-proof " + res.status); }
      return res.json();
    }).then(function (j) { return { txid: txid, raw: j.tx, tx: parseTx(j.tx), height: j.height, proof: j }; });
  }

  /* ------------------------------------------------------- setup and test */

  function load(data) {
    P = BigInt(data.fr_modulus);
    var pz = data.poseidon;
    ROUNDS = {
      ark: pz.ark.map(function (r) { return r.map(BigInt); }),
      mds: pz.mds.map(function (r) { return r.map(BigInt); })
    };
    C = {
      full_rounds: pz.full_rounds, partial_rounds: pz.partial_rounds, rate: pz.rate, capacity: pz.capacity,
      scalar_bits: data.SCALAR_BITS, div_hash_tries: data.DIV_HASH_TRIES, diversifier_len: data.DIVERSIFIER_LEN,
      n_in: data.N_IN, n_out: data.N_OUT,
      magic: hexToBytes(data.envelope.magic), version: data.envelope.version,
      kind_transfer: data.envelope.kind_transfer, kind_mint: data.envelope.kind_mint,
      ciphertext_len: data.envelope.ciphertext_len, ct_out_len: data.envelope.ct_out_len,
      proof_len: data.envelope.proof_len,
      const_salt: hexToBytes(data.envelope.const_salt)
    };
    C.aux_null = frFromBytesStrict(data.envelope.aux_null);
    if (pz.alpha !== 5) { throw new Error("S-box is hardwired to x^5"); }
    TAG = data.tags;
    CURVE = { a: BigInt(data.jubjub.a), d: BigInt(data.jubjub.d), order: BigInt(data.jubjub.scalar_modulus) };
    var q = P - 1n, s = 0, z = 2n;
    while ((q & 1n) === 0n) { q >>= 1n; s++; }
    while (fpow(z, (P - 1n) / 2n) === 1n) { z++; }
    SQRT = { q: q, s: s, z: fpow(z, q) };
  }

  // Runs every exported vector: leaves against the indexer positions, every
  // wallet as recipient and as sender, mint ownership. Resolves to
  // {ok, checked, matched, failures}.
  function selfTest(data) {
    load(data);
    var fail = [], checked = 0, matched = 0, leaves = data.state.leaves, chain = Promise.resolve();
    function bad(msg) { fail.push(msg); }
    function want(txid, wallet, role) {
      return data.vectors.filter(function (v) { return v.txid === txid && v.wallet === wallet && v.role === role; });
    }
    function compare(label, got, exp) {
      got.forEach(function (n) {
        var e = exp.filter(function (v) { return v.j === n.j; })[0];
        checked++;
        if (!e) { return bad(label + ": decrypted output " + n.j + " that the crate did not"); }
        if ((n.v !== null && BigInt(e.v) !== n.v) || bytesToHex(n.d) !== e.d || bytesToHex(frToBytes(n.rSeed)) !== e.r_seed ||
            (n.to !== undefined && n.to !== e.to)) { return bad(label + " output " + n.j + ": note fields differ"); }
        matched++;
      });
      if (got.length !== exp.length) { bad(label + ": " + got.length + " notes, crate has " + exp.length); }
    }
    data.state.events.forEach(function (ev) {
      var env;
      try { env = parseEnvelope(hexToBytes(ev.envelope)); } catch (e) { return bad(ev.txid + ": " + e.message); }
      if (env === null || env.kind !== ev.kind) { return bad(ev.txid + ": kind"); }
      if (ev.kind === "transfer") {
        var hb = hBody(env);
        env.pkEph.forEach(function (pk, j) {
          checked++;
          if (bytesToHex(frToBytes(leaf(hb, j, pk, env.ct[j]))) !== leaves[ev.positions[j]]) { bad(ev.txid + ": leaf " + j); }
        });
      }
      data.wallets.forEach(function (w) {
        var label = ev.txid.slice(0, 8) + " " + w.name;
        if (ev.kind === "mint") {
          var got = decryptAsRecipient(env, w.vk_in), exp = want(ev.txid, w.name, "mint");
          compare(label + " mint", got, exp);
          if (got.length) {
            checked++;
            var l = bytesToHex(frToBytes(mintLeaf(BigInt(ev.value), env.d, env.pkD, env.rSeed)));
            if (l !== leaves[ev.positions[0]] || l !== exp[0].leaf) { bad(label + ": mint leaf"); }
          }
          return;
        }
        compare(label + " recipient", decryptAsRecipient(env, w.vk_in), want(ev.txid, w.name, "recipient"));
        chain = chain.then(function () { return decryptAsSender(env, w.vk_out); }).then(function (got) {
          compare(label + " sender", got, want(ev.txid, w.name, "sender"));
        });
      });
    });
    return chain.then(function () {
      if (matched !== data.vectors.length) { bad("matched " + matched + " of " + data.vectors.length + " vectors"); }
      return { ok: fail.length === 0, checked: checked, matched: matched, vectors: data.vectors.length, failures: fail };
    });
  }

  var API = {
    load: load,
    parseTx: parseTx,
    opReturnPayload: opReturnPayload,
    parseEnvelope: parseEnvelope,
    decryptAsRecipient: decryptAsRecipient,
    decryptAsSender: decryptAsSender,
    leaf: leaf,
    mintLeaf: mintLeaf,
    hBody: hBody,
    fetchTx: fetchTx,
    selfTest: selfTest,
    diversifyHash: diversifyHash,
    addressString: addressString,
    frToHex: function (x) { return bytesToHex(frToBytes(x)); },
    pointToHex: function (p) { return bytesToHex(encodePoint(p)); },
    hexToBytes: hexToBytes,
    bytesToHex: bytesToHex,
    poseidon: poseidon
  };

  root.ShieldedVerify = API;
  if (typeof module !== "undefined" && module.exports) { module.exports = API; }
})(typeof window !== "undefined" ? window : globalThis);
