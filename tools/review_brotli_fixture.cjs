// First-party data-only review; require a separately reviewed patched runtime.
// Never loads the reviewed Rust crate, package hooks, plugins or target code.
'use strict';
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const {patchedRuntime} = require('./review_brotli_runtime.cjs');

function requirePatchedRuntime() {
  assert(patchedRuntime(process.versions),
    'Brotli review blocked: patched supported Node and Brotli runtime required (CVE-2026-111497)');
}

function decodeBounded(input, limit) {
  requirePatchedRuntime();
  assert(input.length > 0 && input.length <= 8192);
  assert(Number.isInteger(limit) && limit > 0 && limit <= 8192);
  const result = require('node:zlib').brotliDecompressSync(input, { info: true, maxOutputLength: limit });
  assert.equal(result.engine.bytesWritten, input.length, 'unconsumed Brotli tail');
  return result.buffer;
}

function review(compressed, plain) {
  const hash = data => crypto.createHash('sha256').update(data).digest('hex');
  assert.equal(compressed.length, 1752);
  assert.equal(hash(compressed), '74106184c7abce3075914e8147e664e6a0c6ee0184d8a4a585be557ad2f8aede');
  assert.equal(plain.length, 5018);
  assert.equal(hash(plain), 'dd598301a25441eeb17800b4d4f6b16a36942586479d57d71863c7173390b5c4');
  const decoded = decodeBounded(compressed, 8192);
  assert(decoded.equals(plain), 'decoded fixture differs from separate plaintext witness');
  return { compressed_bytes: compressed.length, compressed_sha256: hash(compressed),
    decoded_bytes: decoded.length, decoded_sha256: hash(decoded),
    input_fully_consumed: true, plaintext_witness_matches: true,
    target_executed: false, node: process.versions.node,
    bundled_brotli: process.versions.brotli };
}

function selfTest() {
  requirePatchedRuntime();
  const zlib = require('node:zlib');
  const data = Buffer.from('first-party synthetic data '.repeat(20));
  const encoded = zlib.brotliCompressSync(data);
  assert(decodeBounded(encoded, 8192).equals(data));
  assert.throws(() => decodeBounded(Buffer.concat([encoded, Buffer.from('tail')]), 8192));
  assert.throws(() => decodeBounded(encoded.subarray(0, encoded.length - 1), 8192));
  assert.throws(() => decodeBounded(encoded, 1));
  assert.throws(() => decodeBounded(Buffer.alloc(0), 8192));
  assert.throws(() => decodeBounded(Buffer.alloc(8193), 8192));
  assert.throws(() => decodeBounded(encoded, 8193));
  assert.throws(() => review(encoded, data));
  process.stdout.write(JSON.stringify({ synthetic_assertions: 8, target_executed: false }));
}

if (require.main === module) {
  // Stop before importing the decoder or reading any supplied compressed input.
  requirePatchedRuntime();
  if (process.argv.length === 3 && process.argv[2] === '--self-test') {
    selfTest();
  } else {
    assert.equal(process.argv.length, 2);
    // Read a bounded frame: two little-endian sizes, then compressed/plain data.
    const frame = Buffer.alloc(16393);
    let size = 0;
    while (size < frame.length) {
      const n = fs.readSync(0, frame, size, frame.length - size, null);
      if (n === 0) break;
      size += n;
    }
    assert(size >= 8 && size < frame.length, 'frame bounds');
    const a = frame.readUInt32LE(0), b = frame.readUInt32LE(4);
    assert(a <= 8192 && b <= 8192 && size === 8 + a + b, 'frame lengths');
    process.stdout.write(JSON.stringify(review(frame.subarray(8, 8 + a),
      frame.subarray(8 + a, size))));
  }
}
