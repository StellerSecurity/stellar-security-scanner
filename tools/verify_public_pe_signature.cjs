// First-party verification of public signature DATA with existing Node crypto.
// No private keys, Windows loader, trust-store changes or target code are used.
'use strict';
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const frame = Buffer.alloc(524289);
let size = 0;
while (size < frame.length) {
  const n = fs.readSync(0, frame, size, frame.length - size, null);
  if (!n) break;
  size += n;
}
assert(size > 0 && size < frame.length, 'public verification input budget');
const input = JSON.parse(frame.subarray(0, size).toString('utf8'));
function bytes(text, limit) {
  assert(typeof text === 'string' && text.length <= limit * 2);
  const data = Buffer.from(text, 'base64');
  assert(data.length > 0 && data.length <= limit && data.toString('base64') === text);
  return data;
}
assert(Array.isArray(input.certificates) && input.certificates.length <= 8);
const signer = new crypto.X509Certificate(bytes(input.signer_certificate, 65536));
const certificates = input.certificates.map(value => new crypto.X509Certificate(bytes(value, 65536)));
assert(certificates.some(cert => cert.fingerprint256 === signer.fingerprint256));
assert.equal(signer.publicKey.asymmetricKeyType, 'rsa');
const valid = crypto.verify('sha256', bytes(input.signed_attributes, 65536),
  { key: signer.publicKey, padding: crypto.constants.RSA_PKCS1_PADDING },
  bytes(input.signature, 8192));
assert(valid, 'CMS RSA signature value differs');
const links = [];
for (const cert of certificates) {
  for (const issuer of certificates) {
    if (cert.fingerprint256 !== issuer.fingerprint256 && cert.issuer === issuer.subject) {
      links.push({ certificate_sha256: cert.fingerprint256, issuer_sha256: issuer.fingerprint256,
        signature_valid: cert.verify(issuer.publicKey) });
    }
  }
}
assert(links.every(link => link.signature_valid), 'included certificate link differs');
process.stdout.write(JSON.stringify({ cms_signature_value_verified: valid,
  signer_subject: signer.subject, signer_issuer: signer.issuer,
  signer_certificate_sha256: signer.fingerprint256, signer_extended_key_usage: signer.keyUsage,
  signer_valid_from: signer.validFrom, signer_valid_to: signer.validTo,
  included_certificate_links: links, root_trust_verified: false,
  timestamp_verified: false, revocation_checked: false, native_code_cleared: false,
  target_executed: false, node: process.versions.node }));
