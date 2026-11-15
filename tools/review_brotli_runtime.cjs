'use strict';

// A vulnerability floor, never package/execution approval or future safety proof.
// CVE-2026-111497: https://nodejs.org/en/blog/vulnerability/october-2026-security-releases
// Also require the current November fixes, not only the older Brotli fix.
// https://nodejs.org/en/blog/vulnerability/november-2026-security-releases
function patchedRuntime(versions) {
  function parse(value) {
    if (typeof value !== 'string' || !/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(value)) return null;
    const numbers = value.split('.').map(Number);
    return numbers.every(Number.isSafeInteger) ? numbers : null;
  }
  if (!versions || typeof versions !== 'object') return false;
  const node = parse(versions.node), brotli = parse(versions.brotli);
  if (!node || !brotli) return false;
  const floor = {22: [23, 5], 24: [22, 3], 26: [13, 1]}[node[0]];
  if (!floor || node[1] < floor[0] || (node[1] === floor[0] && node[2] < floor[1])) return false;
  const patch = {0: 10, 1: 1, 2: 1}[brotli[1]];
  return brotli[0] === 1 && patch !== undefined && brotli[2] >= patch;
}

module.exports = {patchedRuntime};
