#!/usr/bin/env python3
"""Refresh reviewed source bytes and integrity pins in the commit workflow.

No payload is executed. Review readable modules before running this tool; run
all scanner tests afterwards. The workflow's names and permissions stay intact.
"""
import ast
import base64
import hashlib
import json
from pathlib import Path
import re
import zlib

ROOT = Path(__file__).resolve().parents[1]

def sha(data): return hashlib.sha256(data).hexdigest()

def main():
    path = ROOT / '.github/workflows/commit-check.yml'
    text = path.read_text()
    matches = re.findall(r'          data = \(\n(.*?)          \)\n', text, re.S)
    old_encoded = ''.join(ast.literal_eval('(' + part + ')') for part in matches).encode()
    old_packed = base64.b64decode(old_encoded, validate=True)
    old_raw = zlib.decompress(old_packed)
    bundle = json.loads(old_raw)
    manifest_path = ROOT / 'scanner-manifest.json'
    manifest = json.loads(manifest_path.read_text())
    expected = set(manifest['module_sha256']) | {'source_guard.py'}
    if set(bundle) != expected:
        raise SystemExit('Unexpected embedded module inventory')
    for name, previous in bundle.items():
        source = (ROOT / 'scanner' / name).read_bytes()
        pin = sha(source)
        text = text.replace(previous['sha256'], pin)
        bundle[name] = {'base64':base64.b64encode(source).decode(), 'sha256':pin}
        manifest['exported_module_sha256']['scanner/' + name] = pin
        if name in manifest['module_sha256']:
            manifest['module_sha256'][name] = pin
    raw = json.dumps(bundle, sort_keys=True, separators=(',',':')).encode()
    packed = zlib.compress(raw, 9)
    encoded = base64.b64encode(packed).decode()
    chunks = [encoded[i:i+12000] for i in range(0,len(encoded),12000)]
    pattern = r'      - name: Stage reviewed scanner data chunk \d+\n.*?(?=      - name:)'
    templates = re.findall(pattern, text, re.S)
    if len(templates) != len(matches) or len(templates) < 2:
        raise SystemExit('Unexpected chunk step layout')
    replacement = []
    for i, chunk in enumerate(chunks):
        step = templates[0 if i == 0 else 1]
        step = re.sub(r'Stage reviewed scanner data chunk \d+', 'Stage reviewed scanner data chunk '+str(i+1), step)
        step = re.sub(r'chunk-\d{3}', 'chunk-%03d' % i, step)
        lines = ''.join('              '+repr(chunk[j:j+100])+'\n' for j in range(0,len(chunk),100))
        step = re.sub(r'(          data = \(\n).*?(          \)\n)', lambda m:m[1]+lines+m[2], step, flags=re.S)
        replacement.append(step)
    first = text.index(templates[0])
    end = text.index(templates[-1]) + len(templates[-1])
    text = text[:first] + ''.join(replacement) + text[end:]
    changes = {
        'for index in range('+str(len(matches))+'):':'for index in range('+str(len(chunks))+'):',
        'len(encoded) != '+str(len(old_encoded)):'len(encoded) != '+str(len(encoded)),
        'inflater.decompress(packed, '+str(len(old_raw)+1)+')':'inflater.decompress(packed, '+str(len(raw)+1)+')',
        'len(raw) != '+str(len(old_raw)):'len(raw) != '+str(len(raw)),
        sha(old_packed):sha(packed), sha(old_raw):sha(raw),
    }
    for old,new in changes.items():
        if text.count(old) != 1:
            raise SystemExit('Unexpected integrity guard count for '+old)
        text = text.replace(old,new)
    path.write_text(text)
    workflow_sha = sha(text.encode())
    manifest['workflow_sha256'] = workflow_sha
    manifest['workflow_sha256_by_path']['.github/workflows/commit-check.yml'] = workflow_sha
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True)+'\n')
    print('Refreshed',len(bundle),'modules;',len(chunks),'chunks; SHA-256',workflow_sha)

if __name__ == '__main__': main()
