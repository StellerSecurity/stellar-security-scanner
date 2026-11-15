"""Exact fsevents code/data review evidence. Never load the native addon.

Requires independently obtained, bounded disassembly as TEXT and the pinned
upstream C source. A matching hash alone is not the review performed here.
"""
from collections import Counter
import hashlib
import json
import re
import review_macho_metadata as macho


def require(condition, message):
    if not condition:
        raise macho.Invalid(message)


def expected_strings(source):
    require(len(source) == 9354 and hashlib.sha256(source).hexdigest() ==
            '0c24deee96ba8879cd0ae759260c8507da9a556b7c5e2196cf36536e400bc5eb', 'source identity')
    text = source.decode('utf-8')
    values = {json.loads('"' + m.group(1) + '"')
              for m in re.finditer(r'"((?:[^"\\]|\\.)*)"', text)}
    values.add('fsevents.c')
    values.update(re.findall(r'\b(?:void|napi_value)\s+\*?(\w+)\(', text))
    for found in re.finditer(r'\bCHECK\(', text):
        pos = found.end()
        start = pos
        depth = 1
        quoted = False
        escaped = False
        while depth:
            require(pos < len(text), 'source CHECK bounds')
            c = text[pos]
            if quoted:
                if escaped:
                    escaped = False
                elif c == '\\':
                    escaped = True
                elif c == '"':
                    quoted = False
            elif c == '"':
                quoted = True
            elif c == '(':
                depth += 1
            elif c == ')':
                depth -= 1
            pos += 1
        values.add(re.sub(r'\s+', ' ', text[start:pos-1]).strip())
    constants = re.findall(r'\bCONSTANT\((\w+)\);', text)
    require(len(constants) == 24 and len(set(constants)) == 24, 'source constants')
    for name in constants:
        values.update([name,
                       'napi_create_int32(env, kFSEventStreamEventFlag%s, &value) == napi_ok' % name,
                       'napi_set_named_property(env, constants, "%s", value) == napi_ok' % name])
    return values


def instruction_rows(text, cpu):
    require(len(text.encode()) <= 512 * 1024 and '<unknown>' not in text, 'disassembly budget/unknown')
    result = []
    for line in text.splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s+([0-9a-f ]+)\t(\S+)(?:\s+(.*))?$', line)
        if not match:
            continue
        address, encoded, mnemonic, operands = match.groups()
        encoded = encoded.strip()
        if cpu == 0x100000c and re.fullmatch(r'[0-9a-f]{8}', encoded):
            data = int(encoded, 16).to_bytes(4, 'little')
        else:
            data = bytes.fromhex(encoded)
        require(0 < len(data) <= 16, 'decoded instruction width')
        result.append((int(address, 16), data, mnemonic, operands or ''))
    require(bool(result), 'no decoded instructions')
    return result


def review(data, source, disassembly, loader_metadata):
    require(len(data) == 163626 and hashlib.sha256(data).hexdigest() ==
            '40f2f51199e4f5fc46fa6b985fb3461bb63e6cd86c62bfa9bcee45ed4438d5fb',
            'exact native artifact required')
    strings = expected_strings(source)
    reports = []
    for offset, thin in macho.slices(data):
        meta = macho.inspect(thin)
        cpu = meta['cpu']
        require(cpu in (0x1000007, 0x100000c) and cpu in disassembly
                and cpu in loader_metadata, 'architecture coverage')
        require(not meta['initializers'] and meta['filetype'] == 8, 'unexpected initializer/image kind')
        require(set(meta['libraries']) == {
            '/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation',
            '/System/Library/Frameworks/CoreServices.framework/Versions/A/CoreServices',
            '/usr/lib/libc++.1.dylib', '/usr/lib/libSystem.B.dylib'}, 'unexpected dynamic library')
        rows = instruction_rows(disassembly[cpu], cpu)
        addresses = {row[0] for row in rows}
        require(len(addresses) == len(rows), 'duplicate instruction addresses')
        coverage = []
        for section in meta['sections']:
            if section['name'] == '__cstring':
                raw = thin[section['offset']:section['offset']+section['bytes']]
                actual = [s.decode('ascii') for s in raw.split(b'\0') if s]
                require(all(s in strings for s in actual), 'unexplained native string')
            if not section['attributes'] & 0x80000400:
                continue
            start, end = section['address'], section['address']+section['bytes']
            decoded = sorted(row for row in rows if start <= row[0] < end)
            cursor = start
            for address, encoded, mnemonic, operands in decoded:
                require(address == cursor and address+len(encoded) <= end, 'instruction coverage gap')
                at = section['offset'] + address-start
                require(thin[at:at+len(encoded)] == encoded, 'disassembly bytes differ')
                require(mnemonic not in ('syscall', 'sysenter', 'svc', 'smc', 'hvc', 'int'),
                        'unexpected direct system call')
                cursor += len(encoded)
            require(cursor == end, 'unconsumed executable section')
            coverage.append(dict(section=section['name'], bytes=section['bytes'],
                                 instructions=len(decoded), sha256=section['sha256']))
        direct = 0
        for address, encoded, mnemonic, operands in rows:
            branch = (mnemonic.startswith('j') or mnemonic in ('call', 'callq', 'b', 'bl',
                       'cbz', 'cbnz', 'tbz', 'tbnz') or mnemonic.startswith('b.'))
            if not branch or operands.lstrip().startswith('*'):
                continue
            match = re.search(r'\b0x([0-9a-f]+)', operands)
            if match:
                require(int(match.group(1), 16) in addresses, 'branch into noninstruction data')
                direct += 1
        names = {r['name'] for r in meta['code_symbols']}
        expected = {'_' + x for x in re.findall(r'\b(?:void|napi_value)\s+\*?(\w+)\(', source.decode())}
        generated = {'_node_api_module_get_api_version_v1', '_napi_register_module_v1'}
        cold = {n for n in names if re.fullmatch(r'_\w+\.cold\.\d+', n)}
        require(len(cold) == 74 and names == expected | generated | cold, 'unexpected code function set')
        blocks = re.split(r'(?m)^(?=[0-9a-f]+ <[^>]+>:$)', disassembly[cpu])
        cold_blocks = [b for b in blocks if re.match(r'^[0-9a-f]+ <_\w+\.cold\.\d+>:', b)]
        require(len(cold_blocks) == 74, 'assertion block coverage')
        for block in cold_blocks:
            calls_in_block = []
            for address, encoded, mnemonic, operands in instruction_rows(block, cpu):
                if mnemonic in ('callq', 'bl'):
                    target = re.search(r'\b0x([0-9a-f]+)', operands)
                    calls_in_block.append(meta['stubs'].get(int(target.group(1), 16)) if target else None)
            require(calls_in_block == ['___assert_rtn'], 'unexpected assertion side effect')
        constants = next(b for b in blocks if re.match(r'^[0-9a-f]+ <_Init_Constants>:', b))
        calls = Counter()
        for address, encoded, mnemonic, operands in instruction_rows(constants, cpu):
            if mnemonic in ('bl', 'callq'):
                target = re.search(r'\b0x([0-9a-f]+)', operands)
                if target and int(target.group(1), 16) in meta['stubs']:
                    calls[meta['stubs'][int(target.group(1), 16)]] += 1
        require(calls == Counter({'_napi_create_object': 1, '_napi_create_int32': 24,
                                  '_napi_set_named_property': 24}), 'constant initialization differs')
        loader = loader_metadata[cpu]
        require(len(loader) <= 64*1024 and loader.count('Bind table:\n') == 1
                and loader.count('Lazy bind table:\n') == 1, 'loader metadata framing')
        bindings = loader.split('Bind table:\n', 1)[1].split('Lazy bind table:\n', 1)[0]
        bound = []
        for line in bindings.splitlines():
            if not line.startswith('__'):
                continue
            fields = line.split()
            require(len(fields) == 7 and fields[3:5] == ['pointer', '0'], 'unsupported binding')
            bound.append(fields[-1])
        require(set(bound) == set(meta['imports']) and len(bound) == len(meta['imports']),
                'loader bindings differ from symbol imports')
        reports.append(dict(cpu=cpu, offset=offset, bytes=len(thin), sha256=hashlib.sha256(thin).hexdigest(),
                            executable_sections=coverage, function_symbols=len(names),
                            cold_assertion_functions=len(cold), direct_branches=direct,
                            imports=meta['imports'], libraries=meta['libraries'],
                            loader_metadata_sha256=hashlib.sha256(loader.encode()).hexdigest(),
                            disassembly_sha256=hashlib.sha256(disassembly[cpu].encode()).hexdigest(),
                            unexplained_strings=0, initializers=meta['initializers']))
    require(len(reports) == 2, 'both architecture slices required')
    return reports
