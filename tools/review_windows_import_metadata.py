"""Strict static reader for the remaining LLVM/MSVC import metadata forms.

Evidence tooling only. This file does not grant any runtime scanner clearance.
No target code is loaded, linked, extracted or executed.
"""
import struct
import re
from collections import Counter


class Invalid(ValueError):
    pass


def need(ok, why):
    if not ok:
        raise Invalid(why)


def ascii_name(b, special=False):
    if special and b.startswith(b'\x7f'):
        need(re.fullmatch(b'\\x7f[A-Za-z0-9_.-]+_NULL_THUNK_DATA', b), 'special symbol')
        return b.decode('ascii')
    need(bool(b) and all((32 <= c < 127 for c in b)), 'ASCII name')
    return b.decode('ascii')


def dll_name(b):
    s = ascii_name(b)
    need(re.fullmatch('[A-Za-z0-9_.-]+\\.(?:dll|drv|cpl)', s, re.I), 'DLL basename')
    return s


def short_import(b, machine):
    need(len(b) >= 20, 'short import size')
    (sig0, sig1, version, mach, stamp, size, hint, flags) = struct.unpack_from('<HHHHIIHH', b)
    need((sig0, sig1, version, mach, stamp) == (0, 0xffff, 0, machine, 0), 'short import header')
    need(size == len(b) - 20 and flags in (4, 8, 12), 'short import data/flags')
    strings = b[20:].split(b'\x00')
    need(len(strings) == 3 and strings[-1] == b'', 'short import strings/tail')
    symbol = ascii_name(strings[0])
    dll = dll_name(strings[1])
    kind = flags >> 2
    if kind in (2, 3):
        need(symbol.startswith(('_', '@', '?')), 'prefix name transform')
    if kind == 3:
        suffix = symbol[1:].split('@', 1)
        need(len(suffix) == 1 or suffix[1].isdigit(), 'undecorate suffix')
    return dict(exports=[symbol, '__imp_' + symbol], dll=dll, sections=0, short_imports=1, relocations=0)


def debug_metadata(b, dll):
    need(len(b) >= 4 and struct.unpack_from('<I', b)[0] == 2, 'CodeView version')
    p = 4
    records = []
    while p < len(b):
        need(p + 4 <= len(b), 'CodeView record bounds')
        (n, kind) = struct.unpack_from('<HH', b, p)
        end = p + 2 + n
        need(n >= 2 and end <= len(b), 'CodeView length')
        payload = b[p + 4:end]
        if kind == 9:
            need(len(payload) >= 5 and payload[:4] == bytes(4), 'object name signature')
            need(payload[4] == len(payload) - 5 and payload[5:] == dll.encode(), 'object name')
        elif kind == 0x1013:
            need(len(payload) >= 19, 'compile record size')
            need(payload[18] == len(payload) - 19, 'producer string length')
            producer = payload[19:]
            need(producer == b'Microsoft (R) LINK', 'compiler producer')
        else:
            raise Invalid('unknown CodeView record')
        records.append(kind)
        p = end
    need(records == [9, 0x1013] and p == len(b), 'CodeView structure')


def coff(b, machine):
    need(20 <= len(b) <= 8192, 'COFF size')
    (mach, n, stamp, sp, sc, opt, flags) = struct.unpack_from('<HHIIIHH', b)
    need(mach == machine and stamp == 0 and (opt == 0) and (flags == (0x100 if machine == 0x14c else 0)), 'COFF header')
    need(1 <= n <= 3 and 1 <= sc <= 8 and (20 + n * 40 <= sp), 'COFF table bounds')
    strings_at = sp + sc * 18
    need(strings_at + 4 <= len(b), 'COFF string bounds')
    strings = b[strings_at:]
    need(struct.unpack_from('<I', strings)[0] == len(strings), 'COFF string tail')
    for s in strings[4:].split(b'\x00'):
        if s:
            ascii_name(s, True)
    sections = []
    ranges = [(0, 20 + n * 40), (sp, len(b))]
    for i in range(n):
        (name, vs, rva, size, ptr, rel, lin, nr, nl, attrs) = struct.unpack_from('<8sIIIIIIHHI', b, 20 + i * 40)
        name = ascii_name(name.rstrip(b'\x00'))
        need(vs == rva == lin == nl == 0 and nr <= 3, 'COFF section metadata')
        need(not size or 20 + n * 40 <= ptr <= ptr + size <= sp, 'section range')
        need(not nr or 20 + n * 40 <= rel <= rel + 10 * nr <= sp, 'relocation range')
        if size:
            ranges.append((ptr, ptr + size))
        if nr:
            ranges.append((rel, rel + 10 * nr))
        sections.append(dict(name=name, data=b[ptr:ptr + size], attrs=attrs, relocs=[struct.unpack_from('<IIH', b, rel + j * 10) for j in range(nr)]))
    end = 0
    for (start, stop) in sorted(ranges):
        need(start >= end and (not any(b[end:start])), 'hidden/overlap COFF bytes')
        end = stop
    need(end == len(b), 'COFF end')
    symbols = []
    for i in range(sc):
        (name, value, section, kind, storage, aux) = struct.unpack_from('<8sIhHBB', b, sp + i * 18)
        if name[:4] == bytes(4):
            index = struct.unpack_from('<I', name, 4)[0]
            need(4 <= index < len(strings), 'symbol string index')
            stop = strings.find(b'\x00', index)
            need(stop >= index, 'symbol terminator')
            name = strings[index:stop]
        else:
            name = name.rstrip(b'\x00')
        name = ascii_name(name, True)
        need(kind == aux == 0, 'symbol type/auxiliary')
        symbols.append((name, value, section, storage))
    debug = sections[0]['name'] == '.debug$S'
    base = 1 if debug else 0
    core = sections[base:]
    layout = [s['name'] for s in core]
    expected = []
    dll = None
    if layout == ['.idata$2', '.idata$6']:
        label = core[1]['data']
        name = label.rstrip(b'\x00')
        need(label.endswith(b'\x00') and len(label) == ((len(name) + 2) // 2 * 2 if debug else len(name) + 1), 'DLL string')
        dll = dll_name(name)
        stem = dll.rsplit('.', 1)[0]
        need(core[0]['data'] == bytes(20) and core[0]['attrs'] == 0xc0300040, 'descriptor data')
        need(core[1]['attrs'] == 0xc0200040 and (not core[1]['relocs']), 'DLL section attributes')
        relocation_type = {0x14c: 7, 0x8664: 3, 0xaa64: 2}[machine]
        rel = core[0]['relocs']
        need(len(rel) == 3, 'descriptor relocation count')
        expected_rel = {12: '.idata$6', 0: '.idata$4', 16: '.idata$5'}
        need({r[0] for r in rel} == set(expected_rel), 'descriptor relocation locations')
        for (offset, symbol, type) in rel:
            need(type == relocation_type and symbol < len(symbols) and (symbols[symbol][0] == expected_rel[offset]), 'descriptor relocation target')
        expected = [('__IMPORT_DESCRIPTOR_' + stem, 0, base + 1, 2), ('.idata$2', 0xc0000040 if debug else 0, base + 1, 104), ('.idata$6', 0, base + 2, 3), ('.idata$4', 0xc0000040 if debug else 0, 0, 104), ('.idata$5', 0xc0000040 if debug else 0, 0, 104), ('__NULL_IMPORT_DESCRIPTOR', 0, 0, 2), ('\x7f' + stem + '_NULL_THUNK_DATA', 0, 0, 2)]
    elif layout == ['.idata$3']:
        need(core[0]['data'] == bytes(20) and core[0]['attrs'] == 0xc0300040 and (not core[0]['relocs']), 'null descriptor')
        expected = [('__NULL_IMPORT_DESCRIPTOR', 0, base + 1, 2)]
    elif layout == ['.idata$5', '.idata$4']:
        width = 4 if machine == 0x14c else 8
        attr = 0xc0300040 if width == 4 else 0xc0400040
        need(all((s['data'] == bytes(width) and s['attrs'] == attr and (not s['relocs']) for s in core)), 'null thunks')
        external = [s for s in symbols if s[3] == 2]
        need(len(external) == 1 and re.fullmatch('\\x7f[A-Za-z0-9_.-]+_NULL_THUNK_DATA', external[0][0]), 'null thunk name')
        expected = [(external[0][0], 0, base + 1, 2)]
    else:
        raise Invalid('unknown import metadata layout')
    if debug:
        need(sections[0]['attrs'] == 0x42100040 and (not sections[0]['relocs']), 'debug section attributes')
        need(symbols[0] == ('@comp.id', 0x10175c4, -1, 3), 'compiler absolute symbol')
        expected = [symbols[0]] + expected
    need(symbols == expected, 'unexpected symbol semantics')
    return dict(exports=[s[0] for s in symbols if s[3] == 2 and s[2] > 0], dll=dll, sections=n, short_imports=0, relocations=sum((len(s['relocs']) for s in sections)), debug=sections[0]['data'] if debug else None)


def review(raw, machine):
    need(machine in (0x14c, 0x8664, 0xaa64), 'unsupported machine')
    need(8 <= len(raw) <= 16 * 1024 * 1024 and raw.startswith(b'!<arch>\n'), 'AR framing')
    at = 8
    entries = []
    while at < len(raw):
        need(len(entries) < 100000 and at + 60 <= len(raw), 'AR member budget')
        h = raw[at:at + 60]
        need(h[58:] == b'`\n' and all((32 <= v < 127 for v in h[:58])), 'AR header')
        need(h[48:58].strip().isdigit(), 'AR size')
        need(h[16:28].strip() == b'-1' or not h[16:28].strip() or h[16:28].strip().isdigit(), 'AR timestamp')
        for (x, y) in ((28, 34), (34, 40)):
            need(not h[x:y].strip() or h[x:y].strip() == b'0', 'AR uid/gid')
        need(all((v in b'01234567 ' for v in h[40:48])), 'AR mode')
        n = int(h[48:58])
        end = at + 60 + n
        need(end <= len(raw), 'AR member size')
        entries.append((at, h[:16].strip(), raw[at + 60:end]))
        if n % 2:
            need(raw[end:end + 1] == b'\n', 'AR alignment byte')
        at = end + n % 2
    need(at == len(raw), 'AR trailing data')
    indexes = [d for (_, n, d) in entries if n == b'/']
    need(len(indexes) in (1, 2), 'index count')
    longs = [d for (_, n, d) in entries if n == b'//']
    need(len(longs) <= 1, 'long names count')
    long_names = {}
    if longs:
        table = longs[0]
        p = 0
        while p < len(table) and table[p:] not in (b'\n', b'\x00'):
            stop = table.find(b'/\n', p) if len(indexes) == 1 else table.find(b'\x00', p)
            need(stop > p, 'long name framing')
            long_names[p] = dll_name(table[p:stop])
            p = stop + (2 if len(indexes) == 1 else 1)
        need(p == len(table) or table[p:] in (b'\n', b'\x00'), 'long name tail')
    definitions = {}
    counts = Counter()
    dlls = set()
    all_names = []
    for (offset, name, d) in entries:
        if name in (b'/', b'//'):
            continue
        if name.startswith(b'/'):
            need(name[1:].isdigit() and int(name[1:]) in long_names, 'long name reference')
            member = long_names[int(name[1:])]
        else:
            member = dll_name(name.rstrip(b'/'))
        result = short_import(d, machine) if d.startswith(b'\x00\x00\xff\xff') else coff(d, machine)
        need(result['dll'] is None or result['dll'].lower() == member.lower(), 'DLL member mismatch')
        if result.get('debug') is not None:
            debug_metadata(result['debug'], member)
        definitions[offset] = set(result['exports'])
        dlls.add(member)
        all_names.extend(result['exports'])
        for key in ('sections', 'short_imports', 'relocations'):
            counts[key] += result[key]
        counts['objects'] += 1

    def names_table(b, count):
        names = b.split(b'\x00')
        need(len(names) >= count + 1 and (not any(names[count:])), 'index name tail')
        return [ascii_name(n, True) for n in names[:count]]
    table = indexes[0]
    need(len(table) >= 4, 'first index size')
    count = struct.unpack_from('>I', table)[0]
    need(count <= 100000 and 4 + count * 4 <= len(table), 'first index count')
    offsets = struct.unpack_from('>' + str(count) + 'I', table, 4)
    names = names_table(table[4 + count * 4:], count)
    first = list(zip(names, offsets))
    for (name, offset) in first:
        need(offset in definitions and name in definitions[offset], 'index names vs actual definitions')
    need(set(names) == set(all_names), 'unindexed unique definitions')
    if len(indexes) == 1:
        actual = [(name, offset) for (offset, names) in definitions.items() for name in names]
        need(sorted(first) == sorted(actual), 'GNU index complete definitions')
    else:
        table = indexes[1]
        need(len(table) >= 4, 'second index size')
        count = struct.unpack_from('<I', table)[0]
        need(count <= 100000 and 8 + count * 4 <= len(table), 'second index member count')
        p = 4 + count * 4
        objects = list(struct.unpack_from('<' + str(count) + 'I', table, 4))
        need(len(set(objects)) == len(objects) and set(objects) == set(definitions), 'second index object table')
        count = struct.unpack_from('<I', table, p)[0]
        p += 4
        need(count <= 100000 and p + 2 * count <= len(table), 'second index symbol count')
        positions = struct.unpack_from('<' + str(count) + 'H', table, p)
        p += 2 * count
        need(all((1 <= v <= len(objects) for v in positions)), 'second index positions')
        names = names_table(table[p:], count)
        second = [(name, objects[idx - 1]) for (name, idx) in zip(names, positions)]
        need(sorted(second) == sorted(first), 'two linker indexes differ')
    return dict(counts=dict(counts), dlls=sorted(dlls), unique_exports=len(set(all_names)), linker_symbols=len(first))
