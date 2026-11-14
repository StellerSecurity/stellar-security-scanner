"""Static review of the narrow GNU import-object forms; never execute targets.

This is evidence tooling, not a runtime binary exemption. Callers must bind
review results to exact archive/member hashes and retain all other blockers.
"""
import struct


class ReviewError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ReviewError(message)


def ascii_name(raw):
    require(bool(raw) and all(32 <= c < 127 for c in raw), 'invalid ASCII metadata')
    return raw.decode('ascii')


def cstring(raw):
    at = raw.find(b'\0')
    require(at > 0 and not any(raw[at:]), 'noncanonical string/padding')
    return ascii_name(raw[:at])


def coff(raw, expected_machine):
    require(20 <= len(raw) <= 16 * 1024 * 1024, 'COFF size')
    machine, count, stamp, symbols, number, optional, flags = struct.unpack_from('<HHIIIHH', raw)
    require(machine == expected_machine and machine in (0x14c, 0x8664), 'COFF machine')
    require(optional == 0 and flags in ((0x104, 0x105) if machine == 0x14c else (4, 5)), 'COFF header flags')
    require(1 <= count <= 8 and 1 <= number <= 100000, 'COFF table bounds')
    end_headers = 20 + count * 40
    strings_at = symbols + number * 18
    require(end_headers <= symbols and strings_at + 4 <= len(raw), 'COFF symbol range')
    strings_length = struct.unpack_from('<I', raw, strings_at)[0]
    require(strings_length >= 4 and strings_at + strings_length == len(raw), 'COFF string-table tail')
    strings = raw[strings_at:]
    require(all(c == 0 or 32 <= c < 127 for c in strings[4:]), 'COFF string bytes')
    ranges = [(0, end_headers), (symbols, len(raw))]
    sections = []
    names = [ascii_name(part) for part in strings[4:].split(b'\0') if part]
    for i in range(count):
        row = struct.unpack_from('<8sIIIIIIHHI', raw, 20 + i * 40)
        name, virtual_size, virtual_address, size, pointer, reloc, lines, nr, nl, attributes = row
        name = ascii_name(name.rstrip(b'\0'))
        require(virtual_size == virtual_address == lines == nl == 0, 'non-object section metadata')
        require(nr <= 3 and (not size or end_headers <= pointer <= pointer + size <= symbols), 'section range')
        require(not nr or end_headers <= reloc <= reloc + nr * 10 <= symbols, 'relocation range')
        if size:
            ranges.append((pointer, pointer + size))
        if nr:
            ranges.append((reloc, reloc + nr * 10))
        sections.append((name, raw[pointer:pointer + size], attributes,
                         [struct.unpack_from('<IIH', raw, reloc + j * 10) for j in range(nr)]))
    ranges.sort()
    previous = 0
    for start, end in ranges:
        require(start >= previous and not any(raw[previous:start]), 'overlapping or hidden object bytes')
        previous = end
    require(previous == len(raw), 'unaccounted object tail')
    rows = {}
    index = 0
    while index < number:
        at = symbols + index * 18
        name, value, section, kind, storage, auxiliary = struct.unpack_from('<8sIhHBB', raw, at)
        if name[:4] == b'\0' * 4:
            offset = struct.unpack_from('<I', name, 4)[0]
            require(4 <= offset < len(strings), 'symbol string offset')
            end = strings.find(b'\0', offset)
            require(end >= offset, 'unterminated symbol')
            name = strings[offset:end]
        else:
            name = name.rstrip(b'\0')
        name = ascii_name(name)
        require(kind == 0 and auxiliary in (0, 1) and index + auxiliary < number, 'symbol type/auxiliary')
        require(storage in (2, 3, 103) and -2 <= section <= count, 'symbol class/section')
        if storage == 103:
            require(name == '.file' and value == 0 and section == -2 and auxiliary == 1,
                    'unexpected file symbol')
            require(raw[at + 18:at + 36] == b'fake' + b'\0' * 14, 'unexpected file auxiliary')
        else:
            require(section >= 0 and (section > 0 or value == 0), 'symbol value')
            if section:
                require(value <= len(sections[section - 1][1]), 'out-of-section symbol')
            if auxiliary:
                require(storage == 3 and section > 0 and name == sections[section - 1][0], 'unexpected auxiliary')
                length, nrel, nline, checksum, association, selection, reserved, high = struct.unpack_from('<IHHIhBBH', raw, at + 18)
                require(0 <= len(sections[section - 1][1]) - length <= 3 and nrel == len(sections[section - 1][3]), 'section auxiliary lengths')
                require(nline == checksum == association == selection == reserved == high == 0, 'noncanonical section auxiliary')
        rows[index] = (name, value, section, storage)
        names.append(name)
        index += 1 + auxiliary
    jumps = 0
    for name, data, attributes, relocs in sections:
        if name in ('.data', '.bss'):
            require(not data and not relocs, 'nonempty data/bss')
            require(attributes in ((0xc0300040, 0xc0500040) if name == '.data' else (0xc0300080, 0xc0500080)), 'data/bss flags')
        elif name == '.text':
            require(attributes in (0x60300020, 0x60500020), 'text flags')
            require((not data and not relocs) or (data == b'\xff\x25\0\0\0\0\x90\x90' and len(relocs) == 1), 'unreviewed instructions')
            jumps += bool(data)
        elif name == '.idata$2':
            require(data == b'\0' * 20 and attributes == 0xc0300040 and {r[0] for r in relocs} == {0, 12, 16}, 'import descriptor')
        elif name in ('.idata$4', '.idata$5'):
            require(len(data) in (0, 4, 8) and not any(data) and attributes in (0xc0300040, 0xc0400040, 0xc0300000), 'import address table')
            require(len(relocs) <= 1 and (not relocs or relocs[0][0] == 0), 'import table relocation count')
        elif name == '.idata$7':
            if relocs:
                require(data == b'\0' * 4 and attributes == 0xc0300000 and len(relocs) == 1 and relocs[0][0] == 0, 'import head reference')
            else:
                require(attributes == 0xc0300040, 'DLL name flags')
                dll = cstring(data)
                # These three Windows modules have non-DLL extensions but are
                # documented import targets. This does not run/enable them.
                known_non_dll = dll.lower() in ('ksproxy.ax', 'netsh.exe', 'ntvdm.exe')
                require((dll.lower().endswith(('.dll', '.drv', '.cpl')) or known_non_dll)
                        and '/' not in dll and '\\' not in dll, 'DLL basename')
                names.append(dll)
        elif name == '.idata$6':
            require(attributes == 0xc0200000 and len(data) >= 3 and not relocs, 'import hint/name flags')
            names.append(cstring(data[2:]))
        else:
            raise ReviewError('unreviewed section: ' + name)
        for address, target_id, relocation_type in relocs:
            require(target_id in rows and address + 4 <= len(data), 'relocation target/range')
            target, value, section, storage = rows[target_id]
            target_section = sections[section - 1][0] if section > 0 else 'UNDEF'
            rva_type = 7 if machine == 0x14c else 3
            if name == '.text':
                require(address == 2 and relocation_type == (6 if machine == 0x14c else 4)
                        and target_section == '.idata$5' and value == 0
                        and ((storage == 2 and target.startswith('__imp_')) or (storage == 3 and target == '.idata$5')), 'non-import jump target')
            else:
                require(relocation_type == rva_type and value == 0, 'non-RVA data relocation')
                expected = ('.idata$4' if address == 0 else 'UNDEF' if address == 12 else '.idata$5') if name == '.idata$2' else 'UNDEF' if name == '.idata$7' else '.idata$6'
                require(target_section == expected, 'unexpected import metadata target')
                if expected == 'UNDEF':
                    require(storage == 2, 'nonexternal import metadata')
                    require(target.endswith('_iname') if name == '.idata$2'
                            else target.lstrip('_').startswith('head_'), 'unexpected descriptor symbol')
    exports = [row[0] for row in rows.values() if row[3] == 2 and row[2] > 0]
    return {'jumps': jumps, 'names': names, 'symbols': number, 'exports': exports}


def review(raw, machine):
    require(8 <= len(raw) <= 16 * 1024 * 1024 and raw.startswith(b'!<arch>\n'), 'AR framing')
    offset = 8
    entries = []
    while offset < len(raw):
        require(len(entries) < 100000 and offset + 60 <= len(raw), 'AR member bound')
        header = raw[offset:offset + 60]
        require(header[58:] == b'`\n' and header[48:58].strip().isdigit(), 'AR header')
        require(all(32 <= c < 127 for c in header[:58]), 'AR header encoding')
        for start, end in ((16, 28), (28, 34), (34, 40)):
            require(not header[start:end].strip() or header[start:end].strip().isdigit(), 'AR numeric metadata')
        require(all(c in b'01234567 ' for c in header[40:48]), 'AR mode metadata')
        size = int(header[48:58])
        end = offset + 60 + size
        require(end <= len(raw), 'AR member length')
        entries.append((offset, header[:16].strip(), raw[offset + 60:end]))
        if size % 2:
            require(raw[end:end + 1] == b'\n', 'AR padding')
        offset = end + size % 2
    require(offset == len(raw), 'AR hidden tail')
    objects = {offset for offset, name, value in entries if name not in (b'/', b'//')}
    tables = [value for offset, name, value in entries if name == b'/']
    require(len(tables) == 1, 'GNU linker table count')
    table = tables[0]
    require(len(table) >= 4, 'short GNU linker table')
    count = struct.unpack_from('>I', table)[0]
    require(count <= 100000 and 4 + count * 4 <= len(table), 'GNU linker index bounds')
    indexes = [struct.unpack_from('>I', table, 4 + i * 4)[0] for i in range(count)]
    require(all(index in objects for index in indexes), 'linker index outside objects')
    symbols = table[4 + count * 4:].split(b'\0')
    require(len(symbols) >= count + 1 and not any(symbols[count:]), 'linker names/trailing bytes')
    names = [ascii_name(name) for name in symbols[:count]]
    actual_exports = []
    expected_exports = sorted(zip(names, indexes))
    long_tables = [value for offset, name, value in entries if name == b'//']
    require(len(long_tables) <= 1, 'duplicate long-name table')
    long_names = {}
    if long_tables:
        value = long_tables[0]
        position = 0
        while position < len(value) and value[position:] not in (b'\n', b'\0'):
            end = value.find(b'/\n', position)
            require(end > position, 'AR long-name framing')
            long_names[position] = ascii_name(value[position:end])
            position = end + 2
        names.extend(long_names.values())
    results = []
    for offset, name, value in entries:
        if name in (b'/', b'//'):
            continue
        if name.startswith(b'/'):
            require(name[1:].isdigit() and int(name[1:]) in long_names, 'AR long-name reference')
            member = long_names[int(name[1:])]
        else:
            member = ascii_name(name.rstrip(b'/'))
        require(member and not member.startswith(('/', '\\')) and '..' not in member.split('/'), 'AR member path')
        result = coff(value, machine)
        actual_exports.extend((symbol, offset) for symbol in result.pop('exports'))
        names.append(member)
        names.extend(result.pop('names'))
        results.append(result)
    require(sorted(actual_exports) == expected_exports, 'linker symbol index differs from definitions')
    return {'members': len(results), 'jumps': sum(r['jumps'] for r in results),
            'symbols': sum(r['symbols'] for r in results), 'names': names}
