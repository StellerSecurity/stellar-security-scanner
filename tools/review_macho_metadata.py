"""Bounded Mach-O metadata and stub resolution for independent code review.

No target code is loaded. Metadata success is not a native-code clearance.
"""
import hashlib
import struct


class Invalid(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Invalid(message)


def slices(raw):
    require(32 <= len(raw) <= 96 * 1024 * 1024, 'Mach-O input budget')
    if raw[:4] == bytes.fromhex('cffaedfe'):
        return [(0, raw)]
    require(raw[:4] == bytes.fromhex('cafebabe'), 'unsupported Mach-O/fat magic')
    count = struct.unpack_from('>I', raw, 4)[0]
    require(1 <= count <= 32 and 8+count*20 <= len(raw), 'fat table bounds')
    result = []
    ranges = []
    for i in range(count):
        cpu, subtype, offset, size, alignment = struct.unpack_from('>IIIII', raw, 8+i*20)
        require(alignment <= 24 and offset % (1 << alignment) == 0
                and offset >= 8+count*20 and size >= 32 and offset+size <= len(raw),
                'fat slice bounds/alignment')
        thin = raw[offset:offset+size]
        require(thin[:4] == bytes.fromhex('cffaedfe')
                and struct.unpack_from('<II', thin, 4) == (cpu, subtype), 'fat/thin identity')
        ranges.append((offset, offset+size))
        result.append((offset, thin))
    previous = 8+count*20
    for start, end in sorted(ranges):
        require(start >= previous and not any(raw[previous:start]), 'fat overlap/nonzero padding')
        previous = end
    require(previous == len(raw) or not any(raw[previous:]), 'fat trailing data')
    return result


def inspect(raw):
    require(32 <= len(raw) <= 32 * 1024 * 1024 and raw[:4] == bytes.fromhex('cffaedfe'),
            'thin Mach-O size/magic')
    cpu, subtype, filetype, count, commands_size, flags, reserved = struct.unpack_from('<7I', raw, 4)
    require(1 <= count <= 4096 and 32+commands_size <= len(raw), 'load command budget')
    pos = 32
    sections = []
    libraries = []
    symbol_table = None
    indirect_table = None
    commands = []

    def string(data, offset, end):
        require(0 <= offset < end <= len(data), 'string bounds')
        stop = data.find(b'\0', offset, end)
        require(stop >= offset, 'unterminated string')
        return data[offset:stop].decode('utf-8')

    for _ in range(count):
        require(pos+8 <= 32+commands_size, 'load command header')
        cmd, size = struct.unpack_from('<II', raw, pos)
        require(size >= 8 and size % 8 == 0 and pos+size <= 32+commands_size,
                'load command bounds/alignment')
        commands.append(cmd)
        if cmd == 0x19:
            require(size >= 72, 'segment header')
            segment = struct.unpack_from('<16sQQQQiiII', raw, pos+8)
            name, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, segflags = segment
            require(fileoff+filesize <= len(raw) and size == 72+nsects*80 and nsects <= 1024,
                    'segment/section bounds')
            for i in range(nsects):
                row = struct.unpack_from('<16s16sQQ8I', raw, pos+72+i*80)
                secname, segname, address, length, offset, align, reloff, nreloc, attr, one, two, three = row
                zero = attr & 255 in (1, 12, 18)
                require(align <= 32 and (zero or offset+length <= len(raw))
                        and vmaddr <= address and address+length <= vmaddr+vmsize,
                        'section address/data bounds')
                require(nreloc <= 1000000 and reloff+nreloc*8 <= len(raw), 'relocation bounds')
                payload = b'' if zero else raw[offset:offset+length]
                sections.append(dict(name=secname.split(b'\0')[0].decode('ascii'),
                                     segment=segname.split(b'\0')[0].decode('ascii'),
                                     address=address, bytes=length, offset=offset,
                                     attributes=attr, reserved1=one, reserved2=two,
                                     zero_fill=zero, sha256=hashlib.sha256(payload).hexdigest()))
        elif cmd in (0xc, 0x80000018, 0x8000001f, 0x80000023):
            require(size >= 24, 'dylib command')
            at = struct.unpack_from('<I', raw, pos+8)[0]
            require(24 <= at < size, 'dylib name offset')
            libraries.append(string(raw, pos+at, pos+size))
        elif cmd == 2:
            require(size == 24 and symbol_table is None, 'symbol table command')
            symbol_table = struct.unpack_from('<4I', raw, pos+8)
        elif cmd == 0xb:
            require(size == 80 and indirect_table is None, 'dynamic symbol command')
            indirect_table = struct.unpack_from('<II', raw, pos+56)
        pos += size
    require(pos == 32+commands_size and symbol_table is not None, 'command table completeness')
    offset, symbols, strings, string_bytes = symbol_table
    require(symbols <= 1000000 and offset+symbols*16 <= len(raw)
            and strings+string_bytes <= len(raw), 'symbol/string table bounds')
    table = []
    for i in range(symbols):
        index, kind, section, desc, value = struct.unpack_from('<IBBHQ', raw, offset+i*16)
        require(index < string_bytes, 'symbol name offset')
        table.append(dict(name=string(raw, strings+index, strings+string_bytes), kind=kind,
                          section=section, descriptor=desc, value=value))
    imports = sorted({r['name'] for r in table if not r['kind'] & 0xe0
                      and r['kind'] & 14 == 0 and r['value'] == 0 and r['name']})
    stubs = {}
    if indirect_table:
        at, number = indirect_table
        require(number <= 1000000 and at+number*4 <= len(raw), 'indirect table bounds')
        for section in sections:
            if section['attributes'] & 255 != 8:
                continue
            stride = section['reserved2']
            require(1 <= stride <= 64 and section['bytes'] % stride == 0, 'symbol stub stride')
            entries = section['bytes'] // stride
            first = section['reserved1']
            require(first+entries <= number, 'symbol stub index range')
            for i in range(entries):
                index = struct.unpack_from('<I', raw, at+(first+i)*4)[0]
                require(index < len(table), 'symbol stub target')
                stubs[section['address']+i*stride] = table[index]['name']
    return dict(cpu=cpu, subtype=subtype, filetype=filetype, sections=sections,
                libraries=libraries, imports=imports, stubs=stubs,
                code_symbols=[r for r in table if not r['kind'] & 0xe0 and r['kind'] & 14 == 14
                              and 0 < r['section'] <= len(sections)
                              and sections[r['section']-1]['attributes'] & 0x80000400],
                initializers=[s['name'] for s in sections if s['attributes'] & 255 in (9, 10, 21)],
                load_commands=commands, native_code_cleared=False, target_executed=False)
