"""Pure static executable-range/decoded-byte validation for review tooling.

No subprocess, target loading, native-code clearance or execution authorization.
Disassembled data can resemble instructions; complete byte coverage is evidence,
not proof of program behavior. ELF/PE loader metadata is explicitly unreviewed.
"""
import hashlib
import re
import struct
import review_macho_metadata as M
import review_pe_code_ranges as P


def rows(text, arm):
    result = []
    for line in text.splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s+([0-9a-f ]+)\t(\S+)(?:\s+(.*))?$', line)
        if not match:
            continue
        address, encoded, mnemonic, operands = match.groups()
        encoded = encoded.strip()
        raw = (int(encoded, 16).to_bytes(4, 'little')
               if arm and re.fullmatch('[0-9a-f]{8}', encoded) else bytes.fromhex(encoded))
        if not 0 < len(raw) <= 16:
            raise ValueError('instruction length')
        result.append((int(address, 16), raw, mnemonic, operands or ''))
    return result


def verify_chunk(data, section, start, stop, decoded):
    """Accept contiguous byte-matched rows, permitting a final crossing instruction."""
    cursor = start
    accepted = []
    end = section['address'] + section['bytes']
    for address, raw, mnemonic, operands in decoded:
        if not start <= address < stop:
            continue
        if address != cursor or address + len(raw) > end:
            raise ValueError('noncontiguous/overlapping/out-of-bounds instruction: expected %x, got %x, width %d, end %x' % (cursor, address, len(raw), end))
        at = section['offset'] + address - section['address']
        if data[at:at+len(raw)] != raw:
            raise ValueError('decoded bytes do not match input')
        cursor += len(raw)
        accepted.append((address, raw, mnemonic, operands))
    if cursor < stop or cursor == start:
        raise ValueError('undecoded code interval')
    return cursor, accepted


def images(data):
    if data.startswith(b'MZ'):
        return P.images(data)
    if data[:4] != b'\x7fELF':
        return [(offset, thin, M.inspect(thin)) for offset, thin in M.slices(data)]
    if len(data) < 64 or data[4:7] != b'\x02\x01\x01':
        raise ValueError('unsupported ELF class/endianness/version')
    machine = struct.unpack_from('<H', data, 18)[0]
    cpu = {62: 0x1000007, 183: 0x100000c}.get(machine)
    if cpu is None:
        raise ValueError('unsupported ELF machine')
    at = struct.unpack_from('<Q', data, 40)[0]
    stride, count, names = struct.unpack_from('<HHH', data, 58)
    if stride != 64 or not 0 < count <= 4096 or names >= count or at < 64 or at+count*stride > len(data):
        raise ValueError('ELF section table bounds')
    records = [struct.unpack_from('<IIQQQQIIQQ', data, at+i*stride) for i in range(count)]
    nt = records[names]
    if nt[1] != 3 or nt[4]+nt[5] > len(data):
        raise ValueError('ELF string table')
    strings = data[nt[4]:nt[4]+nt[5]]
    sections = []
    occupied = []
    for record in records:
        name, kind, flags, address, offset, length, link, info, align, entsize = record
        if not flags & 4 or not length:
            continue
        if (kind != 1 or not flags & 2 or offset+length > len(data) or name >= len(strings)
                or address+length > 2**64 or (align and align & (align-1))):
            raise ValueError('ELF executable section bounds/type')
        stop = strings.find(b'\0', name)
        if stop < name:
            raise ValueError('ELF section name')
        label = strings[name:stop].decode('ascii')
        if not re.fullmatch(r'[.A-Za-z0-9_]+', label):
            raise ValueError('unexpected ELF section name')
        if any(address < old_end and old_start < address+length for old_start, old_end in occupied):
            raise ValueError('overlapping ELF executable address ranges')
        occupied.append((address,address+length))
        sections.append(dict(name=label,address=address,bytes=length,offset=offset,
                             attributes=0x80000400,zero_fill=False,
                             sha256=hashlib.sha256(data[offset:offset+length]).hexdigest()))
    if not sections:
        raise ValueError('no ELF executable section')
    return [(0, data, dict(cpu=cpu,sections=sections,libraries=[],imports=[],initializers=[],
                           loader_metadata_reviewed=False))]
