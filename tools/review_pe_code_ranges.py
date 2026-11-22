"""Bound PE executable file-byte ranges; no loader/import/security clearance."""
import hashlib
import re
import struct


def require(test, message):
    if not test:
        raise ValueError(message)


def images(data):
    require(512 <= len(data) <= 32 * 1024**2 and data[:2] == b'MZ', 'PE input bounds/signature')
    at = struct.unpack_from('<I', data, 60)[0]
    require(64 <= at <= len(data) - 24 and data[at:at + 4] == b'PE\0\0', 'PE header bounds')
    machine, count = struct.unpack_from('<HH', data, at + 4)
    optional_size = struct.unpack_from('<H', data, at + 20)[0]
    optional = at + 24
    require(1 <= count <= 96 and optional_size >= 96 and optional + optional_size <= len(data),
            'PE optional-header/section count')
    magic = struct.unpack_from('<H', data, optional)[0]
    cpu = {(0x14c, 0x10b): 7, (0x8664, 0x20b): 0x1000007,
           (0xaa64, 0x20b): 0x100000c}.get((machine, magic))
    require(cpu is not None and optional_size >= (224 if magic == 0x10b else 240), 'PE architecture')
    base = struct.unpack_from('<I' if magic == 0x10b else '<Q', data, optional + (28 if magic == 0x10b else 24))[0]
    section_align, file_align = struct.unpack_from('<II', data, optional + 32)
    image_size, headers_size = struct.unpack_from('<II', data, optional + 56)
    require(512 <= file_align <= 65536 and not file_align & (file_align - 1)
            and section_align >= file_align and not section_align & (section_align - 1), 'PE alignment')
    table = optional + optional_size
    require(table + count * 40 <= headers_size <= len(data) and headers_size % file_align == 0,
            'PE section-table/header bounds')
    require(image_size > 0 and image_size % section_align == 0 and
            base + image_size <= (2**32 if magic == 0x10b else 2**64), 'PE image bounds')
    raw_ranges, virtual_ranges, sections, names = [], [], [], set()
    for index in range(count):
        row = table + index * 40
        name = data[row:row + 8].rstrip(b'\0').decode('ascii')
        require(re.fullmatch(r'[.A-Za-z0-9_$]+', name) and name not in names, 'PE section name')
        names.add(name)
        virtual_size, rva, size, offset = struct.unpack_from('<IIII', data, row + 8)
        flags = struct.unpack_from('<I', data, row + 36)[0]
        require(rva % section_align == 0 and rva >= headers_size and
                rva + max(virtual_size, size) <= image_size, 'PE virtual section bounds')
        if size:
            require(offset >= headers_size and offset % file_align == 0 and size % file_align == 0
                    and offset <= len(data) and size <= len(data) - offset, 'PE raw section bounds')
            require(not any(offset < end and start < offset + size for start, end in raw_ranges),
                    'PE overlapping raw sections')
            raw_ranges.append((offset, offset + size))
        span = max(virtual_size, size)
        require(not any(rva < end and start < rva + span for start, end in virtual_ranges),
                'PE overlapping virtual sections')
        virtual_ranges.append((rva, rva + span))
        if not flags & 0x20000020:
            continue
        require(size > 0 and virtual_size > 0, 'PE executable zero-fill section needs separate review')
        code_bytes = min(size, virtual_size)
        padding = data[offset + code_bytes:offset + size]
        require(not any(padding), 'nonzero PE raw alignment padding needs separate review')
        sections.append(dict(name=name, address=base + rva, offset=offset, bytes=code_bytes,
                             attributes=0x80000400, zero_fill=False,
                             raw_bytes=size, zero_padding_bytes=len(padding),
                             zero_padding_sha256=hashlib.sha256(padding).hexdigest(),
                             raw_sha256=hashlib.sha256(data[offset:offset + size]).hexdigest(),
                             unbacked_virtual_bytes=max(0, virtual_size - size),
                             sha256=hashlib.sha256(data[offset:offset + code_bytes]).hexdigest()))
    require(sections, 'no PE executable file-byte section')
    return [(0, data, dict(cpu=cpu, sections=sections, libraries=[], imports=[], initializers=[],
                           loader_metadata_reviewed=False, pe_file_bytes_only=True))]
