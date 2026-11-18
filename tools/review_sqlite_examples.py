"""Read SQLite leaf records as bytes. Never load SQLite or execute stored SQL."""
import hashlib
import json
import struct


def require(value, message):
    if not value:
        raise ValueError(message)


def inspect(raw):
    require(len(raw) == 32768 and raw[:16] == b'SQLite format 3\0', 'database identity/size')
    require(raw[16:24] == bytes.fromhex('1000010100402020'), 'page format')
    require(struct.unpack_from('>I', raw, 28)[0] == 8, 'page count')
    require(raw[32:40] == b'\0' * 8, 'freelist is unsupported')
    require(struct.unpack_from('>I', raw, 44)[0] == 4, 'schema format')
    require(struct.unpack_from('>I', raw, 56)[0] == 1, 'only UTF-8 is reviewed')
    require(raw[64:92] == b'\0' * 28, 'reserved/application/auto-vacuum data')
    require(raw[24:28] == raw[92:96], 'version-valid-for counter')
    covered = bytearray(len(raw))
    records, fields = [], []

    def claim(start, size):
        require(0 <= start <= start + size <= len(raw), 'range bounds')
        require(not any(covered[start:start+size]), 'overlapping regions')
        covered[start:start+size] = b'\x01' * size

    def varint(start, stop):
        value = 0
        for index in range(9):
            require(start + index < stop, 'truncated varint')
            byte = raw[start+index]
            value = (value << (8 if index == 8 else 7)) | (byte if index == 8 else byte & 127)
            if index == 8 or byte < 128:
                return value, start + index + 1
        raise ValueError('invalid varint')

    def record(start, stop):
        header, at = varint(start, stop)
        require(at - start <= header <= stop - start, 'record header bounds')
        serials = []
        while at < start + header:
            serial, at = varint(at, start + header)
            serials.append(serial)
        require(at == start + header, 'record header end')
        cursor = at
        values = []
        for serial in serials:
            require(serial not in (10, 11), 'reserved record type')
            width = {0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 6, 6: 8, 7: 8, 8: 0, 9: 0}.get(serial)
            if width is None:
                width = (serial - 12) // 2
            require(0 <= width and cursor + width <= stop, 'record value bounds')
            data = raw[cursor:cursor+width]
            if serial >= 13 and serial % 2:
                values.append(data.decode('utf-8', errors='strict'))
                fields.append({'offset': cursor, 'bytes': width, 'kind': 'utf8'})
            elif serial >= 12:
                values.append({'blob': data.hex()})
                fields.append({'offset': cursor, 'bytes': width, 'kind': 'blob'})
            elif serial == 0:
                values.append(None)
            elif serial in (8, 9):
                values.append(serial - 8)
            elif serial == 7:
                values.append({'float_bytes': data.hex()})
            else:
                values.append(int.from_bytes(data, 'big', signed=True))
            cursor += width
        require(cursor == stop, 'unparsed record bytes')
        return values

    claim(0, 100)
    for page in range(8):
        base, end = page * 4096, (page + 1) * 4096
        at = base + (100 if page == 0 else 0)
        require(raw[at] in (10, 13), 'only leaf table/index pages are reviewed')
        kind = raw[at]
        free, count, content = struct.unpack_from('>HHH', raw, at + 1)
        require(raw[at+7] == 0 and 0 <= count <= 500, 'fragments/cell limit')
        require(at + 8 + count * 2 <= base + content <= end, 'cell area bounds')
        claim(at, 8 + count * 2)
        seen = set()
        while free:
            require(free not in seen and content <= free <= 4092, 'freeblock bounds/cycle')
            seen.add(free)
            following, size = struct.unpack_from('>HH', raw, base + free)
            require(size >= 4 and free + size <= 4096, 'freeblock size')
            require(not any(raw[base+free+4:base+free+size]), 'nonzero freeblock payload')
            claim(base + free, size)
            require(following == 0 or following > free, 'freeblock order')
            free = following
        for index in range(count):
            offset = struct.unpack_from('>H', raw, at+8+index*2)[0]
            require(content <= offset < 4096, 'cell pointer bounds')
            start = base + offset
            length, cursor = varint(start, end)
            rowid = None
            if kind == 13:
                rowid, cursor = varint(cursor, end)
            require(0 < length <= 4061 and cursor + length <= end, 'overflow/local payload bounds')
            values = record(cursor, cursor + length)
            claim(start, cursor + length - start)
            records.append({'page': page + 1, 'rowid': rowid, 'values': values})
    require(all(flag or byte == 0 for flag, byte in zip(covered, raw)), 'unaccounted nonzero bytes')
    return {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw), 'pages': 8,
            'records': records, 'fields': fields, 'unaccounted_nonzero_bytes': 0,
            'zero_padding_bytes': covered.count(0), 'sql_executed': False}
