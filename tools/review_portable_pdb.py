"""Inspect standalone Portable PDB metadata without loading a debugger or CLR."""
import hashlib
import json
import struct
import uuid


def require(value, message):
    if not value:
        raise ValueError(message)


def compressed(raw, at):
    require(0 <= at < len(raw), 'truncated compressed integer')
    first = raw[at]
    width = 1 if first < 128 else 2 if first < 192 else 4 if first < 224 else 0
    require(width and at + width <= len(raw), 'invalid compressed integer')
    mask = {1: 127, 2: 63, 4: 31}[width]
    value = first & mask
    for byte in raw[at+1:at+width]:
        value = (value << 8) | byte
    return value, at + width


def integers(raw, start=0):
    result = []
    while start < len(raw):
        value, start = compressed(raw, start)
        result.append(value)
    return result


def sequence_points(raw, document, documents, signatures):
    at = 0

    def read(signed=False):
        nonlocal at
        before = at
        value, at = compressed(raw, at)
        if signed:
            bits = {1: 7, 2: 14, 4: 29}[at-before]
            value = (value >> 1) - ((1 << (bits-1)) if value & 1 else 0)
        return value

    require(read() <= signatures, 'sequence local signature reference')
    if not document:
        document = read()
    require(1 <= document <= documents, 'sequence initial document')
    previous_il, previous_line, previous_column, points = -1, None, None, 0
    while at < len(raw):
        delta = read()
        if previous_il >= 0 and delta == 0:
            document = read()
            require(1 <= document <= documents, 'sequence document reference')
            continue
        il = delta if previous_il == -1 else previous_il + delta
        require(0 <= il < 0x20000000, 'sequence IL offset')
        lines = read()
        columns = read(signed=lines > 0)
        if lines or columns:
            line = read(signed=previous_line is not None)
            column = read(signed=previous_column is not None)
            if previous_line is not None:
                line += previous_line
                column += previous_column
            end_line, end_column = line + lines, column + columns
            require(0 < line <= end_line < 0x20000000 and line != 0xfeefee, 'sequence line bounds')
            require(0 <= column < 65536 and 0 <= end_column < 65536, 'sequence column bounds')
            require(lines > 0 or end_column > column, 'sequence empty span')
            previous_line, previous_column = line, column
        previous_il = il
        points += 1
    require(points > 0, 'empty sequence record')
    return points


def inspect(raw):
    require(32 <= len(raw) <= 1024 * 1024, 'portable PDB size limit')
    require(raw[:12] == b'BSJB\x01\0\x01\0\0\0\0\0', 'metadata header')
    version_size = struct.unpack_from('<I', raw, 12)[0]
    require(version_size == 12 and raw[16:28] == b'PDB v1.0\0\0\0\0', 'metadata version')
    flags, count = struct.unpack_from('<HH', raw, 28)
    require(flags == 0 and count == 6, 'metadata stream count/flags')
    at, streams, ranges = 32, {}, []
    for _ in range(count):
        require(at + 8 <= len(raw), 'truncated stream entry')
        offset, size = struct.unpack_from('<II', raw, at)
        at += 8
        end = raw.find(b'\0', at, at + 32)
        require(end != -1, 'unterminated stream name')
        name = raw[at:end].decode('ascii')
        after = (end + 4) & ~3
        require(not any(raw[end:after]), 'stream name padding')
        require(name not in streams and offset % 4 == 0 and offset + size <= len(raw), 'stream bounds/name')
        streams[name] = (offset, raw[offset:offset+size])
        ranges.append((offset, offset + size))
        at = after
    require(set(streams) == {'#Pdb', '#~', '#Strings', '#US', '#GUID', '#Blob'}, 'unknown metadata stream')
    cursor = at
    for start, end in sorted(ranges):
        require(start >= cursor and start-cursor < 4 and not any(raw[cursor:start]), 'overlapping streams or unclassified padding')
        cursor = end
    require(cursor == len(raw), 'trailing metadata bytes')

    fields, values, used = [], [], {0}

    def text(offset, data, encoding='utf-8'):
        value = data.decode(encoding, errors='strict')
        fields.append({'offset': offset, 'bytes': len(data), 'encoding': encoding})
        values.append(value)
        return value

    strings_at, strings = streams['#Strings']
    require(strings and strings[0] == 0 and strings[-1] == 0, 'string heap framing')
    for part in strings.split(b'\0'):
        part.decode('utf-8', errors='strict')
    text(strings_at, strings)
    require(streams['#US'][1] == b'\0' * 4, 'unexpected user-string heap')
    guids = streams['#GUID'][1]
    require(len(guids) % 16 == 0, 'GUID heap alignment')

    blob_at, blobs = streams['#Blob']
    require(blobs and blobs[0] == 0, 'blob heap framing')
    entries, cursor = {0: (blob_at, b'')}, 1
    while cursor < len(blobs):
        index = cursor
        size, cursor = compressed(blobs, cursor)
        require(cursor + size <= len(blobs), 'blob heap bounds')
        entries[index] = (blob_at + cursor, blobs[cursor:cursor+size])
        cursor += size

    def blob(index):
        require(index in entries, 'blob reference is not a record boundary')
        used.add(index)
        return entries[index]

    def blob_text(index):
        offset, data = blob(index)
        return text(offset, data)

    def guid(index):
        require(1 <= index <= len(guids) // 16, 'GUID reference bounds')
        return str(uuid.UUID(bytes_le=guids[(index-1)*16:index*16]))

    pdb = streams['#Pdb'][1]
    require(len(pdb) >= 32, 'PDB stream header')
    external_bits = struct.unpack_from('<Q', pdb, 24)[0]
    require(len(pdb) == 32 + 4 * external_bits.bit_count(), 'external table row counts')
    external, cursor = {}, 32
    for table in range(64):
        if external_bits >> table & 1:
            require(table < 48, 'external debug table reference')
            external[table] = struct.unpack_from('<I', pdb, cursor)[0]
            cursor += 4
    tables = streams['#~'][1]
    require(len(tables) >= 24 and tables[:4] == b'\0'*4, 'table stream header')
    major, minor, heaps, reserved = tables[4:8]
    require((major, minor, reserved) == (2, 0, 1) and heaps & ~7 == 0, 'table stream version/flags')
    valid, sorted_bits = struct.unpack_from('<QQ', tables, 8)
    require(valid & ~sum(1 << t for t in range(48, 56)) == 0, 'non-debug table in standalone PDB')
    counts, cursor = {}, 24
    for table in range(48, 56):
        if valid >> table & 1:
            require(cursor + 4 <= len(tables), 'truncated table count')
            counts[table] = struct.unpack_from('<I', tables, cursor)[0]
            require(counts[table] <= 200000, 'table row budget')
            cursor += 4
    all_counts = external | counts
    require(counts.get(49, 0) in (0, external.get(6, 0)), 'method debug row count')
    coded_tables = (6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42, 44, 43, 48, 50, 51, 52, 53)
    schemas = {48: ('b', 'g', 'b', 'g'), 49: (48, 'b'), 50: (6, 53, 51, 52, 'u4', 'u4'),
               51: ('u2', 'u2', 's'), 52: ('s', 'b'), 53: (53, 'b'), 54: (6, 6), 55: ('c', 'g', 'b')}

    def width(kind):
        if isinstance(kind, int):
            return 2 if all_counts.get(kind, 0) < 65536 else 4
        if kind in ('u2', 'u4'):
            return int(kind[1])
        if kind == 'c':
            return 2 if max((all_counts.get(t, 0) for t in coded_tables), default=0) < 2048 else 4
        return 4 if heaps & {'s': 1, 'g': 2, 'b': 4}[kind] else 2

    rows = {}
    for table in range(48, 56):
        schema = schemas[table]
        rows[table] = []
        for _ in range(counts.get(table, 0)):
            row = []
            for kind in schema:
                size = width(kind)
                require(cursor + size <= len(tables), 'truncated table record')
                value = int.from_bytes(tables[cursor:cursor+size], 'little')
                cursor += size
                if kind == 'b':
                    blob(value)
                elif kind == 'g':
                    guid(value)
                elif kind == 's':
                    require(value < len(strings) and b'\0' in strings[value:], 'string reference bounds')
                    strings[value:strings.index(0, value)].decode('utf-8', errors='strict')
                elif isinstance(kind, int):
                    extra = 1 if table == 50 and kind in (51, 52) else 0
                    require(value <= all_counts.get(kind, 0) + extra, 'table reference bounds')
                elif kind == 'c':
                    tag, index = value & 31, value >> 5
                    require(tag < len(coded_tables) and 1 <= index <= all_counts.get(coded_tables[tag], 0), 'coded table reference bounds')
                row.append(value)
            rows[table].append(row)
    require(0 <= len(tables)-cursor <= 4 and not any(tables[cursor:]), 'table stream tail')

    documents = []
    for name, algorithm, checksum, language in rows[48]:
        _, data = blob(name)
        require(data and data[0] < 128, 'document separator')
        parts = [blob_text(index) for index in integers(data, 1)]
        documents.append(chr(data[0]).join(parts))
        require(guid(algorithm) == '8829d00f-11b8-4213-878b-770e8597ac16', 'document hash algorithm')
        require(len(blob(checksum)[1]) == 32, 'document hash width')
        require(guid(language) == '3f5162f8-07c6-11d3-9053-00c04fa302a1', 'document language')
    point_count = 0
    for document, sequence in rows[49]:
        if sequence:
            point_count += sequence_points(blob(sequence)[1], document, counts.get(48, 0), external.get(17, 0))
    for method, imports, variable, constant, start, length in rows[50]:
        require(method and variable and constant and start + length < 0x80000000, 'local scope record')
    for attributes, index, name in rows[51]:
        require(attributes & ~1 == 0, 'local variable flags')
    for name, signature in rows[52]:
        offset, data = blob(signature)
        if data[:1] == b'\x0e' and data[1:] != b'\xff':
            text(offset + 1, data[1:], 'utf-16-le')
        else:
            require(data[:1] == b'\x08' and len(data) == 5, 'unreviewed local constant signature')
    import_shapes = {1: 'n', 2: 'an', 3: 't', 4: 'nn', 5: 'n', 6: 'na', 7: 'nn', 8: 'nan', 9: 'nt'}
    for parent, index in rows[53]:
        items = iter(integers(blob(index)[1]))
        for kind in items:
            require(kind in import_shapes, 'unknown import kind')
            for field in import_shapes[kind]:
                value = next(items, None)
                require(value is not None, 'truncated import')
                if field == 'n':
                    blob_text(value)
                elif field == 'a':
                    require(1 <= value <= external.get(35, 0), 'assembly import reference')
                else:
                    tag, row = value & 3, value >> 2
                    require(tag < 3 and 1 <= row <= external.get((2, 1, 27)[tag], 0), 'type import reference')

    custom_kinds = {}
    source_links = []
    for parent, kind, index in rows[55]:
        kind = guid(kind)
        custom_kinds[kind] = custom_kinds.get(kind, 0) + 1
        offset, data = blob(index)
        if kind == 'cc110556-a091-4d38-9fec-25ab9a351a6a':
            link = json.loads(text(offset, data))
            require(isinstance(link, dict) and set(link) == {'documents'} and isinstance(link['documents'], dict), 'Source Link object')
            require(all(isinstance(k, str) and isinstance(v, str) for k, v in link['documents'].items()), 'Source Link values')
            source_links.append(link)
        elif kind == 'b5feec05-8cd0-4a83-96da-466284bb4bd8':
            require(data.endswith(b'\0'), 'compilation options terminator')
            options = text(offset, data).split('\0')[:-1]
            require(len(options) % 2 == 0 and len(set(options[::2])) == len(options) // 2, 'compilation option pairs')
        elif kind == '7e4d4708-096e-4c5c-aeda-cb10ba6a740d':
            cursor = 0
            while cursor < len(data):
                for _ in range(2):
                    end = data.find(b'\0', cursor)
                    require(end >= cursor, 'metadata reference terminator')
                    text(offset + cursor, data[cursor:end])
                    cursor = end + 1
                require(cursor + 25 <= len(data) and data[cursor] & ~3 == 0, 'metadata reference fields')
                cursor += 25
        elif kind == '6da9a61e-f8c7-4874-be62-68bc5630df71':
            require(len(data) % 8 == 0, 'hoisted scope alignment')
            for start, length in struct.iter_unpack('<II', data):
                require(start + length < 0x80000000, 'hoisted scope bounds')
        elif kind == '54fd2ac5-e925-401a-9c2a-f94f171072f8':
            require(len(data) >= 4, 'async stepping header')
            require(int.from_bytes(data[:4], 'little') < 0x80000000, 'async catch handler offset')
            cursor = 4
            while cursor < len(data):
                require(cursor + 8 <= len(data), 'async stepping offsets')
                require(all(offset < 0x80000000 for offset in struct.unpack_from('<II', data, cursor)), 'async stepping offset bounds')
                cursor += 8
                method, cursor = compressed(data, cursor)
                require(1 <= method <= external.get(6, 0), 'async method reference')
        elif kind == '83c563c4-b4f3-47d5-b824-ba5441477ea8':
            require(len(data) <= 1024, 'dynamic bit-vector budget')
        else:
            raise ValueError('unreviewed custom debug kind: ' + kind)
    remaining = [index for index, (_, data) in entries.items() if index not in used and data]
    require(not remaining, 'unreferenced nonempty blobs: ' + str(remaining[:20]))
    return {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw),
            'streams': {name: {'offset': offset, 'bytes': len(data)} for name, (offset, data) in streams.items()},
            'tables': counts, 'blob_records': len(entries), 'sequence_points': point_count, 'fields': fields,
            'documents': documents, 'source_links': source_links, 'custom_kinds': custom_kinds,
            'text': '\n'.join(values), 'unclassified_nonzero_bytes': 0,
            'packages_executed': False, 'network_requests': 0}
