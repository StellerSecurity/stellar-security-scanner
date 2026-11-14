"""Review a bounded no-leap TZif2/3 database subset as data, never execute it."""
import struct
import re
import hashlib


class Invalid(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Invalid(message)


def footer_text(raw, version):
    require(all(32 <= v < 127 for v in raw), 'footer ASCII')
    text = raw.decode('ascii')
    name = r'(?:[A-Za-z]{3,}|<[A-Za-z0-9+-]{3,}>)'
    clock = r'[+-]?[0-9]{1,3}(?::[0-9]{1,2}(?::[0-9]{1,2})?)?'
    rule = r'M[0-9]{1,2}\.[1-5]\.[0-6](?:/' + clock + r')?'
    match = re.fullmatch(name + r'(?P<standard>' + clock + r')'
                         + r'(?:' + name + r'(?P<daylight>' + clock + r')?,'
                         + rule + ',' + rule + r')?', text)
    require(len(text) <= 256 and match is not None, 'unsupported POSIX footer')
    for month in re.findall(r'M([0-9]+)\.', text):
        require(1 <= int(month) <= 12, 'month range')
    for value in (match.group('standard'), match.group('daylight')):
        if value is None:
            continue
        fields = [int(v) for v in value.lstrip('+-').split(':')]
        require(fields[0] <= 24 and all(v < 60 for v in fields[1:]), 'offset clock range')
    for value in re.findall(r'/(' + clock + ')', text):
        fields = [int(v) for v in value.lstrip('+-').split(':')]
        require(fields[0] <= (167 if version == 51 else 24) and all(v < 60 for v in fields[1:]), 'transition clock range')
    return text


def review(raw):
    require(isinstance(raw, bytes) and 0 < len(raw) <= 8 * 1024 * 1024, 'database size')
    offset = 0
    rows = []
    total_transitions = 0
    while offset < len(raw):
        require(len(rows) < 1000, 'record limit')
        start = offset
        blocks = []
        version = None
        for width in (4, 8):
            require(offset + 44 <= len(raw), 'truncated header')
            head = raw[offset:offset + 44]
            require(head[:4] == b'TZif' and head[4] in (50, 51) and not any(head[5:20]), 'header magic/version/reserved')
            if version is None:
                version = head[4]
            require(head[4] == version, 'mixed record versions')
            ut, standard, leap, count, types, chars = struct.unpack_from('>6I', head, 20)
            # This reviewed database has none. Do not claim to review additional
            # leap-second or transition-indicator dialects without new work.
            require(ut == standard == leap == 0, 'unsupported leap/indicator data')
            require(0 <= count <= 20000 and 1 <= types <= 256 and 1 <= chars <= 4096, 'count bounds')
            total_transitions += count
            require(total_transitions <= 100000, 'transition budget')
            end = offset + 44 + count * (width + 1) + types * 6 + chars
            require(end <= len(raw), 'truncated block')
            cursor = offset + 44
            times = [v[0] for v in struct.iter_unpack('>i' if width == 4 else '>q', raw[cursor:cursor + count * width])]
            require(all(a < b for a, b in zip(times, times[1:])), 'unsorted transitions')
            cursor += count * width
            indices = raw[cursor:cursor + count]
            require(all(v < types for v in indices), 'transition type index')
            cursor += count
            tt = list(struct.iter_unpack('>iBB', raw[cursor:cursor + types * 6]))
            cursor += types * 6
            labels = raw[cursor:end]
            require(labels[-1] == 0 and all(v == 0 or v in (43, 45) or 48 <= v <= 57 or 65 <= v <= 90 or 97 <= v <= 122 for v in labels), 'abbreviation byte grammar')
            require(all(len(label) <= 32 for label in labels.split(b'\0')), 'label length')
            abbreviations = []
            for gmtoff, dst, idx in tt:
                require(-89999 <= gmtoff <= 93599 and dst in (0, 1) and idx < chars, 'local time type')
                stop = labels.find(b'\0', idx)
                require(stop >= idx and stop - idx <= 32, 'abbreviation termination/length')
                abbreviations.append(labels[idx:stop].decode('ascii'))
            blocks.append(dict(offset=offset, end_offset=end, time_width=width, transitions=count, types=types, character_bytes=chars, first_transition=times[0] if times else None, last_transition=times[-1] if times else None, local_types=[dict(offset=s, dst=d, abbreviation=a) for (s,d,i),a in zip(tt,abbreviations)],label_table_sha256=hashlib.sha256(labels).hexdigest()))
            offset = end
        require(offset < len(raw) and raw[offset] == 10, 'missing footer opening')
        close = raw.find(b'\n', offset + 1, min(len(raw), offset + 258))
        require(close != -1, 'missing/oversized footer end')
        footer = footer_text(raw[offset + 1:close], version)
        offset = close + 1
        rows.append(dict(offset=start,end_offset=offset,version=chr(version),sha256=hashlib.sha256(raw[start:offset]).hexdigest(),blocks=blocks,footer=footer))
    return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),records=rows,record_count=len(rows),transition_count=total_transitions,target_executed=False,all_bytes_accounted_for=offset==len(raw))
