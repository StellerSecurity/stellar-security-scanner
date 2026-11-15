"""Read one bounded MS-OVBA compressed chunk as DATA, never as VBA code.

An intact chunk inside a malformed compound file is only partial evidence. This
reader does not resolve CFB sector chains, p-code or modules, validate an Office
document, grant an exception, or execute the decoded bytes.
"""


class Invalid(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Invalid(message)


def chunk(raw):
    require(3 <= len(raw) <= 4098, 'chunk size')
    header = int.from_bytes(raw[:2], 'little')
    require((header >> 12) & 7 == 3 and (header & 4095) + 3 == len(raw),
            'chunk signature/size')
    if not header & 32768:
        require(len(raw) == 4098, 'raw chunk size')
        return raw[2:]
    out = bytearray()
    pos = 2
    while pos < len(raw):
        flags = raw[pos]
        pos += 1
        require(pos < len(raw), 'empty flag group')
        for bit in range(8):
            if pos == len(raw):
                break
            if flags & (1 << bit):
                require(pos + 2 <= len(raw) and bool(out), 'copy token bounds')
                token = int.from_bytes(raw[pos:pos+2], 'little')
                pos += 2
                width = max(4, (len(out) - 1).bit_length())
                mask = 65535 >> width
                length = (token & mask) + 3
                offset = (token >> (16 - width)) + 1
                require(offset <= len(out) and len(out) + length <= 4096,
                        'copy range/output limit')
                # Overlapping copies are part of the specified encoding.
                for _ in range(length):
                    out.append(out[-offset])
            else:
                require(len(out) < 4096, 'literal output limit')
                out.append(raw[pos])
                pos += 1
    return bytes(out)


def fragments(raw, candidate_limit=128):
    require(len(raw) <= 2 * 1024 * 1024, 'CFB input limit')
    require(raw.startswith(bytes.fromhex('d0cf11e0a1b11ae1')), 'CFB signature')
    require(1 <= candidate_limit <= 128, 'candidate budget')
    attempted = 0
    found = []
    exhausted = False
    for pos in range(1, len(raw) - 2):
        if raw[pos-1] != 1:
            continue
        header = int.from_bytes(raw[pos:pos+2], 'little')
        size = (header & 4095) + 3
        if (header >> 12) & 7 != 3 or pos + size > len(raw):
            continue
        if attempted == candidate_limit:
            exhausted = True
            break
        attempted += 1
        try:
            decoded = chunk(raw[pos:pos+size])
        except Invalid:
            continue
        if b'Attribute VB_' in decoded:
            found.append((pos, size, decoded))
    return found, dict(candidates_attempted=attempted, budget_exhausted=exhausted,
                      partial_review=True, compound_file_cleared=False,
                      target_executed=False)
