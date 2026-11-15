"""Bounded core-WASM function/code ranges; never type or behavior approval.

No WASM engine is used. Length/local declarations are parsed as data only.
Instruction semantics, control/type validation, imports and data need separate
review. Unknown sections/local types fail rather than being silently omitted.
"""
import hashlib


def require(ok, message):
    if not ok:
        raise ValueError(message)


class Reader:
    def __init__(self, data, start=0, end=None):
        self.data = data
        self.pos = start
        self.end = len(data) if end is None else end
        require(0 <= start <= self.end <= len(data), 'reader bounds')

    def byte(self):
        require(self.pos < self.end, 'truncated byte')
        value = self.data[self.pos]
        self.pos += 1
        return value

    def u32(self):
        value = 0
        for index in range(5):
            byte = self.byte()
            require(index < 4 or byte < 16, 'u32 overflow')
            value |= (byte & 127) << (index * 7)
            if byte < 128:
                return value
        raise ValueError('u32 length')


def inspect(raw):
    require(8 <= len(raw) <= 32 * 1024 * 1024 and raw[:8] == b'\0asm\1\0\0\0',
            'core WASM header/size')
    reader = Reader(raw, 8)
    sections = []
    functions = []
    function_count = None
    seen = set()
    while reader.pos < reader.end:
        kind = reader.byte()
        require(kind <= 12, 'unsupported section')
        size = reader.u32()
        start = reader.pos
        end = start + size
        require(end <= reader.end, 'section bounds')
        if kind:
            require(kind not in seen, 'duplicate section')
            seen.add(kind)
        sections.append(dict(id=kind, start=start, end=end,
                             sha256=hashlib.sha256(raw[start:end]).hexdigest()))
        inner = Reader(raw, start, end)
        if kind == 3:
            function_count = inner.u32()
            require(function_count <= 100000, 'function count budget')
            for _ in range(function_count):
                inner.u32()
            require(inner.pos == end, 'function vector trailing bytes')
        elif kind == 10:
            count = inner.u32()
            require(function_count is not None and count == function_count,
                    'code/function count mismatch or ordering')
            for index in range(count):
                size_at = inner.pos
                length = inner.u32()
                body = inner.pos
                body_end = body + length
                require(0 < length and body_end <= end, 'function body bounds')
                local_reader = Reader(raw, body, body_end)
                groups = local_reader.u32()
                require(groups <= 10000, 'local groups budget')
                locals_count = 0
                for _ in range(groups):
                    locals_count += local_reader.u32()
                    require(locals_count <= 1000000, 'locals budget')
                    require(local_reader.byte() in (0x7f, 0x7e, 0x7d, 0x7c, 0x7b, 0x70, 0x6f),
                            'unsupported local value type')
                require(local_reader.pos < body_end and raw[body_end - 1] == 0x0b,
                        'missing function instruction/final end')
                functions.append(dict(index=index, size_offset=size_at, body_start=body,
                                      code_start=local_reader.pos, end=body_end,
                                      locals=locals_count))
                inner.pos = body_end
            require(inner.pos == end, 'code vector trailing bytes')
        reader.pos = end
    require(function_count is not None and len(functions) == function_count,
            'missing/inconsistent function or code sections')
    return dict(sections=sections, functions=functions, metadata_only=True,
                type_validation_complete=False, semantic_review_complete=False,
                native_code_cleared=False, target_executed=False)


class Coverage:
    """Byte-match decoder output to exactly the independently parsed code ranges.

    Function length prefixes and locals are metadata, not instructions. Rows
    overlapping them, changed bytes, duplicates or missing bytes fail closed.
    This is still NOT an opcode/type/behavior validator.
    """
    def __init__(self, raw):
        import bisect
        self._bisect = bisect.bisect_right
        self.raw = raw
        self.metadata = inspect(raw)
        self.functions = self.metadata['functions']
        self.starts = [f['code_start'] for f in self.functions]
        self.covered = bytearray(len(raw))
        self.rows = 0

    def add(self, address, encoded):
        require(isinstance(address, int) and isinstance(encoded, bytes)
                and 0 < len(encoded) <= 65536, 'decoded row address/size/type')
        index = self._bisect(self.starts, address) - 1
        require(index >= 0 and address + len(encoded) <= self.functions[index]['end'],
                'decoded bytes outside function code')
        end = address + len(encoded)
        require(self.raw[address:end] == encoded, 'decoded bytes differ from original')
        require(not any(self.covered[address:end]), 'duplicate/overlapping decoded row')
        self.covered[address:end] = b'\1' * len(encoded)
        self.rows += 1

    def finish(self):
        total = sum(f['end'] - f['code_start'] for f in self.functions)
        for f in self.functions:
            require(all(self.covered[f['code_start']:f['end']]), 'undecoded function bytes')
        require(sum(self.covered) == total, 'unexpected decoded bytes')
        return dict(instruction_bytes=total, decoded_rows=self.rows,
                    byte_coverage_complete=True, type_validation_complete=False,
                    semantic_review_complete=False, native_code_cleared=False,
                    target_executed=False)
