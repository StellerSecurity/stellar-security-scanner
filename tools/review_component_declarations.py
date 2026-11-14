"""Read declaration-only component syntax as data, never instantiate Wasm."""
import json
from collections import Counter

class Invalid(ValueError):
    pass

class Reader:
    def __init__(self, raw, shared=None, depth=0):
        if len(raw) > 1024 * 1024 or depth > 48:
            raise Invalid('size/depth limit')
        self.raw = raw
        self.pos = 0
        self.depth = depth
        self.shared = shared if shared is not None else {'nodes': 0, 'strings': [], 'types': Counter()}

    def byte(self):
        if self.pos >= len(self.raw):
            raise Invalid('truncated field')
        value = self.raw[self.pos]
        self.pos += 1
        return value

    def expect(self, value):
        if self.byte() != value:
            raise Invalid('unexpected tag')

    def uint(self):
        value = 0
        for i in range(5):
            b = self.byte()
            if i == 4 and b & 0xf0:
                raise Invalid('u32 overflow')
            value |= (b & 127) << (7 * i)
            if b < 128:
                return value
        raise Invalid('oversized u32')

    def name(self):
        n = self.uint()
        if n > 65536 or self.pos + n > len(self.raw):
            raise Invalid('string bounds')
        try:
            value = self.raw[self.pos:self.pos + n].decode('utf-8')
        except UnicodeError:
            raise Invalid('invalid UTF8')
        self.pos += n
        if any(ord(c) < 32 and c not in '\r\n\t' for c in value):
            raise Invalid('string control')
        self.shared['strings'].append(value)
        return value

    def vector(self, fn):
        n = self.uint()
        self.shared['nodes'] += n
        if n > 10000 or self.shared['nodes'] > 100000:
            raise Invalid('node budget')
        return [fn() for _ in range(n)]

    def option(self, fn):
        tag = self.byte()
        if tag == 1:
            return fn()
        if tag != 0:
            raise Invalid('option tag')

    def named(self):
        if self.byte() not in (0, 1):
            raise Invalid('external name attribute')
        return self.name()

    def valtype(self):
        if self.pos == len(self.raw):
            raise Invalid('missing value type')
        if 0x73 <= self.raw[self.pos] <= 0x7f:
            return self.byte()
        # This subset's nonnegative type indices are encoded as signed LEB33.
        result = 0
        for i in range(5):
            b = self.byte()
            result |= (b & 127) << (7 * i)
            if b < 128:
                if b & 64 or result > 0xffffffff:
                    raise Invalid('unsupported negative value type/index')
                return result
        raise Invalid('oversized type index')

    def external(self):
        tag = self.byte()
        if tag in (1, 4, 5):
            self.uint()
        elif tag == 3:
            bound = self.byte()
            if bound == 0:
                self.uint()
            elif bound != 1:
                raise Invalid('type bound')
        else:
            raise Invalid('unsupported external kind')

    def alias(self):
        sort = self.byte()
        if sort not in (3, 5):
            raise Invalid('alias sort')
        target = self.byte()
        if target == 0:
            self.uint()
            self.name()
        elif target == 2 and sort == 3:
            self.uint()
            self.uint()
        else:
            raise Invalid('alias target')

    def declaration(self, component):
        tag = self.byte()
        if tag == 1:
            self.type()
        elif tag == 2:
            self.alias()
        elif tag == 4 or tag == 3 and component:
            self.named()
            self.external()
        else:
            raise Invalid('unsupported type declaration')

    def label_type(self):
        self.name()
        self.valtype()

    def type(self):
        self.depth += 1
        if self.depth > 48:
            raise Invalid('type depth')
        tag = self.byte()
        self.shared['types'][hex(tag)] += 1
        if tag in (0x41, 0x42):
            self.vector(lambda: self.declaration(tag == 0x41))
        elif tag == 0x40:
            self.vector(self.label_type)
            result = self.byte()
            if result == 0:
                self.valtype()
            elif result == 1:
                self.expect(0)
            else:
                raise Invalid('result list')
        elif 0x73 <= tag <= 0x7f:
            pass
        elif tag in (0x72,):
            self.vector(self.label_type)
        elif tag == 0x71:
            def case():
                self.name()
                self.option(self.valtype)
                self.expect(0)
            self.vector(case)
        elif tag in (0x70, 0x6b):
            self.valtype()
        elif tag == 0x6f:
            self.vector(self.valtype)
        elif tag in (0x6e, 0x6d):
            self.vector(self.name)
        elif tag == 0x6a:
            self.option(self.valtype)
            self.option(self.valtype)
        elif tag in (0x69, 0x68):
            self.uint()
        else:
            raise Invalid('unsupported type tag ' + hex(tag))
        self.depth -= 1

    def done(self):
        if self.pos != len(self.raw):
            raise Invalid('unparsed bytes')


def review(raw):
    if not raw.startswith(b'\0asm\x0d\0\x01\0'):
        raise Invalid('component header')
    outer = Reader(raw)
    outer.pos = 8
    sections = []
    exports = []
    custom = []
    def export(r):
        name = r.named()
        r.expect(3)  # Export only types, never functions or instances.
        index = r.uint()
        r.expect(0)  # No optional extern type annotation in this artifact.
        exports.append({'name': name, 'type_index': index})
    while outer.pos < len(raw):
        if len(sections) >= 10000:
            raise Invalid('section budget')
        start = outer.pos
        tag = outer.byte()
        size = outer.uint()
        end = outer.pos + size
        if end > len(raw):
            raise Invalid('section bounds')
        r = Reader(raw[outer.pos:end], outer.shared)
        if tag == 7:
            r.vector(r.type)
        elif tag == 11:
            r.vector(lambda: export(r))
        elif tag == 0:
            name = r.name()
            if name == 'package-docs':
                r.expect(0)
                payload = r.raw[r.pos:]
                # JSON data only. No markdown renderer, scripts or object hooks.
                try:
                    docs = json.loads(payload.decode('utf-8'))
                except (UnicodeError, ValueError, RecursionError):
                    raise Invalid('invalid docs JSON')
                stack = [(docs, 0)]
                seen = 0
                while stack:
                    value, depth = stack.pop()
                    seen += 1
                    if depth > 32 or seen > 10000:
                        raise Invalid('docs node/depth budget')
                    if isinstance(value, dict):
                        stack.extend((v, depth + 1) for v in value.values())
                    elif isinstance(value, list):
                        stack.extend((v, depth + 1) for v in value)
                if not isinstance(docs, dict):
                    raise Invalid('docs type')
                outer.shared['strings'].append(payload.decode('utf-8'))
                r.pos = len(r.raw)
            elif name == 'producers':
                def field():
                    r.name()
                    r.vector(lambda: (r.name(), r.name()))
                r.vector(field)
            else:
                raise Invalid('unknown custom payload')
            custom.append(name)
        else:
            raise Invalid('non-declaration section ' + str(tag))
        r.done()
        sections.append({'offset': start, 'id': tag, 'end_offset': end})
        outer.pos = end
    return {'sections': sections, 'exports': exports, 'custom_sections': custom,
            'type_counts': dict(outer.shared['types']), 'nodes': outer.shared['nodes'],
            'strings': outer.shared['strings'], 'all_bytes_accounted_for': True,
            'target_executed': False}
