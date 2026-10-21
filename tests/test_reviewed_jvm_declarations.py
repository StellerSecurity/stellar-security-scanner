"""Exact reviewed declarations never grant trust to another class or archive."""
import hashlib
import io
import json
from pathlib import Path
import sys
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scanner'))
import content_guard as content
from test_content_coverage import engine

ROOT = Path(__file__).resolve().parents[1]


def validate_declaration_bytes(raw):
    """Independently consume the entire reviewed format, including annotations.

    This deliberately rejects ordinary classes. It is evidence for six fixed
    fixtures, not a general rule for clearing arbitrary JVM binaries.
    """
    offset, pool = 0, [None]
    def take(size):
        nonlocal offset
        if offset + size > len(raw):
            raise ValueError('truncated')
        value = raw[offset:offset + size]; offset += size
        return value
    def u1(): return int.from_bytes(take(1), 'big')
    def u2(): return int.from_bytes(take(2), 'big')
    def u4(): return int.from_bytes(take(4), 'big')
    def string(index):
        if not 0 < index < len(pool) or pool[index][0] != 1:
            raise ValueError('invalid UTF constant')
        return pool[index][1]
    def class_name(index):
        if not 0 < index < len(pool) or pool[index][0] != 7:
            raise ValueError('invalid class constant')
        return string(pool[index][1])
    if take(4) != b'\xca\xfe\xba\xbe' or u2() != 0 or u2() != 49:
        raise ValueError('unexpected header')
    count = u2()
    for _ in range(1, count):
        tag = u1()
        if tag == 1: pool.append((tag, content.java_modified_utf8(take(u2()))))
        elif tag == 7: pool.append((tag, u2()))
        else: raise ValueError('unexpected constant tag')
    for tag, value in pool[1:]:
        if tag == 7: string(value)
    flags, name, parent = u2(), class_name(u2()), class_name(u2())
    if flags not in (0x0601, 0x2601) or parent != 'java/lang/Object':
        raise ValueError('unexpected type')
    interfaces = [class_name(u2()) for _ in range(u2())]
    if interfaces != ([] if name == 'javax/inject/Provider' else ['java/lang/annotation/Annotation']):
        raise ValueError('unexpected interface')
    if u2() != 0: raise ValueError('fields present')
    def annotation(depth=0):
        if depth > 8: raise ValueError('depth')
        string(u2())
        for _ in range(u2()):
            string(u2()); element(depth + 1)
    def element(depth=0):
        if depth > 8: raise ValueError('depth')
        tag = chr(u1())
        if tag == 's': string(u2())
        elif tag == 'e': string(u2()); string(u2())
        elif tag == '[':
            for _ in range(u2()): element(depth + 1)
        else: raise ValueError('unexpected annotation element')
    def attributes(allowed):
        seen = set()
        for _ in range(u2()):
            attr, size = string(u2()), u4()
            end = offset + size
            if attr not in allowed or attr in seen: raise ValueError('unknown attribute')
            seen.add(attr)
            if attr in ('SourceFile', 'Signature'): string(u2())
            elif attr == 'AnnotationDefault': element()
            elif attr == 'RuntimeVisibleAnnotations':
                for _ in range(u2()): annotation()
            if offset != end: raise ValueError('attribute length')
    methods = []
    for _ in range(u2()):
        if u2() != 0x0401: raise ValueError('non-abstract method')
        method, descriptor = string(u2()), string(u2())
        if method.startswith('<'): raise ValueError('initializer')
        methods.append((method, descriptor))
        attributes({'Signature', 'AnnotationDefault'})
    expected = {'javax/inject/Named': [('value', '()Ljava/lang/String;')],
                'javax/inject/Provider': [('get', '()Ljava/lang/Object;')]}.get(name, [])
    if methods != expected: raise ValueError('unexpected methods')
    attributes({'SourceFile', 'Signature', 'RuntimeVisibleAnnotations'})
    if offset != len(raw): raise ValueError('trailing content')


class ReviewedJvmDeclarations(unittest.TestCase):
    def setUp(self):
        self.files = {name: bytes.fromhex(raw) for name, raw in json.loads(
            (ROOT / 'tests/fixtures/javax-inject-1-declarations.json').read_text()).items()}

    def scan(self, name, raw):
        scanner = content.Inspector(engine=engine())
        scanner.content(name, raw)
        return scanner.report('a'*40, 'test')

    def jar(self, extra):
        result = io.BytesIO()
        with zipfile.ZipFile(result, 'w') as archive:
            for name, raw in {**self.files, **extra}.items():
                archive.writestr(name, raw)
        return result.getvalue()

    def test_each_review_record_is_bound_to_the_complete_fixture(self):
        review = json.loads((ROOT / 'reviews/javax-inject-1-declarations.json').read_text())
        self.assertEqual(6, len(review['classes']))
        self.assertEqual(set(self.files), {row['path'] for row in review['classes']})
        for row in review['classes']:
            raw = self.files[row['path']]
            self.assertEqual(row['bytes'], len(raw))
            self.assertEqual(row['sha256'], hashlib.sha256(raw).hexdigest())
            self.assertTrue(content.reviewed_jvm_declaration(raw))
            validate_declaration_bytes(raw)
            self.assertEqual(0, row['code_attributes'] + row['native_methods'] + row['initializers'])
            result = self.scan(row['path'], raw)
            self.assertEqual('passed', result['status'])
            self.assertEqual(1, result['files_scanned'])
            self.assertEqual('exact-jvm-declaration-review:javax-inject-1', result['exclusions'][0]['reason'])

    def test_every_single_byte_mutation_loses_review(self):
        for name, raw in self.files.items():
            for index in range(len(raw)):
                changed = raw[:index] + bytes([raw[index] ^ 1]) + raw[index + 1:]
                self.assertFalse(content.reviewed_jvm_declaration(changed), (name, index))
            for changed in (raw[:-1], raw + b'payload', b'payload' + raw):
                self.assertFalse(content.reviewed_jvm_declaration(changed))

    def test_reviewed_name_does_not_authorize_different_contents(self):
        for name in self.files:
            raw = b'\xca\xfe\xba\xbe\0\0\0=' + b'\0' * 40
            result = self.scan(name, raw)
            self.assertEqual('incomplete', result['status'])
            self.assertFalse(result['exclusions'])

    def test_all_other_archive_members_still_scanned(self):
        result = self.scan('javax.inject-1.jar', self.jar({'loader.js': b'reverse shell'}))
        self.assertEqual('blocked', result['status'])
        self.assertTrue(any(f['malware'] for f in result['findings']))
        self.assertEqual(7, result['files_scanned'])

    def test_unreviewed_class_and_native_in_same_jar_still_block_coverage(self):
        extra = {'Other.class': b'\xca\xfe\xba\xbe\0\0', 'lib.so': b'\x7fELF' + b'\0' * 24}
        result = self.scan('javax.inject-1.jar', self.jar(extra))
        self.assertEqual('incomplete', result['status'])
        self.assertEqual(2, sum(g['reason'] == 'executable-binary-needs-independent-review' for g in result['gaps']))
        self.assertEqual(6, len(result['exclusions']))

    def test_exact_contents_cannot_hide_an_appended_payload(self):
        result = self.scan('Provider.class', self.files['javax/inject/Provider.class'] + b'reverse shell')
        self.assertNotEqual('passed', result['status'])
        self.assertFalse(result['exclusions'])


if __name__ == '__main__':
    unittest.main()
