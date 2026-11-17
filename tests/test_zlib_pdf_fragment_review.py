"""Exact clipped test data must not allow unknown PDFs, font programs or tails."""
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'scanner'))
import review_zlib_pdf_fragment as reader
import content_guard as guard
from test_content_coverage import engine


def make_index(values):
    if not values:
        return b'\0\0'
    offsets = [1]
    for value in values:
        offsets.append(offsets[-1]+len(value))
    return len(values).to_bytes(2,'big') + b'\1' + bytes(offsets) + b''.join(values)


def number(value):
    if value == 391:
        return bytes((248,27))
    if not -107 <= value <= 107:
        raise ValueError('synthetic fixture size')
    return bytes((value+139,))


def synthetic_cff():
    header = bytes((1,0,4,1))
    names = make_index([b'Synthetic'])
    strings = make_index([b'Family'])
    subrs = make_index([])
    glyphs = make_index([b'\x0e', bytes((140,140,21,140,141,5,14)),
                         bytes((140,140,21,140,140,140,140,30,14))])
    charset = bytes((0,0,1,0,15))
    def top(start, chars, private):
        return (number(391)+bytes((12,22))+b''.join(number(n) for n in (-1,-2,3,4))+bytes((5,))+
                number(start)+bytes((15,))+number(chars)+bytes((17,))+number(0)+number(private)+bytes((18,)))
    placeholder = make_index([top(0,0,0)])
    start = len(header+names+placeholder+strings+subrs)
    chars = start+len(charset)
    private = chars+len(glyphs)
    top_index = make_index([top(start,chars,private)])
    assert len(top_index) == len(placeholder)
    return header+names+top_index+strings+subrs+charset+glyphs


class FontReviewTests(unittest.TestCase):
    def test_complete_synthetic_font_has_only_bounded_path_glyphs(self):
        data = synthetic_cff()
        report = reader.cff(data)
        self.assertEqual(report['bytes_accounted'], len(data))
        self.assertEqual(report['charset_sids'], [0,1,15])
        self.assertEqual(len(report['glyphs']), 3)
        self.assertFalse(report['embedded_postscript'])
        self.assertFalse(report['rendered'])

    def test_index_bounds_offsets_and_truncation_reject(self):
        self.assertEqual(reader.index(make_index([b'x']),0), ([b'x'],6))
        for raw in (b'\0', b'\0\1', b'\0\1\0', b'\0\1\1\0\2x', b'\0\1\1\1\3x'):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    reader.index(raw,0)

    def test_font_trailing_bytes_and_offsets_are_not_unexamined(self):
        raw = synthetic_cff()
        for changed in (raw+b'X', raw[:-1], bytes((2,))+raw[1:]):
            with self.assertRaises(ValueError):
                reader.cff(changed)

    def test_subroutines_escapes_bad_stacks_and_missing_terminal_reject(self):
        for raw in (b'\x0a\x0e', b'\x1d\x0e', b'\x0c\x15\x0e', b'\x05\x0e',
                    b'\x0eX', bytes((140,21,14)), bytes((140,140,21))):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    reader.charstring(raw)

    def test_dictionary_postscript_operators_are_rejected(self):
        for op in ((12,21), (12,20), (12,23), (19,)):
            with self.assertRaises(ValueError):
                reader.dictionary(bytes((139,*op)))


class PdfLexingTests(unittest.TestCase):
    def test_nested_escaped_and_octal_strings_are_fully_covered(self):
        raw = b'(one\\040(two)\\)three) Tj <2e> % comment\n'
        report = reader.pdf_tokens(raw, {'Tj'})
        self.assertEqual(report['literal_strings'], [b'one (two))three', b'.'])
        self.assertEqual(report['bytes_accounted'], len(raw))

    def test_active_escaped_names_and_unknown_operators_reject(self):
        for data in (b'/JavaScript', b'/#4a#53', b'/OpenAction', b'/Launch', b'1 2 system', b'exec'):
            with self.assertRaises(ValueError):
                reader.pdf_tokens(data, {'Tj'})

    def test_unclosed_strings_hex_and_unknown_delimiters_reject(self):
        for data in (b'(', b'(\\', b'<zz>', b'<2e', b'}'):
            with self.assertRaises(ValueError):
                reader.pdf_tokens(data, set())


class ExactFragmentBindingTests(unittest.TestCase):
    def synthetic_input(self, plaintext=b'benign text'):
        compressed = zlib.compress(plaintext)
        raw = b'A'*18643 + b'\n' + compressed
        profile = ('synthetic/clipped.pdf',len(raw),hashlib.sha256(raw).hexdigest())
        streams = ((18644,len(compressed),len(plaintext),hashlib.sha256(plaintext).hexdigest(),True,'text'),)
        return raw, profile, streams

    def test_unknown_paths_changed_bytes_lengths_and_unconsumed_tails_reject(self):
        raw, profile, streams = self.synthetic_input()
        with patch.object(guard,'REVIEWED_ZLIB_PDF_INPUT',profile), patch.object(guard,'REVIEWED_ZLIB_PDF_STREAMS',streams):
            self.assertIsNotNone(guard.reviewed_zlib_pdf_texts(profile[0],raw))
            for path,data in ((profile[0]+'.other',raw),('other/'+profile[0],raw),(profile[0],raw+b'X'),(profile[0],b'B'+raw[1:])):
                self.assertIsNone(guard.reviewed_zlib_pdf_texts(path,data))
        changed = raw+b'X'
        changed_profile = (profile[0],len(changed),hashlib.sha256(changed).hexdigest())
        changed_stream = ((streams[0][0],streams[0][1]+1,*streams[0][2:]),)
        with patch.object(guard,'REVIEWED_ZLIB_PDF_INPUT',changed_profile), patch.object(guard,'REVIEWED_ZLIB_PDF_STREAMS',changed_stream):
            self.assertIsNone(guard.reviewed_zlib_pdf_texts(profile[0],changed))

    def test_decoded_malware_is_not_hidden_by_a_data_review(self):
        raw, profile, streams = self.synthetic_input(b'reverse shell')
        with patch.object(guard,'REVIEWED_ZLIB_PDF_INPUT',profile), patch.object(guard,'REVIEWED_ZLIB_PDF_STREAMS',streams):
            scanner = guard.Inspector(engine=engine())
            scanner.content(profile[0],raw)
            report = scanner.report('a'*40,'test')
            self.assertEqual(report['status'],'blocked')
            self.assertTrue(any(f['malware'] for f in report['findings']))

    def test_truncated_stream_state_and_unknown_payload_roles_reject(self):
        raw, profile, streams = self.synthetic_input()
        for changed in ((*streams[0][:4],False,'text'), (*streams[0][:5],'unknown')):
            with patch.object(guard,'REVIEWED_ZLIB_PDF_INPUT',profile), patch.object(guard,'REVIEWED_ZLIB_PDF_STREAMS',(changed,)):
                self.assertIsNone(guard.reviewed_zlib_pdf_texts(profile[0],raw))

    def test_evidence_matches_all_present_bytes_and_each_decoded_stream(self):
        report = json.loads((ROOT/'reviews/zlib-pdf-fragment-data.json').read_bytes())
        self.assertEqual(report['reader_sha256'],hashlib.sha256((ROOT/'tools/review_zlib_pdf_fragment.py').read_bytes()).hexdigest())
        self.assertEqual((report['member'],report['bytes'],report['sha256']),guard.REVIEWED_ZLIB_PDF_INPUT)
        self.assertTrue(report['all_present_input_bytes_accounted'])
        self.assertEqual(sum(row['end']-row['start'] for row in report['ranges']),102400)
        self.assertEqual(len(report['streams']),6)
        self.assertEqual([(s['compressed_bytes'],s['decoded_bytes'],s['decoded_sha256'],s['complete_zlib_stream']) for s in report['streams']],
                         [(s[1],s[2],s[3],s[4]) for s in guard.REVIEWED_ZLIB_PDF_STREAMS])
        self.assertEqual(report['streams'][4]['review']['bytes_accounted'],121)
        self.assertEqual(len(report['streams'][4]['review']['glyphs']),3)
        self.assertFalse(report['streams'][5]['complete_zlib_stream'])
        self.assertEqual(report['inspection']['status'],'passed')
        self.assertFalse(report['complete_pdf'])
        self.assertFalse(report['target_executed'])


if __name__ == '__main__':
    unittest.main()
