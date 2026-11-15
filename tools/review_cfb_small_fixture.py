"""Exact small malformed CFB regression datum; never open it as an Office file.

All 1,049 original bytes were read as header/directory fragments in the source
review. This is not a validator or waiver for arbitrary malformed documents.
"""
import hashlib
import re
import struct

MEMBER = 'cfb-0.14.0/tests/infinite_loops_fuzzed/loop_in_open_1'
SHA256 = 'b587ad479a6bc028b26c93c9d53bce38d1d08f1a2294426e6c10003664158873'


def describe(raw):
    if len(raw) != 1049 or raw[:8] != bytes.fromhex('d0cf11e0a1b11ae1'):
        raise ValueError('exact CFB fixture framing required')
    minor, major, endian, shift, mini = struct.unpack_from('<5H', raw, 24)
    if (minor, major, endian, shift, mini) != (62, 3, 65534, 9, 6):
        raise ValueError('unexpected CFB header version/sector sizes')
    header = {offset: struct.unpack_from('<I', raw, offset)[0]
              for offset in (40, 44, 48, 56, 60, 64, 68, 72, 76)}
    expected = {40: 0, 44: 1, 48: 1, 56: 4096, 60: 2097154,
                64: 512, 68: 0, 72: 4294966799, 76: 255}
    if header != expected:
        raise ValueError('fuzzed allocation metadata differs')
    sector = 1 << shift
    directory_start = (header[48] + 1) * sector
    if directory_start != 1024 or len(raw) - directory_start != 25:
        raise ValueError('directory truncation differs')
    if raw[directory_start:] != b'\0' + b'\xff' * 24:
        raise ValueError('partial directory fragment differs')
    strings = [s.decode('utf-16-le') for s in re.findall(rb'(?:[ -~]\x00){3,}', raw)]
    if strings != ['VAA', 'ThisWorkbo', 'hisWorkbo', 'VAA']:
        raise ValueError('unexplained directory-name fragment')
    if re.search(rb'[ -~]{3,}', raw):
        raise ValueError('unexplained ASCII text')
    return dict(bytes=len(raw), sector_bytes=sector, full_sectors=1,
                declared_fat_sector=255, declared_directory_sector=1,
                directory_bytes_available=25, directory_entry_bytes_required=128,
                declared_minifat_start=header[60], declared_difat_sectors=header[72],
                regions=[dict(offset=a, end=b, sha256=hashlib.sha256(raw[a:b]).hexdigest())
                         for a, b in ((0, 512), (512, 1024), (1024, 1049))],
                name_fragments=strings, valid_compound_file=False,
                resolved_macro_stream=False, compound_file_validation_complete=False,
                target_executed=False)


def review(path, raw):
    if path.rsplit('!', 1)[-1] != MEMBER or hashlib.sha256(raw).hexdigest() != SHA256:
        raise ValueError('unreviewed fixture identity')
    result = describe(raw)
    result['exact_regression_datum_reviewed'] = True
    result['safe_to_open_in_office'] = False
    return result
