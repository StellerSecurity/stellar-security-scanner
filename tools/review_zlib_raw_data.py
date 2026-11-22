"""Review a checksum-bound raw regression corpus without running crate code."""
import argparse
from collections import Counter
import hashlib
import io
import json
from pathlib import Path
import re
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scanner'))
import content_guard as guard

ARCHIVE_SHA = 'b268e58e7c693d7c271f93ffc4ba3b380412554231c85bf61ca7af91042a4112'
SOURCE_SHA = 'b0f9f7a61e89ce66eb7f5fdb03164f985f8e4d0f1c54890d56bf57d03c299cb5'
COMMIT = '0254e07204884bfc902d6ebb68c8b703d0ea49cf'
MEMBER, SIZE, CHECKSUM = guard.REVIEWED_ZLIB_RAW_DATA[0]
BLOB_SHA = '2b937a7f43ee323e096b319e7a0269c47bca53a4'


def inspect_archive(raw):
    if len(raw) > 8 * 1024**2 or hashlib.sha256(raw).hexdigest() != ARCHIVE_SHA:
        raise ValueError('exact reviewed zlib-rs archive required')
    selected, seen, total = {}, set(), 0
    wanted = {MEMBER, 'zlib-rs-0.6.8/src/deflate.rs', 'zlib-rs-0.6.8/Cargo.toml'}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
        for member in archive:
            total += member.size
            if member.name in seen or len(seen) >= 4096 or total > 32 * 1024**2:
                raise ValueError('archive review bounds')
            seen.add(member.name)
            if member.name in wanted:
                if not member.isfile() or member.size > 2 * 1024**2:
                    raise ValueError('regular bounded source/data input required')
                selected[member.name] = archive.extractfile(member).read(member.size + 1)
    if set(selected) != wanted:
        raise ValueError('review inputs missing')
    data = selected[MEMBER]
    source = selected['zlib-rs-0.6.8/src/deflate.rs']
    manifest = selected['zlib-rs-0.6.8/Cargo.toml']
    if (len(data) != SIZE or hashlib.sha256(data).hexdigest() != CHECKSUM or
            hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest() != BLOB_SHA or
            hashlib.sha256(source).hexdigest() != SOURCE_SHA):
        raise ValueError('exact data and consuming source identities required')
    if (b'build = false\n' not in manifest or b'#[cfg(test)]\nmod test {' not in source or
            source.count(b'inflate_buf_error.dat') != 1):
        raise ValueError('reviewed test-only consumption context changed')
    projections = guard.reviewed_zlib_raw_texts(MEMBER, data)
    if projections is None or len(projections[0]) != len(data):
        raise ValueError('complete raw ASCII projection required')
    inspector = guard.Inspector()
    for index, text in enumerate(projections):
        inspector.inspect_text(MEMBER, text, counted=index == 0)
    inspection = inspector.report(COMMIT, 'exact-raw-regression-data-projections')
    if inspection['status'] != 'passed' or inspection['findings'] or inspection['gaps']:
        raise ValueError('raw data projections failed content inspection')
    magic = (b'MZ', b'\x7fELF', b'PK\x03\x04', b'%PDF', b'#!', b'\0asm', b'\xd0\xcf\x11\xe0')
    if any(data.find(value) >= 0 for value in magic):
        raise ValueError('unexpected embedded executable/archive/document marker')
    return dict(schema=1, package='zlib-rs', version='0.6.8', source_commit=COMMIT,
                archive_sha256=ARCHIVE_SHA, consumer_source_sha256=SOURCE_SHA,
                reader_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                member=MEMBER, bytes=len(data), sha256=CHECKSUM, official_git_blob_sha1=BLOB_SHA,
                byte_histogram={str(k): v for k, v in sorted(Counter(data).items())},
                ascii_bytes_reviewed=len(data), distinct_bytes=len(set(data)),
                printable_runs=len(re.findall(rb'[ -~]{5,}', data)),
                projection_sha256=[hashlib.sha256(text.encode()).hexdigest() for text in projections],
                inspection=inspection, target_executed=False, full_package_clearance=False,
                consuming_context='Only cfg(test) insufficient_compress_space: compress_slice input and round-trip comparison; no interpreter, document renderer, loader or application runtime include.',
                other_inputs_cleared=False,
                limitations=['No generic ASCII-with-controls exception.',
                             'No PDF/CFB parser or native code clearance. The separate paper-100k.pdf fragment is outside this raw-data review and requires its own independent review.',
                             'Absence of magic bytes alone is not a safety proof; exact source identity and test-only consumption were independently reviewed.'],
                source_url='https://github.com/trifectatechfoundation/zlib-rs/tree/'+COMMIT+'/zlib-rs/src/deflate/test-data')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('archive', type=Path)
    args = parser.parse_args()
    if args.archive.is_symlink() or args.archive.stat().st_size > 8 * 1024**2:
        raise ValueError('bounded local reviewed archive required')
    print(json.dumps(inspect_archive(args.archive.read_bytes()), indent=2))
