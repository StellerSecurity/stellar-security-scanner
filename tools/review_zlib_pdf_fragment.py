"""Bounded structural review of one compression-test fragment; never render it."""
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import tarfile
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scanner'))
import content_guard as guard

CHECKSUM = '60f73a051b7ca35bfec44734b2eed7736cb5c0b7f728beb7b97ade6c5e44849b'
MEMBER = 'zlib-rs-0.6.8/src/deflate/test-data/paper-100k.pdf'
ARCHIVE_SHA = 'b268e58e7c693d7c271f93ffc4ba3b380412554231c85bf61ca7af91042a4112'


def integer(data, at):
    if at >= len(data):
        raise ValueError('CFF integer bounds')
    byte = data[at]
    if 32 <= byte <= 246:
        return byte - 139, at + 1
    if 247 <= byte <= 254 and at + 1 < len(data):
        value = (byte - (247 if byte <= 250 else 251)) * 256 + data[at+1] + 108
        return value if byte <= 250 else -value, at + 2
    if byte == 28 and at + 3 <= len(data):
        return struct.unpack_from('>h', data, at+1)[0], at + 3
    if byte == 29 and at + 5 <= len(data):
        return struct.unpack_from('>i', data, at+1)[0], at + 5
    raise ValueError('unsupported CFF integer')


def index(data, at):
    if at + 2 > len(data):
        raise ValueError('CFF INDEX bounds')
    count = int.from_bytes(data[at:at+2], 'big')
    at += 2
    if not count:
        return [], at
    if count > 8 or at >= len(data) or data[at] not in (1, 2, 3, 4):
        raise ValueError('bounded CFF INDEX declaration required')
    width = data[at]
    at += 1
    if at + (count+1)*width > len(data):
        raise ValueError('CFF INDEX offsets truncated')
    offsets = [int.from_bytes(data[at+i*width:at+(i+1)*width], 'big') for i in range(count+1)]
    at += (count+1)*width
    if offsets[0] != 1 or offsets != sorted(offsets) or at + offsets[-1] - 1 > len(data):
        raise ValueError('CFF INDEX offsets invalid')
    return [data[at+offsets[i]-1:at+offsets[i+1]-1] for i in range(count)], at + offsets[-1] - 1


def dictionary(data):
    at, stack, entries = 0, [], {}
    while at < len(data):
        if data[at] >= 32 or data[at] in (28, 29):
            value, at = integer(data, at)
            if not -32768 <= value <= 32767 or len(stack) >= 16:
                raise ValueError('CFF dictionary operand bounds')
            stack.append(value)
            continue
        op = (data[at],)
        at += 1
        if op == (12,):
            if at >= len(data):
                raise ValueError('truncated CFF dictionary escape')
            op = (12, data[at])
            at += 1
        if op not in ((12, 22), (5,), (15,), (17,), (18,)) or op in entries:
            raise ValueError('unreviewed CFF dictionary operator')
        entries[op], stack = stack, []
    if stack or set(entries) != {(12,22), (5,), (15,), (17,), (18,)}:
        raise ValueError('incomplete CFF dictionary')
    return entries


def charstring(data):
    if not data or len(data) > 256:
        raise ValueError('bounded Type 2 glyph required')
    at, stack, commands, moved = 0, [], [], False
    while at < len(data):
        byte = data[at]
        if byte >= 32 or byte == 28:
            value, at = integer(data, at)
            if not -32768 <= value <= 32767 or len(stack) >= 48:
                raise ValueError('Type 2 operand bounds')
            stack.append(value)
            continue
        at += 1
        if byte == 14:
            if stack or at != len(data):
                raise ValueError('Type 2 terminal operands or trailing bytes')
            commands.append(dict(operator='endchar', operands=[]))
            return commands
        if byte == 21:
            if len(stack) not in ((2,) if moved else (2, 3)):
                raise ValueError('Type 2 rmoveto arity')
            moved = True
        elif byte == 5:
            if not moved or len(stack) < 2 or len(stack) % 2:
                raise ValueError('Type 2 rlineto arity/context')
        elif byte == 30:
            if not moved or len(stack) < 4 or len(stack) % 4:
                raise ValueError('Type 2 vhcurveto arity/context')
        else:
            raise ValueError('unreviewed Type 2 operator; subroutines/escapes are forbidden')
        commands.append(dict(operator={21:'rmoveto', 5:'rlineto', 30:'vhcurveto'}[byte], operands=stack))
        stack = []
    raise ValueError('Type 2 glyph missing endchar')


def cff(data):
    if not 20 <= len(data) <= 1024 or data[:4] != bytes((1, 0, 4, 1)):
        raise ValueError('reviewed CFF v1 header required')
    names, at = index(data, 4)
    top, at = index(data, at)
    strings, at = index(data, at)
    global_subrs, at = index(data, at)
    if (len(names) != 1 or len(top) != 1 or len(strings) != 1 or global_subrs or
            not all(re.fullmatch(rb'[A-Za-z0-9+.-]{1,64}', name) for name in names+strings)):
        raise ValueError('single bounded CFF font without global subroutines required')
    entries = dictionary(top[0])
    if entries[(12,22)] != [391] or entries[(15,)] != [at] or len(entries[(17,)]) != 1 or entries[(18,)] != [0, len(data)]:
        raise ValueError('CFF offsets/private dictionary or string binding changed')
    box = entries[(5,)]
    if len(box) != 4 or box[0] > box[2] or box[1] > box[3]:
        raise ValueError('CFF font bounding box')
    chars_at = entries[(17,)][0]
    if data[at:at+1] != b'\0' or chars_at != at + 5 or chars_at > len(data):
        raise ValueError('exact three-glyph charset layout required')
    sids = struct.unpack_from('>HH', data, at+1)
    if sids != (1, 15):
        raise ValueError('unexpected CFF charset identifiers')
    glyphs, end = index(data, chars_at)
    if len(glyphs) != 3 or end != len(data):
        raise ValueError('CFF trailing/unaccounted bytes or glyph count')
    commands = [charstring(glyph) for glyph in glyphs]
    return dict(bytes_accounted=len(data), font_name=names[0].decode(), bbox=box,
                charset_sids=[0, *sids], glyphs=commands, global_subroutines=0,
                private_dictionary_bytes=0, embedded_postscript=False, rendered=False)


def pdf_tokens(data, allowed):
    """Lex all bytes, including strings, without a PDF/PostScript interpreter."""
    at, operators, strings, names = 0, [], [], []
    delimiters = b'\0\t\n\x0c\r ()<>[]{}/%'
    while at < len(data):
        byte = data[at]
        if byte in b'\0\t\n\x0c\r ':
            at += 1
            continue
        if byte == 37:
            while at < len(data) and data[at] not in b'\r\n':
                at += 1
            continue
        if byte == 40:
            at += 1
            depth, value = 1, bytearray()
            while at < len(data) and depth:
                byte = data[at]
                at += 1
                if byte == 92:
                    if at >= len(data):
                        raise ValueError('truncated PDF literal escape')
                    escaped = data[at]
                    at += 1
                    if 48 <= escaped <= 55:
                        digits = bytes((escaped,))
                        while len(digits) < 3 and at < len(data) and 48 <= data[at] <= 55:
                            digits += data[at:at+1]
                            at += 1
                        value.append(int(digits, 8) & 255)
                    elif escaped == 13:
                        if data[at:at+1] == b'\n':
                            at += 1
                    elif escaped != 10:
                        value.extend({110:b'\n',114:b'\r',116:b'\t',98:b'\b',102:b'\x0c'}.get(escaped, bytes((escaped,))))
                elif byte == 40:
                    depth += 1
                    value.append(byte)
                elif byte == 41:
                    depth -= 1
                    if depth:
                        value.append(byte)
                else:
                    value.append(byte)
                if depth > 16 or len(value) > 65536:
                    raise ValueError('PDF string bounds')
            if depth:
                raise ValueError('unclosed PDF literal')
            strings.append(bytes(value))
            continue
        if data[at:at+2] in (b'<<', b'>>'):
            at += 2
            continue
        if byte in b'[]':
            at += 1
            continue
        if byte == 60:
            end = data.find(b'>', at+1)
            if end < 0 or end-at > 65536:
                raise ValueError('PDF hex-string bounds')
            hexdata = re.sub(rb'\s+', b'', data[at+1:end])
            if re.fullmatch(rb'[0-9a-fA-F]*', hexdata) is None:
                raise ValueError('invalid PDF hex string')
            strings.append(bytes.fromhex((hexdata+b'0' if len(hexdata)%2 else hexdata).decode()))
            at = end+1
            continue
        is_name = byte == 47
        if is_name:
            at += 1
        start = at
        while at < len(data) and data[at] not in delimiters:
            at += 1
        if at == start:
            raise ValueError('unreviewed PDF lexical byte')
        token = data[start:at]
        if is_name:
            token = re.sub(rb'#([0-9a-fA-F]{2})', lambda match:bytes((int(match[1],16),)), token)
            if token in (b'JS',b'JavaScript',b'OpenAction',b'AA',b'Launch',b'EmbeddedFile',b'RichMedia',b'XFA'):
                raise ValueError('active PDF name rejected')
            names.append(token)
        elif re.fullmatch(rb'[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)', token):
            pass
        elif token.decode('ascii') in allowed:
            operators.append(token.decode())
        else:
            raise ValueError('unreviewed PDF/CMap operator: '+repr(token))
    return dict(operators=sorted(set(operators)), names=sorted({x.decode('ascii') for x in names}),
                literal_strings=strings, bytes_accounted=len(data))


def review(data):
    if len(data) != 102400 or hashlib.sha256(data).hexdigest() != CHECKSUM:
        raise ValueError('exact reviewed fragment required')
    blob = hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
    if blob != 'b3325e4a2bb578419d6c7fa412aaa78d493ff274':
        raise ValueError('official Git blob identity changed')
    pattern = rb'([0-9]+) 0 obj<<(/Length ([0-9]+)[^>]*?)>>stream\r\n'
    expected = [(3,19109,8934), (6,28415,7551), (9,36411,4318),
                (11,40855,214), (12,41153,117), (14,41647,409790)]
    matches = list(re.finditer(pattern, data))
    if [(int(m[1]),m.end(),int(m[3])) for m in matches] != expected:
        raise ValueError('fragment stream graph changed')
    inspector = guard.Inspector()
    inspector.inspect_text(MEMBER+'!xmp-prefix', data[:18643].decode('utf-8'))
    cursor, ranges, streams = 18643, [(0,18643,'xmp-prefix')], []
    for match in matches:
        number, start, length = int(match[1]), match.end(), int(match[3])
        structural = data[cursor:start]
        grammar = pdf_tokens(structural, {'endstream','endobj','obj','R','stream'})
        inspector.inspect_text(MEMBER+'!structure', structural.decode('ascii'))
        for value in grammar.pop('literal_strings', []):
            inspector.inspect_text(MEMBER+'!structural-string', value.decode('latin1'))
        ranges.append((cursor,start,'structure'))
        stop = min(len(data), start+length)
        compressed = data[start:stop]
        decoder = zlib.decompressobj()
        decoded = decoder.decompress(compressed, 16*1024**2+1)
        if len(decoded) > 16*1024**2 or decoder.unconsumed_tail or decoder.unused_data or decoder.eof != (number != 14):
            raise ValueError('fragment decompression bounds/tail/EOF changed')
        details = {}
        if number in (3,6,9):
            details = pdf_tokens(decoded, {'gs','BT','ET','Tf','Tm','rg','Tc','Tw','TJ','TD','T*','Tj','q','Q','cm','Do','w','m','l','S','re','f','W','n','CS','cs','SCN','scn','g','k','J','j','d','G','RG','K','h','c','v','y','s','B','B*','b','b*','f*','W*','Tr','Ts','Tz','TL','Td','ri','i','sh'})
            inspector.inspect_text(MEMBER+'!page-'+str(number), decoded.decode('latin1'))
        elif number == 11:
            details = pdf_tokens(decoded, {'findresource','begin','dict','def','begincmap','begincodespacerange','endcodespacerange','beginbfchar','endbfchar','endcmap','CMapName','currentdict','defineresource','pop','end'})
            inspector.inspect_text(MEMBER+'!cmap', decoded.decode('ascii'))
        elif number == 12:
            details = cff(decoded)
        else:
            if (match[2] != b'/Length 409790/Filter/FlateDecode/Width 2032/Height 1612/BitsPerComponent 8/ColorSpace/DeviceRGB/Type/XObject/Subtype/Image' or
                    len(decoded) > 2032*1612*3):
                raise ValueError('exact partial RGB raster declaration required')
            details = dict(width=2032,height=1612,components=3,bits_per_component=8,
                           declared_raster_bytes=2032*1612*3, complete_raster=False, rendered=False)
        for value in details.pop('literal_strings', []):
            inspector.inspect_text(MEMBER+'!decoded-string', value.decode('latin1'))
        ranges.append((start,stop,'compressed-stream-'+str(number)))
        streams.append(dict(object=number,compressed_bytes=len(compressed),declared_compressed_bytes=length,
                            decoded_bytes=len(decoded),decoded_sha256=hashlib.sha256(decoded).hexdigest(),
                            complete_zlib_stream=decoder.eof,all_present_compressed_bytes_consumed=True,
                            structural_review=grammar,review=details))
        cursor = stop
    if cursor != len(data) or any(a[1] != b[0] for a,b in zip(ranges,ranges[1:])):
        raise ValueError('unaccounted fragment bytes')
    inspection = inspector.report('0254e07204884bfc902d6ebb68c8b703d0ea49cf','exact-pdf-fragment-data-review')
    if inspection['status'] != 'passed' or inspection['findings'] or inspection['gaps']:
        raise ValueError('decoded fragment text inspection failed: '+json.dumps(inspection))
    return dict(schema=1,member=MEMBER,bytes=len(data),sha256=CHECKSUM,archive_sha256=ARCHIVE_SHA,official_git_blob_sha1=blob,
                reader_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                ranges=[dict(start=a,end=b,role=role) for a,b,role in ranges],streams=streams,
                all_present_input_bytes_accounted=True,inspection=inspection,
                complete_pdf=False,complete_image=False,target_executed=False,rendered=False,
                native_code_cleared=False,full_package_clearance=False,
                sources=['https://adobe-type-tools.github.io/font-tech-notes/pdfs/5176.CFF.pdf',
                         'https://adobe-type-tools.github.io/font-tech-notes/pdfs/5177.Type2.pdf',
                         'https://opensource.adobe.com/dc-acrobat-sdk-docs/pdfstandards/pdfreference1.7old.pdf'],
                limitations=['This exact incomplete compression/checksum-test fragment only; no generic PDF or truncated-stream clearance.',
                             'The final RGB stream is intentionally incomplete. All 60753 present bytes are consumed; no missing image suffix is invented or accepted for other files.',
                             'No PDF viewer, font engine, target crate, JavaScript or PostScript interpreter is executed.'])


if __name__ == '__main__':
    path = Path(sys.argv[1])
    if path.is_symlink() or path.stat().st_size > 8*1024**2 or hashlib.sha256(path.read_bytes()).hexdigest() != ARCHIVE_SHA:
        raise ValueError('exact local reviewed archive required')
    with tarfile.open(path) as archive:
        info = archive.getmember(MEMBER)
        if not info.isfile() or info.size != 102400:
            raise ValueError('exact regular corpus member required')
        data = archive.extractfile(info).read(102401)
        consumers = []
        expected = {
            'avx2':'7aaa38f49d28d2a2259356e99538a77d4e945ab64822fa500fa7d1ed3c03740f',
            'avx512':'66c7c7764d6c39ce40af65af38d247ace48fec16bf1d0a6e39c1c2f15710e248',
            'avx512_vnni':'8b3d068c0d456581966fad39e7f1befa98be5b80e95365ebd65330cdafc9ea2c',
            'lsx':'5e13e8ad0844ed11966a45bb4556db3e896bb29235d84182d2f7afdd605586ca',
            'neon':'6c7d5b4680cdbb68c9bcd5392edda612d918cb92b2cebd5c23d18c912ca464c7',
        }
        for arch, checksum in expected.items():
            name = 'zlib-rs-0.6.8/src/adler32/'+arch+'.rs'
            member = archive.getmember(name)
            if not member.isfile() or member.size > 1024**2:
                raise ValueError('bounded regular consuming source required')
            source = archive.extractfile(member).read(member.size+1)
            at = source.find(b'paper-100k.pdf')
            if (hashlib.sha256(source).hexdigest() != checksum or source.count(b'paper-100k.pdf') != 1 or
                    b'#[test]' not in source[max(0,at-200):at]):
                raise ValueError('reviewed checksum-test consumption source changed')
            consumers.append(dict(path=name,sha256=checksum,references=1,test_only=True))
    result = review(data)
    result['consumer_sources'] = consumers
    result['consuming_context'] = 'Five cfg(test) large_input functions pass these bytes only to Adler-32 checksum implementations; no document/font renderer or interpreter.'
    print(json.dumps(result,indent=2))
