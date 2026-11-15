"""Bounded SHA-256 Authenticode integrity evidence, never Windows trust approval.

The public certificate and signature are data only. The caller may use the
existing Node crypto standard library to verify the prepared signature value.
No PE image is loaded, linked or run. Unsupported layouts/algorithms fail.
"""
import base64
import hashlib
import struct


class Invalid(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Invalid(message)


class Der:
    def __init__(self, raw):
        require(len(raw) <= 256 * 1024, 'DER size budget')
        self.raw = raw
        self.nodes = 0

    def read(self, pos=0, end=None, depth=0):
        if end is None:
            end = len(self.raw)
        require(depth <= 64 and self.nodes < 10000 and 0 <= pos < end <= len(self.raw),
                'DER depth/node/bounds budget')
        self.nodes += 1
        start = pos
        tag = self.raw[pos]
        pos += 1
        require(tag & 31 != 31 and pos < end, 'DER tag/header')
        size = self.raw[pos]
        pos += 1
        if size & 128:
            count = size & 127
            require(1 <= count <= 4 and pos + count <= end and self.raw[pos] != 0,
                    'DER length encoding')
            size = int.from_bytes(self.raw[pos:pos+count], 'big')
            pos += count
            require(size >= 128, 'nonminimal DER length')
        require(pos + size <= end, 'DER value bounds')
        children = []
        if tag & 32:
            current = pos
            while current < pos + size:
                child = self.read(current, pos + size, depth + 1)
                children.append(child)
                current = child['end']
        return dict(tag=tag, start=start, value=pos, end=pos+size, children=children)

    def body(self, node):
        return self.raw[node['value']:node['end']]

    def encoded(self, node):
        return self.raw[node['start']:node['end']]

    def oid(self, node):
        require(node['tag'] == 6, 'OID type')
        data = self.body(node)
        require(0 < len(data) <= 64, 'OID size')
        arcs = []
        value = 0
        for byte in data:
            require(not (value == 0 and byte == 128), 'nonminimal OID arc')
            value = value * 128 + (byte & 127)
            require(value <= 2**64, 'OID arc budget')
            if byte < 128:
                arcs.append(value)
                value = 0
        require(bool(arcs) and not data[-1] & 128, 'OID termination')
        first = 0 if arcs[0] < 40 else 1 if arcs[0] < 80 else 2
        return '.'.join(map(str, [first, arcs[0]-first*40] + arcs[1:]))


def image_data(raw):
    require(128 <= len(raw) <= 16 * 1024 * 1024 and raw[:2] == b'MZ', 'PE size/magic')
    pe = int.from_bytes(raw[60:64], 'little')
    require(64 <= pe <= len(raw)-24 and raw[pe:pe+4] == b'PE\0\0', 'PE header bounds')
    machine, count = struct.unpack_from('<HH', raw, pe+4)
    size = struct.unpack_from('<H', raw, pe+20)[0]
    optional = pe + 24
    require(1 <= count <= 96 and optional + size + count*40 <= len(raw), 'PE table bounds')
    magic = struct.unpack_from('<H', raw, optional)[0]
    require(magic in (0x10b, 0x20b), 'PE optional header kind')
    directory = optional + (96 if magic == 0x10b else 112)
    require(directory + 40 <= optional + size, 'PE security directory bounds')
    count_at = optional + (92 if magic == 0x10b else 108)
    require(struct.unpack_from('<I', raw, count_at)[0] >= 5, 'missing certificate directory')
    entry = directory + 32
    cert_at, cert_size = struct.unpack_from('<II', raw, entry)
    header_size = struct.unpack_from('<I', raw, optional+60)[0]
    require(optional+size+count*40 <= header_size <= cert_at and cert_at % 8 == 0,
            'PE header/certificate overlap or alignment')
    require(8 <= cert_size <= 256*1024 and cert_at+cert_size == len(raw),
            'one final certificate table required')
    cert_length, revision, kind = struct.unpack_from('<IHH', raw, cert_at)
    require(revision == 0x200 and kind == 2 and 8 <= cert_length <= cert_size
            and (cert_length+7)//8*8 == cert_size and not any(raw[cert_at+cert_length:]),
            'unsupported certificate record/padding')
    checksum = optional + 64
    digest = hashlib.sha256()
    digest.update(raw[:checksum])
    digest.update(raw[checksum+4:entry])
    digest.update(raw[entry+8:header_size])
    sections = []
    for index in range(count):
        pos = optional + size + index*40
        length, pointer = struct.unpack_from('<II', raw, pos+16)
        if length:
            sections.append((pointer, length))
    end = header_size
    for pointer, length in sorted(sections):
        # Do not guess Microsoft's behavior for exotic gaps/overlaps/overlays.
        require(pointer == end and pointer+length <= cert_at, 'noncontiguous PE sections')
        digest.update(raw[pointer:pointer+length])
        end = pointer + length
    require(end == cert_at, 'unsupported PE overlay')
    return dict(image_sha256=digest.hexdigest(), machine=machine,
                section_count=count, certificate_offset=cert_at,
                certificate_bytes=cert_size), raw[cert_at+8:cert_at+cert_length]


def _prepare(raw):
    info, certificate = image_data(raw)
    der = Der(certificate)
    root = der.read()
    require(root['tag'] == 0x30 and len(root['children']) == 2, 'CMS ContentInfo')
    require(not any(certificate[root['end']:]) and len(certificate)-root['end'] <= 7,
            'CMS nonzero or oversized certificate padding')
    require(der.oid(root['children'][0]) == '1.2.840.113549.1.7.2', 'CMS signedData OID')
    wrapped = root['children'][1]
    require(wrapped['tag'] == 0xa0 and len(wrapped['children']) == 1, 'CMS wrapper')
    signed = wrapped['children'][0]['children']
    require(len(signed) == 5 and signed[3]['tag'] == 0xa0 and signed[4]['tag'] == 0x31,
            'CMS SignedData shape')
    sha256 = '2.16.840.1.101.3.4.2.1'
    require(len(signed[1]['children']) == 1
            and der.oid(signed[1]['children'][0]['children'][0]) == sha256,
            'unsupported CMS digest algorithm')
    encapsulated = signed[2]['children']
    content_oid = '1.3.6.1.4.1.311.2.1.4'
    require(len(encapsulated) == 2 and der.oid(encapsulated[0]) == content_oid
            and len(encapsulated[1]['children']) == 1, 'SPC content shape')
    content = encapsulated[1]['children'][0]
    parts = content['children']
    require(len(parts) == 2 and der.oid(parts[0]['children'][0]) == '1.3.6.1.4.1.311.2.1.15',
            'SPC PE image OID')
    digest_info = parts[1]['children']
    require(len(digest_info) == 2 and der.oid(digest_info[0]['children'][0]) == sha256
            and digest_info[1]['tag'] == 4 and len(der.body(digest_info[1])) == 32,
            'SPC SHA-256 image digest')
    require(der.body(digest_info[1]).hex() == info['image_sha256'], 'signed PE image digest differs')
    require(len(signed[4]['children']) == 1, 'one CMS signer required')
    signer = signed[4]['children'][0]['children']
    require(len(signer) in (6, 7) and signer[3]['tag'] == 0xa0 and signer[5]['tag'] == 4,
            'CMS SignerInfo shape')
    require(der.oid(signer[2]['children'][0]) == sha256
            and der.oid(signer[4]['children'][0]) == '1.2.840.113549.1.1.1',
            'only SHA-256 RSA-PKCS1 signature supported')
    attrs = signer[3]
    values = {}
    encodings = []
    for attr in attrs['children']:
        pair = attr['children']
        require(len(pair) == 2 and pair[1]['tag'] == 0x31, 'signed attribute shape')
        oid = der.oid(pair[0])
        require(oid not in values, 'duplicate signed attribute')
        values[oid] = pair[1]['children']
        encodings.append(der.encoded(attr))
    require(encodings == sorted(encodings), 'noncanonical signed attribute SET')
    require(len(values.get('1.2.840.113549.1.9.3', [])) == 1
            and der.oid(values['1.2.840.113549.1.9.3'][0]) == content_oid, 'signed content type')
    md = values.get('1.2.840.113549.1.9.4', [])
    require(len(md) == 1 and md[0]['tag'] == 4
            and der.body(md[0]) == hashlib.sha256(der.body(content)).digest(),
            'signed PKCS7 content digest differs')
    sid = signer[1]['children']
    require(len(sid) == 2 and sid[1]['tag'] == 2, 'issuer/serial signer identity')
    certs = signed[3]['children']
    require(1 <= len(certs) <= 8, 'certificate count budget')
    matches = []
    for cert in certs:
        fields = cert['children'][0]['children']
        version = 1 if fields[0]['tag'] == 0xa0 else 0
        require(len(fields) >= version+6, 'certificate fields')
        if (der.body(fields[version]) == der.body(sid[1])
                and der.encoded(fields[version+2]) == der.encoded(sid[0])):
            matches.append(cert)
    require(len(matches) == 1, 'ambiguous or missing signer certificate')
    encoded_attrs = der.encoded(attrs)
    signature_data = b'\x31' + encoded_attrs[1:]
    encode = lambda data: base64.b64encode(data).decode('ascii')
    evidence = dict(info, file_bytes=len(raw), file_sha256=hashlib.sha256(raw).hexdigest(),
                    cms_image_digest_matches=True, cms_content_digest_matches=True,
                    root_trust_verified=False, timestamp_verified=False,
                    revocation_checked=False, native_code_cleared=False,
                    target_executed=False)
    public_verification = dict(signer_certificate=encode(der.encoded(matches[0])),
                               certificates=[encode(der.encoded(c)) for c in certs],
                               signed_attributes=encode(signature_data),
                               signature=encode(der.body(signer[5])))
    return evidence, public_verification


def prepare(raw):
    require(isinstance(raw, bytes), 'PE bytes required')
    try:
        return _prepare(raw)
    except (IndexError, KeyError, TypeError, struct.error, OverflowError) as exc:
        raise Invalid('unsupported or malformed CMS structure') from exc
