"""Inspect exact regression input DATA, never fdeflate or downloaded code."""
import hashlib
import zlib


class Invalid(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise Invalid(message)


class Bits:
    def __init__(self, raw):
        require(len(raw) <= 1024, 'bitstream size')
        self.raw = raw
        self.pos = 0

    def read(self, n):
        require(0 <= n <= 16 and self.pos + n <= len(self.raw) * 8, 'bit bounds')
        value = 0
        for i in range(n):
            value |= ((self.raw[self.pos // 8] >> (self.pos % 8)) & 1) << i
            self.pos += 1
        return value


def wrapper(raw):
    require(6 <= len(raw) <= 1024, 'fixture size')
    cmf, flag = raw[:2]
    require(cmf & 15 == 8 and cmf >> 4 <= 7 and (cmf * 256 + flag) % 31 == 0
            and not flag & 32, 'zlib header/dictionary')
    return raw[2:-4], int.from_bytes(raw[-4:], 'big')


def raw_payload(raw):
    body, declared_adler = wrapper(raw)
    decoder = zlib.decompressobj(-15)
    try:
        decoded = decoder.decompress(body, 1025)
    except zlib.error as exc:
        raise Invalid('invalid raw DEFLATE') from exc
    require(len(decoded) <= 1024 and decoder.eof and not decoder.unused_data
            and not decoder.unconsumed_tail, 'DEFLATE size/end/tail')
    return decoded, declared_adler


def missing_eob(raw):
    body, declared_adler = wrapper(raw)
    bits = Bits(body)
    require(bits.read(1) == 1 and bits.read(2) == 2, 'final dynamic block required')
    literals, distances, codes = bits.read(5) + 257, bits.read(5) + 1, bits.read(4) + 4
    require(literals <= 286 and distances <= 32 and codes <= 19, 'alphabet bounds')
    order = (16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15)
    lengths = [0] * 19
    for i in range(codes):
        lengths[order[i]] = bits.read(3)
    require(sum(1 << (7 - width) for width in lengths if width) == 128,
            'incomplete/oversubscribed code-length tree')
    counts = [lengths.count(i) for i in range(8)]
    counts[0] = 0
    next_code = {}
    code = 0
    for width in range(1, 8):
        code = (code + counts[width - 1]) * 2
        next_code[width] = code
    table = {}
    for symbol, width in enumerate(lengths):
        if width:
            code = next_code[width]
            next_code[width] += 1
            reverse = int(format(code, '0%db' % width)[::-1], 2)
            table[(width, reverse)] = symbol

    def symbol():
        value = 0
        for width in range(1, 8):
            value |= bits.read(1) << (width - 1)
            if (width, value) in table:
                return table[(width, value)]
        raise Invalid('invalid code-length symbol')

    decoded = []
    while len(decoded) < literals + distances:
        value = symbol()
        if value < 16:
            decoded.append(value)
        elif value == 16:
            require(bool(decoded), 'repeat without predecessor')
            decoded.extend([decoded[-1]] * (bits.read(2) + 3))
        elif value == 17:
            decoded.extend([0] * (bits.read(3) + 3))
        else:
            decoded.extend([0] * (bits.read(7) + 11))
        require(len(decoded) <= literals + distances, 'code-length repeat overflow')
    require(decoded[256] == 0, 'expected missing end-of-block symbol')
    consumed = bits.pos
    remaining = len(body) * 8 - consumed
    require(0 <= remaining <= 64, 'unreviewed remainder')
    require(all(bits.read(1) == 0 for _ in range(remaining)), 'nonzero unreviewed remainder')
    return dict(literal_count=literals, distance_count=distances, code_count=codes,
                header_bits=consumed, zero_remainder_bits=remaining,
                code_lengths_sha256=hashlib.sha256(bytes(decoded)).hexdigest(),
                declared_adler32=declared_adler, expected_error='BadLiteralLengthHuffmanTree',
                all_bytes_accounted_for=True, valid_zlib_stream=False)


def review(raw, kind):
    if kind == 'payload-with-bad-checksum':
        payload, declared = raw_payload(raw)
        actual = zlib.adler32(payload)
        require(len(payload) == 281 and actual == 751299 and declared != actual,
                'source regression output differs')
        require(hashlib.sha256(payload).hexdigest() ==
                'd43cb34069584694314352cbf48255e7a0f78926da4e2f337cf770e0a53744bc',
                'different decoded payload')
        return dict(decoded_bytes=len(payload), decoded_sha256=hashlib.sha256(payload).hexdigest(),
                    decoded_adler32=actual, declared_adler32=declared,
                    valid_zlib_stream=False, raw_deflate_complete=True,
                    all_bytes_accounted_for=True, target_executed=False)
    require(kind == 'missing-eob-zero-tail', 'unknown review kind')
    return dict(missing_eob(raw), target_executed=False)
