"""Bounded FST-v3 set-data inspection; no library or target execution."""
import struct
import hashlib
COMMON = tuple((ord(c) for c in ['t', 'e', '/', 'o', 'a', 's', 'r', 'i', 'p', 'c', 'n', 'w', '.', 'h', 'l', 'm', '-', 'd', 'u', '0', '1', '2', 'g', '=', ':', 'b', 'f', '3', 'y', '5', '&', '_', '4', 'v', '9', '6', '7', '8', 'k', '%', '?', 'x', 'C', 'D', 'A', 'S', 'F', 'I', 'B', 'E', 'j', 'P', 'T', 'z', 'R', 'N', 'M', '+', 'L', 'O', 'q', 'H', 'G']))


class Invalid(ValueError):
    pass


def need(ok, why):
    if not ok:
        raise Invalid(why)


def checksum(raw):
    crc = 0xffffffff
    for b in raw:
        crc ^= b
        for _ in range(8):
            crc = crc >> 1 ^ (0x82f63b78 if crc & 1 else 0)
    crc ^= 0xffffffff
    return (crc >> 15 | crc << 17) + 0xa282ead8 & 0xffffffff


def review(raw):
    """Account for every FST-v3 byte and enumerate only four-byte scalars.

    Nodes are stored backwards; packed deltas may point only to complete
    earlier nodes or the empty-final sentinel. Nonzero transducer outputs,
    orphan bytes/states, inconsistent indexes and non-scalar keys fail.
    """
    need(36 <= len(raw) <= 1024 * 1024, 'size budget')
    (version, kind) = struct.unpack_from('<QQ', raw)
    need(version == 3 and kind == 0, 'set format/version')
    (count, root, check) = struct.unpack_from('<QQI', raw, len(raw) - 20)
    need(0 < count <= 0x110000 and root == len(raw) - 21 and (checksum(raw[:-4]) == check), 'footer/checksum')
    nodes = {}
    at = root

    def byte(p):
        need(16 <= p <= root, 'node byte bounds')
        return raw[p]

    def number(p, n):
        need(0 <= n <= 8 and 16 <= p <= p + n <= root + 1, 'packed integer bounds')
        return int.from_bytes(raw[p:p + n], 'little')
    while at >= 16:
        need(len(nodes) < 100000, 'node budget')
        flag = byte(at)
        if flag & 128:
            common = flag & 63
            label = COMMON[common - 1] if common else byte(at - 1)
            label_bytes = 0 if common else 1
            if flag & 64:
                start = at - label_bytes
                target = start - 1
            else:
                sizes_at = at - label_bytes - 1
                sizes = byte(sizes_at)
                (width, output) = (sizes >> 4, sizes & 15)
                need(1 <= width <= 8 and output == 0, 'non-set output/transition width')
                start = sizes_at - width
                delta = number(start, width)
                target = start - delta if delta else 0
            final = False
            edges = [(label, target)]
        else:
            final = bool(flag & 64)
            n = flag & 63
            extra = int(n == 0)
            if extra:
                n = byte(at - 1)
                if n == 1:
                    n = 256
            sizes_at = at - extra - 1
            sizes = byte(sizes_at)
            (width, output) = (sizes >> 4, sizes & 15)
            need(0 <= width <= 8 and output == 0 and (n == 0 or width > 0), 'non-set output/width')
            index_bytes = 256 if n > 32 else 0
            labels_end = sizes_at - index_bytes
            start = labels_end - n - n * width
            need(start >= 16, 'node start')
            labels = [byte(labels_end - i - 1) for i in range(n)]
            need(all((a < b for (a, b) in zip(labels, labels[1:]))), 'unsorted/duplicate transitions')
            if index_bytes:
                expected = bytearray([255]) * 256
                for (i, label) in enumerate(labels):
                    expected[label] = i
                need(raw[labels_end:sizes_at] == expected, 'transition index differs from labels')
            edges = []
            for (i, label) in enumerate(labels):
                delta = number(labels_end - n - (i + 1) * width, width)
                edges.append((label, start - delta if delta else 0))
        need(16 <= start <= at and all((target == 0 or 16 <= target < start for (_, target) in edges)), 'forward/invalid transition')
        need(final or edges, 'dead non-final state')
        nodes[at] = (start, final, edges)
        at = start - 1
    need(at == 15, 'unaccounted body bytes')
    for (_, _, edges) in nodes.values():
        need(all((target == 0 or target in nodes for (_, target) in edges)), 'transition inside a node')
    stack = [(root, b'')]
    visited = set()
    keys = 0
    steps = 0
    digest = hashlib.sha256()
    (lowest, highest) = (0x110000, 0)
    while stack:
        (addr, prefix) = stack.pop()
        steps += 1
        need(steps <= 5 * 0x110000 and len(prefix) <= 4, 'enumeration budget/depth')
        if addr == 0:
            (final, edges) = (True, [])
        else:
            visited.add(addr)
            (_, final, edges) = nodes[addr]
        if final:
            need(len(prefix) == 4, 'key not four-byte scalar')
            value = int.from_bytes(prefix, 'big')
            need(value <= 0x10ffff and (not 0xd800 <= value <= 0xdfff), 'invalid Unicode scalar')
            keys += 1
            need(keys <= count, 'excess keys')
            digest.update(value.to_bytes(4, 'big'))
            lowest = min(lowest, value)
            highest = max(highest, value)
        for (label, target) in reversed(edges):
            stack.append((target, prefix + bytes([label])))
    need(keys == count and len(visited) == len(nodes), 'footer count/orphan node')
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), states=len(nodes), transitions=sum((len(v[2]) for v in nodes.values())), keys=keys, lowest_scalar=lowest, highest_scalar=highest, ordered_scalar_sha256=digest.hexdigest(), crc32c_verified=True, all_bytes_accounted_for=True, target_executed=False)


def table_witness(source):
    """Parse literal integers, never Rust code, then compare a second encoding."""
    import re
    need(len(source) < 1024 * 1024, 'source witness budget')
    constants = {}
    for key in ('ASCII_START', 'ASCII_CONTINUE', 'CHUNK', 'ZERO_START', 'ZERO_CONTINUE', 'LEAF_START', 'LEAF_CONTINUE'):
        found = re.search('\\bconst ' + key + ': (?:u128|usize) = (0x[0-9a-fA-F]+|[0-9]+);', source)
        need(found is not None, 'missing literal constant')
        constants[key] = int(found[1], 0)
    arrays = {}
    for key in ('TRIE_START', 'TRIE_CONTINUE', 'LEAF'):
        found = re.search('\\bstatic ' + key + ': Align(?:8|64)<\\[u8; ([0-9]+)\\]> = Align(?:8|64)\\(\\[([^\\]]*)\\]\\);', source)
        need(found is not None and int(found[1]) <= 65536, 'array declaration')
        tokens = found[2].split(',')
        need(not tokens[-1].strip(), 'array terminator')
        values = []
        for token in tokens[:-1]:
            token = token.strip()
            need(re.fullmatch('0x[0-9a-fA-F]+|[0-9]+', token), 'nonliteral array value')
            values.append(int(token, 0))
        need(len(values) == int(found[1]) and all((0 <= x <= 255 for x in values)), 'array count/range')
        arrays[key] = values
    need(constants['CHUNK'] == 64, 'unsupported chunk size')
    result = {}
    for kind in ('START', 'CONTINUE'):
        trie = arrays['TRIE_' + kind]
        zero = constants['ZERO_' + kind]
        need(0 <= zero < len(trie), 'zero fallback index')
        digest = hashlib.sha256()
        count = 0
        for value in range(0x110000):
            if 0xd800 <= value <= 0xdfff:
                continue
            if value < 128:
                member = bool(constants['ASCII_' + kind] & 1 << value)
            else:
                at = value // 512
                chunk = trie[at] if at < len(trie) else trie[zero]
                offset = constants['LEAF_' + kind] + chunk * 32 + value // 8 % 64
                need(0 <= offset < len(arrays['LEAF']), 'leaf index')
                member = bool(arrays['LEAF'][offset] >> value % 8 & 1)
            if member:
                count += 1
                digest.update(value.to_bytes(4, 'big'))
        result[kind.lower()] = dict(keys=count, ordered_scalar_sha256=digest.hexdigest())
    return result
