"""Bounded CFB allocation inventory, not a document/macro security verdict.

Parse only bytes in memory. Never recover by guessing allocation pointers, open
an Office application, or equate a broken chain with harmless contents.
"""
import hashlib
import struct

FREE = 0xffffffff
END = 0xfffffffe
FAT = 0xfffffffd
DIFAT = 0xfffffffc


class Invalid(ValueError):
    pass


def require(test, reason):
    if not test:
        raise Invalid(reason)


def words(raw):
    require(len(raw) % 4 == 0, 'unaligned allocation array')
    return list(struct.unpack('<' + 'I' * (len(raw) // 4), raw))


def chain(start, table, sector_count):
    """Return only a complete, unique, bounded chain; no partial-success result."""
    result = []
    seen = set()
    while start != END:
        require(0 <= start < sector_count and start < len(table), 'chain outside allocation table/data')
        require(start not in seen, 'allocation cycle')
        require(len(result) < sector_count, 'allocation budget')
        seen.add(start)
        result.append(start)
        start = table[start]
    return result


class Reader:
    def __init__(self, raw):
        require(512 <= len(raw) <= 2 * 1024 * 1024, 'input byte limit')
        require(raw[:8] == bytes.fromhex('d0cf11e0a1b11ae1'), 'CFB signature')
        minor, major, endian, shift, mini = struct.unpack_from('<5H', raw, 24)
        require(endian == 0xfffe and mini == 6, 'unsupported byte order/mini-sector size')
        require((major, shift) in ((3, 9), (4, 12)), 'unsupported CFB version/sector size')
        self.raw = raw
        self.major = major
        self.sector_size = 1 << shift
        require(len(raw) >= self.sector_size, 'truncated header sector')
        self.count = (len(raw) - self.sector_size) // self.sector_size
        self.owners = {}
        self.streams = []
        self.entries = []
        self.minifat = []
        self.mini_stream = b''
        self.mini_owners = {}
        self.fat = []
        require(struct.unpack_from('<I', raw, 56)[0] == 4096, 'unsupported mini-stream cutoff')

    def sector(self, number):
        require(0 <= number < self.count, 'sector outside complete input sectors')
        offset = (number + 1) * self.sector_size
        return self.raw[offset:offset+self.sector_size]

    def claim(self, ids, owner):
        require(len(set(ids)) == len(ids), 'duplicate sector claim')
        for number in ids:
            require(0 <= number < self.count, 'claimed sector outside complete input sectors')
            require(number not in self.owners, 'overlapping sector ownership')
        self.owners.update((number, owner) for number in ids)

    def read_regular(self, start, size, owner):
        require(0 <= size <= len(self.raw), 'declared stream size limit')
        ids = chain(start, self.fat, self.count)
        require(len(ids) == (size + self.sector_size - 1) // self.sector_size,
                'stream chain length differs from declared size')
        self.claim(ids, owner)
        return b''.join(self.sector(i) for i in ids)[:size]

    def load_tables(self):
        raw = self.raw
        fat_count, directory = struct.unpack_from('<II', raw, 44)
        difat_start, difat_count = struct.unpack_from('<II', raw, 68)
        require(0 < fat_count <= self.count and difat_count <= self.count, 'allocation sector count limit')
        fat_ids = [v for v in words(raw[76:512]) if v != FREE]
        next_id = difat_start
        seen = set()
        for _ in range(difat_count):
            require(next_id not in seen, 'DIFAT cycle')
            seen.add(next_id)
            self.claim([next_id], 'DIFAT')
            entries = words(self.sector(next_id))
            fat_ids.extend(v for v in entries[:-1] if v != FREE)
            next_id = entries[-1]
        require(next_id == END, 'DIFAT terminator/count mismatch')
        require(len(fat_ids) == fat_count and len(set(fat_ids)) == fat_count, 'FAT count/uniqueness')
        self.claim(fat_ids, 'FAT')
        self.fat = [v for i in fat_ids for v in words(self.sector(i))]
        require(len(self.fat) >= self.count, 'FAT does not cover data sectors')
        require(all(self.fat[i] == FAT for i in fat_ids), 'FAT sector marker')
        require(all(self.fat[i] == DIFAT for i in seen), 'DIFAT sector marker')
        ids = chain(directory, self.fat, self.count)
        require(ids, 'missing directory chain')
        self.claim(ids, 'directory')
        return b''.join(self.sector(i) for i in ids)

    def load_directory(self, data):
        for offset in range(0, len(data), 128):
            entry = data[offset:offset+128]
            name_bytes = struct.unpack_from('<H', entry, 64)[0]
            kind = entry[66]
            if kind == 0:
                continue
            require(kind in (1, 2, 5), 'invalid directory entry kind')
            require(2 <= name_bytes <= 64 and name_bytes % 2 == 0, 'directory name length')
            require(entry[name_bytes-2:name_bytes] == b'\0\0', 'directory name terminator')
            try:
                name = entry[:name_bytes-2].decode('utf-16-le')
            except UnicodeDecodeError as error:
                raise Invalid('directory name encoding') from error
            start = struct.unpack_from('<I', entry, 116)[0]
            size = struct.unpack_from('<Q', entry, 120)[0]
            require(self.major != 3 or size <= 0x80000000, 'v3 stream size')
            self.entries.append(dict(id=offset // 128, name=name, kind=kind, start=start, bytes=size))
        require(self.entries and self.entries[0]['id'] == 0 and self.entries[0]['kind'] == 5,
                'root directory entry missing')

    def load_streams(self):
        root = self.entries[0]
        self.mini_stream = self.read_regular(root['start'], root['bytes'], 'mini-stream')
        mini_start, mini_count = struct.unpack_from('<II', self.raw, 60)
        require(mini_count <= self.count, 'mini-FAT sector count limit')
        self.minifat = words(self.read_regular(mini_start, mini_count * self.sector_size, 'mini-FAT'))
        for entry in self.entries[1:]:
            if entry['kind'] != 2:
                continue
            size = entry['bytes']
            if size >= 4096:
                data = self.read_regular(entry['start'], size, 'stream:' + str(entry['id']))
            else:
                ids = chain(entry['start'], self.minifat, len(self.mini_stream) // 64)
                require(len(ids) == (size + 63) // 64, 'mini-stream chain length differs from size')
                require(not any(i in self.mini_owners for i in ids), 'overlapping mini-sector ownership')
                self.mini_owners.update((i, entry['id']) for i in ids)
                data = b''.join(self.mini_stream[i*64:(i+1)*64] for i in ids)[:size]
            self.streams.append(dict(id=entry['id'], name=entry['name'], bytes=len(data),
                                     sha256=hashlib.sha256(data).hexdigest()))

    def inventory(self):
        errors = []
        try:
            self.load_directory(self.load_tables())
            self.load_streams()
        except Invalid as error:
            errors.append(str(error))
        unresolved = [i for i in range(self.count) if i not in self.owners]
        return dict(bytes=len(self.raw), sector_bytes=self.sector_size,
                    complete_sectors=self.count, trailing_bytes=len(self.raw) % self.sector_size,
                    declared_entries=self.entries, resolved_streams=self.streams,
                    claimed_sector_count=len(self.owners), unresolved_sector_ids=unresolved,
                    allocation_errors=errors, structural_walk_finished=not errors,
                    directory_tree_validated=False, unused_slack_reviewed=False,
                    macro_or_pcode_review_complete=False, compound_file_cleared=False,
                    target_executed=False)
