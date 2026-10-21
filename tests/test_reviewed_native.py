import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scanner'))
import content_guard as guard

class ReviewedNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = bytes.fromhex((Path(__file__).parent/'fixtures/symfony-hiddeninput.hex').read_text())
    def test_reviewed_bytes_are_recorded(self):
        scanner=guard.Inspector();scanner.content('pkg/Resources/bin/hiddeninput.exe',self.raw)
        self.assertEqual([],scanner.gaps)
        self.assertEqual(1,scanner.files_scanned)
        self.assertEqual('exact-native-code-review:symfony-hiddeninput-20120325',scanner.exclusions[0]['reason'])
    def test_mutated_truncated_and_appended_bytes_stay_incomplete(self):
        for raw in (self.raw[:-1],self.raw+b'payload',self.raw[:1050]+bytes([self.raw[1050]^1])+self.raw[1051:]):
            scanner=guard.Inspector();scanner.content('pkg/Resources/bin/hiddeninput.exe',raw)
            self.assertEqual('executable-binary-needs-independent-review',scanner.gaps[0]['reason'])
    def test_review_does_not_cover_another_member(self):
        scanner=guard.Inspector();scanner.content('pkg/other.exe',self.raw)
        self.assertTrue(scanner.gaps)
    def test_review_does_not_cover_adjacent_binary(self):
        scanner=guard.Inspector();scanner.content('pkg/Resources/bin/hiddeninput.exe',self.raw)
        scanner.content('pkg/Resources/bin/second.exe',b'MZ'+b'\0'*100)
        self.assertEqual(1,len(scanner.gaps))
