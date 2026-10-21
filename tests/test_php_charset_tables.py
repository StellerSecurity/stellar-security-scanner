import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scanner'))
import content_guard as guard

PATH = 'pint!vendor/symfony/polyfill-iconv/Resources/charset/from.cp437.php'
HEADER = b'<?php\nnamespace _HumbugBox123;\nstatic $data = array('
TAIL = b');\n$result =& $data;\nunset($data);\nreturn $result;\n'
TABLE = HEADER + b"'\x00' => '\x00', '\xff' => '\xc2\xa0', 0 => '0', '\\\\' => '\\\\'" + TAIL


class CharsetTables(unittest.TestCase):
    def test_raw_byte_literals_are_inspected_without_execution(self):
        value = guard.php_charset_table(PATH, TABLE)
        self.assertIn("'\\x00' => '\\x00'", value)
        self.assertIn("'\\xff' => '\\xc2\\xa0'", value)
        scan = guard.Inspector()
        scan.content(PATH, TABLE)
        self.assertEqual(scan.report('a'*40, 'fixture')['status'], 'passed')
        self.assertEqual(scan.files_scanned, 1)

    def test_added_code_and_expressions_fail_closed(self):
        cases = [TABLE+b"system('payload');", TABLE.replace(b"0 => '0'",b"0 => system('id')"),
                 TABLE.replace(b'unset($data);',b'eval($data);'),
                 TABLE.replace(b'return $result;',b'return include $result;'),
                 TABLE.replace(b"'\xff'",b'"${payload()}"')]
        for data in cases:
            self.assertIsNone(guard.php_charset_table(PATH, data))
            scan = guard.Inspector(); scan.content(PATH,data)
            self.assertNotEqual(scan.report('a'*40,'fixture')['status'],'passed')

    def test_wrong_path_and_arbitrary_binary_are_not_accepted(self):
        self.assertIsNone(guard.php_charset_table('other.php',TABLE))
        self.assertIsNone(guard.php_charset_table(PATH,b'\x00garbage'))

    def test_escapes_truncation_and_limits_are_strict(self):
        for data in [TABLE[:-5],TABLE.replace(b"0 => '0'",b"0 => '\\q'"),
                     TABLE.replace(b"0 => '0'",b"0 => '"+b'x'*33+b"'"),TABLE+b' '*1048576]:
            self.assertIsNone(guard.php_charset_table(PATH,data))


if __name__ == '__main__':
    unittest.main()
