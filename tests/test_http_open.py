"""HTTP setup is not evidence of reading local browser credential files."""
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scanner'))
import source_guard_v2 as guard


class HttpOpenTests(unittest.TestCase):
    def rules(self, source):
        return {r['rule'] for r in guard.behavior_rules('fixture.js', source)}

    def test_http_open_does_not_mean_file_read(self):
        source = "const xhr = new XMLHttpRequest(); xhr.open('GET', url); fetch(url); // cookies"
        self.assertNotIn('credential-access-and-network-review', self.rules(source))

    def test_actual_file_read_still_requires_review(self):
        source = "const xhr = new XMLHttpRequest(); xhr.open('GET', url); fetch(url); fs.readFileSync('Cookies');"
        self.assertIn('credential-access-and-network-review', self.rules(source))

    def test_axios_style_configured_http_method(self):
        source = "var request = new XMLHttpRequest(); var cookies = {}; request.open(config.method.toUpperCase(), buildURL(url), true); fetch(url);"
        self.assertNotIn('credential-access-and-network-review', self.rules(source))

    def test_string_and_comment_cannot_supply_constructor_binding(self):
        for declaration in ("'const xhr = new XMLHttpRequest();';", "/* const xhr = new XMLHttpRequest(); */", "// const xhr = new XMLHttpRequest();\n"):
            source = declaration + "xhr.open('GET', url); fetch(url); // Cookies"
            self.assertIn('credential-access-and-network-review', self.rules(source))

    def test_template_syntax_is_conservatively_reviewed(self):
        source = "const x = `${payload}`; const xhr = new XMLHttpRequest(); xhr.open('GET', url); fetch(url); // Cookies"
        self.assertIn('credential-access-and-network-review', self.rules(source))

    def test_alias_or_other_receiver_use_keeps_review(self):
        for operation in ('configure(xhr);', 'const other = xhr;', 'xhr.open = reader;', 'xhr[method] = reader;'):
            source = "const xhr = new XMLHttpRequest(); " + operation + "xhr.open('GET', url); fetch(url); // Cookies"
            self.assertIn('credential-access-and-network-review', self.rules(source))

    def test_strong_execution_detection_remains(self):
        # Construct inert JavaScript test data; this string is never executed.
        callback = 'eval'
        source = f"const xhr = new XMLHttpRequest(); xhr.open('GET', url); fetch(url).then({callback});"
        self.assertIn('remote-response-evaluation', self.rules(source))

    def test_regex_literal_cannot_supply_constructor_binding(self):
        source = "const pattern = /const xhr = new XMLHttpRequest();/; xhr.open(config.method, url); fetch(url); // Cookies"
        self.assertIn('credential-access-and-network-review', self.rules(source))

    def test_overridden_constructor_keeps_review(self):
        source = "XMLHttpRequest = FileReader; const xhr = new XMLHttpRequest(); xhr.open(config.method, url); fetch(url); // Cookies"
        self.assertIn('credential-access-and-network-review', self.rules(source))

    def test_unknown_open_still_requires_review(self):
        for call in ("open('Cookies')", "store.open('Cookies')", "fs.open('Cookies')"):
            self.assertIn('credential-access-and-network-review', self.rules(call + '; fetch(url);'))

    def test_reassigned_receiver_still_requires_review(self):
        source = "let xhr = new XMLHttpRequest(); xhr = fs; xhr.open('Cookies'); fetch(url);"
        self.assertIn('credential-access-and-network-review', self.rules(source))

    def test_overridden_method_still_requires_review(self):
        source = "const xhr = new XMLHttpRequest(); xhr.open = fs.open; xhr.open('Cookies'); fetch(url);"
        self.assertIn('credential-access-and-network-review', self.rules(source))

    def test_http_open_does_not_suppress_other_open(self):
        source = "const xhr = new XMLHttpRequest(); xhr.open('GET', url); open('Cookies'); fetch(url);"
        self.assertIn('credential-access-and-network-review', self.rules(source))

    def test_no_http_method_literal_keeps_review(self):
        source = "const xhr = new XMLHttpRequest(); xhr.open(method, url); fetch(url); // Cookies"
        self.assertIn('credential-access-and-network-review', self.rules(source))

    def test_redeclaration_still_requires_review(self):
        source = "var xhr = new XMLHttpRequest(); function f(xhr) { xhr.open('GET', url); } fetch(url); // Cookies"
        self.assertIn('credential-access-and-network-review', self.rules(source))


if __name__ == '__main__':
    unittest.main()
