"""X.509 parsing never confers trust on the certificate issuer or payload."""
import base64
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scanner'))
import content_guard as c
from test_content_coverage import engine
# Public Apple Root CA G3, SHA256 63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179.
CERT = base64.b64decode('MIICQzCCAcmgAwIBAgIILcX8iNLFS5UwCgYIKoZIzj0EAwMwZzEbMBkGA1UEAwwSQXBwbGUgUm9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcNMTQwNDMwMTgxOTA2WhcNMzkwNDMwMTgxOTA2WjBnMRswGQYDVQQDDBJBcHBsZSBSb290IENBIC0gRzMxJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzB2MBAGByqGSM49AgEGBSuBBAAiA2IABJjpLz1AcqTtkyJygRMc3RCV8cWjTnHcFBbZDuWmBSp3ZHtfTjjTuxxEtX/1H7YyYl3J6YRbTzBPEVoA/VhYDKX1DyxNB0cTddqXl5dvMVztK517IDvYuVTZXpmkOlEKMaNCMEAwHQYDVR0OBBYEFLuw3qFYM4iapIqZ3r6966/ayySrMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2gAMGUCMQCD6cHEFl4aXTQY2e3v9GwOAEZLuN+yRhHFD/3meoyhpmvOwgPUnPWTxnS4at+qIxUCMG1mihDK1A3UT82NQz60imOlM27jbdoXt2QfyFMm+YhidDkLF1vLUagM6BgD56KyKA==')

class CertificateTests(unittest.TestCase):
    def test_real_der_certificate(self):
        self.assertTrue(c.x509_certificate_data('certs/root.cer',CERT))
        scanner=c.Inspector(engine=engine());scanner.content('root.cer',CERT)
        self.assertFalse(scanner.gaps)
        self.assertIn('strings-inspected',scanner.exclusions[0]['reason'])
    def test_appended_payload_and_concatenation_rejected(self):
        for raw in (CERT+b'reverse shell',CERT+CERT,CERT[:-1]):
            self.assertFalse(c.x509_certificate_data('root.cer',raw))
            scanner=c.Inspector(engine=engine());scanner.content('root.cer',raw)
            self.assertTrue(scanner.gaps or scanner.findings)
    def test_false_der_and_inflated_outer_length(self):
        bad=bytearray(CERT+b'reverse shell');bad[2:4]=(len(bad)-4).to_bytes(2,'big')
        for raw in (bytes(bad),b'\x30\x03abc',b'\x30\x80\0\0',b'\x30\x81\x03abc'):
            self.assertFalse(c.x509_certificate_data('root.cer',raw))
    def test_suffix_and_size_are_bounded(self):
        self.assertFalse(c.x509_certificate_data('payload.so',CERT))
        self.assertFalse(c.x509_certificate_data('root.cer',CERT+bytes(65536)))
    def test_native_payload_disguised_as_certificate_still_gap(self):
        scanner=c.Inspector(engine=engine());scanner.content('root.cer',b'\x7fELF'+bytes(64))
        self.assertEqual('executable-binary-needs-independent-review',scanner.gaps[0]['reason'])
