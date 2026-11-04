"""Static CMD launch-wrapper regression tests; no payload is executed."""
import base64
import gzip
import unittest

import operations
import ops_extended
from command_analyzer import analyze_command, _wrapped_powershell


class CommandWrapperRegression(unittest.TestCase):
    def test_supported_wrappers(self):
        for prefix in ('%COMSPEC% /b /c start /b /min ',
                       'cmd.exe /d /s /c ',
                       'cmd /c start "" /min ',
                       '%comspec% /c start /wait /b '):
            with self.subTest(prefix=prefix):
                text = prefix + 'powershell -enc YQBiAGMA'
                offset, child = _wrapped_powershell(text)
                self.assertEqual(text[offset:], child)
                self.assertEqual(offset, len(prefix))

    def test_non_invocations_are_not_promoted(self):
        for text in ('echo powershell -enc YQBiAGMA',
                     'cmd /c echo powershell -enc YQBiAGMA',
                     '%COMSPEC% /c type powershell -enc YQBiAGMA',
                     'cmd /c start "powershell -enc YQBiAGMA"',
                     'cmd /c start /unknown powershell -enc YQBiAGMA',
                     'tool.exe powershell -enc YQBiAGMA'):
            with self.subTest(text=text):
                self.assertIsNone(_wrapped_powershell(text))

    def test_nested_compression_and_evidence_offsets(self):
        # Inert text: a URL is evidence only, never contacted.
        inner = "Write-Output 'https://example.invalid/static-analysis-fixture'"
        compressed = base64.b64encode(gzip.compress(inner.encode(), mtime=0)).decode()
        script = '$s=[Convert]::FromBase64String("' + compressed + '"); # GzipStream'
        encoded = base64.b64encode(script.encode('utf-16le')).decode()
        prefix = '%COMSPEC% /b /c start /b /min '
        text = prefix + 'powershell -nop -w hidden -encodedcommand ' + encoded
        result = analyze_command(text)
        parsed = result['parsed_structure']
        self.assertEqual(parsed['executable'], '%COMSPEC%')
        self.assertTrue(parsed['evidence_preserved'])
        self.assertEqual(parsed['nested_interpreter'], 'powershell')
        self.assertEqual(parsed['nested_interpreter_offset'], len(prefix))
        self.assertFalse(result['needs_choice'])
        self.assertIn('https://example.invalid/static-analysis-fixture', result['iocs']['urls'])
        self.assertTrue(result['decode_chains'])
        for span in result['identified_payloads']:
            if span['confidence'] >= .8:
                self.assertEqual(text[span['offset']:span['offset'] + len(span['span'])], span['span'])

    def test_benign_and_file_operands(self):
        for text in ('cmd /c dir', 'certutil -decode input.b64 output.exe',
                     'ls -la /home/user/Documents'):
            with self.subTest(text=text):
                self.assertEqual(analyze_command(text)['decode_chains'], [])


if __name__ == '__main__':
    unittest.main()
