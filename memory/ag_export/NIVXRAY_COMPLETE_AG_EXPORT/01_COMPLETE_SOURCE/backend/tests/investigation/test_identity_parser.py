"""Tests for the Identity Parser.

Contracts:
  · Pure, never raises
  · Never mutates input
  · Emits sibling fields prefixed by origin
  · Detects DOMAIN\\User, UPN, Windows SID
  · Skip-list guards URLs, paths, command-lines
  · Vendor-neutral
"""
from __future__ import annotations

from nivxforge.investigation.pipeline.identity_parser import (
    expand_identities,
)
from nivxforge.investigation.pipeline.parser import ParsedInput


def _pi(records):
    return ParsedInput(kind="json", records=records, text=None,
                        diagnostics=[])


class TestIdentityParser:

    def test_domain_user_split(self):
        pi = _pi([{"User": "CORP\\alice"}])
        out = expand_identities(pi)
        rec = out.records[0]
        assert rec["User.username"] == "alice"
        assert rec["User.user_domain"] == "CORP"
        assert rec["User.identity_format"] == "domain_user"
        # Origin retained
        assert rec["User"] == "CORP\\alice"

    def test_upn_split(self):
        pi = _pi([{"user_email": "alice@corp.com"}])
        out = expand_identities(pi)
        rec = out.records[0]
        assert rec["user_email.upn"] == "alice@corp.com"
        assert rec["user_email.username"] == "alice"
        assert rec["user_email.user_domain"] == "corp.com"
        assert rec["user_email.identity_format"] == "upn"

    def test_windows_sid(self):
        sid = "S-1-5-21-1111111111-2222222222-3333333333-1001"
        pi = _pi([{"account_sid": sid}])
        out = expand_identities(pi)
        rec = out.records[0]
        assert rec["account_sid.sid"] == sid
        assert rec["account_sid.identity_format"] == "sid"

    def test_urls_are_never_treated_as_identities(self):
        # "https://alice@corp.com/x" would UPN-match without the
        # skip-list. Confirm the guard holds.
        pi = _pi([{"url": "https://alice@corp.com/dashboard"}])
        out = expand_identities(pi)
        for k in out.records[0]:
            assert not k.startswith("url."), (
                f"identity parser leaked into URL field: {k}"
            )

    def test_windows_paths_are_never_split(self):
        # "C:\Windows" superficially resembles DOMAIN\User.
        # The skip-list on image/imagepath/file.path prevents that.
        pi = _pi([{"Image": "C:\\Windows\\System32\\cmd.exe"}])
        out = expand_identities(pi)
        for k in out.records[0]:
            assert not k.startswith("Image."), (
                f"identity parser split a Windows path: {k}"
            )

    def test_command_lines_are_never_split(self):
        pi = _pi([{"commandline": "net user CORP\\alice /add"}])
        out = expand_identities(pi)
        for k in out.records[0]:
            assert not k.startswith("commandline."), k

    def test_non_identity_strings_are_ignored(self):
        # A random string that isn't any of the three formats stays put.
        pi = _pi([{"note": "reboot planned for tomorrow"}])
        out = expand_identities(pi)
        assert out is pi

    def test_never_raises_on_pathological_input(self):
        weird = _pi([
            {},
            {"k": None},
            {"k": 42},
            {"k": ["x"]},
            {"k": {"nested": "value"}},
            "not-a-dict",
            {"k": "x" * 10_000},   # oversized
        ])
        out = expand_identities(weird)
        assert len(out.records) == len(weird.records)

    def test_does_not_mutate_input(self):
        rec = {"User": "CORP\\alice"}
        pi = _pi([rec])
        expand_identities(pi)
        # Original record still has only its single key.
        assert set(rec.keys()) == {"User"}

    def test_short_circuit_when_no_identities(self):
        pi = _pi([{"a": "b", "c": "d"}])
        out = expand_identities(pi)
        assert out is pi

    def test_sysmon_style_domain_user_ends_up_mappable(self):
        # End-to-end: after identity expansion, a User field carries
        # a `username` sibling that Semantic Mapping can resolve.
        from nivxforge.investigation.pipeline.schema_understanding import (
            understand_schema,
        )
        from nivxforge.investigation.pipeline.semantic_field_mapper import (
            map_semantic_fields,
        )
        pi = _pi([{"EventID": 1, "Computer": "h1",
                    "User": "CORP\\alice"}])
        enriched = expand_identities(pi)
        fp = understand_schema(enriched)
        result = map_semantic_fields(fp, enriched)
        surfaces = {m.surface_field: m.concept for m in result.mappings}
        # ``User.username`` leaf-resolves to User via the registry.
        assert surfaces.get("User.username") == "User"
