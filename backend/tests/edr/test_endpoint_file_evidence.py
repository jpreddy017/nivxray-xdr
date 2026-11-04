"""Bounded scan/projection tests. No database or live sensor is substituted."""
import copy
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from services.edr import endpoint_file_evidence as files

T0, T1 = 1788220800000, 1790812800000
SHA = "a" * 64


def doc(n=1, *, path=r"C:\tmp\file.dll", hashes=None, ts="2026-09-02T10:00:00+00:00"):
    return {"_id": f"{n:024x}", "tenant_id": "ten_a", "connector_id": "ep_a",
            "observation_id": f"obs_{n}", "event": {"kind": "file_create", "ts": ts,
            "raw": {"target": path, "sha256": "b" * 64,
                    "file": {"path": path, "hashes": hashes or {}}},
            "process": {"image": "writer.exe", "hashes": {"sha256": "c" * 64}}}}


class FileEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.q = files.validate_query("ep_a", T0, T1)

    def test_process_and_payload_hashes_are_not_file_hashes(self):
        row, _ = files.project(doc(), self.q)
        self.assertEqual(row["hashes"], {})
        self.assertEqual(row["identity_basis"], "PATH_IDENTITY_ONLY")
        self.assertEqual(row["assessment"], "NOT_ASSESSED")

    def test_valid_file_hash_is_preserved(self):
        row, _ = files.project(doc(hashes={"sha256": SHA}), self.q)
        self.assertEqual(row["hashes"]["sha256"], SHA)
        self.assertEqual(row["identity_basis"], "CONTENT_IDENTITY_SHA256")

    def test_invalid_hash_cannot_claim_content_identity(self):
        row, _ = files.project(doc(hashes={"sha256": "not-a-hash"}), self.q)
        self.assertEqual(row["hashes"], {})
        self.assertIsNone(row["file_key"])

    def test_same_name_different_contents_preserve_observations(self):
        result = files.scan_page([doc(2, hashes={"sha256": SHA}),
                                  doc(1, hashes={"sha256": "d" * 64})], self.q, "ten_a")
        self.assertEqual(len(result["observations"]), 2)
        self.assertNotEqual(*[r["file_key"] for r in result["observations"]])

    def test_source_writer_is_not_joined_by_pid(self):
        row, _ = files.project(doc(), self.q)
        self.assertEqual(row["writer_image"], "writer.exe")
        self.assertEqual(row["writer_basis"], "SOURCE_STATED_ON_FILE_EVENT")

    def test_no_writer_stays_unknown(self):
        record = doc(); record["event"]["process"] = {}
        row, _ = files.project(record, self.q)
        self.assertEqual(row["writer_basis"], "WRITER_NOT_OBSERVED")

    def test_path_filter_is_exact_not_regex(self):
        q = {**self.q, "key": ".*"}
        self.assertIsNone(files.project(doc(), q)[0])

    def test_sha_filter_never_falls_back_to_name(self):
        q = {**self.q, "key_type": "sha256", "key": SHA}
        self.assertIsNone(files.project(doc(path=SHA), q)[0])

    def test_half_open_end_is_excluded(self):
        self.assertIsNone(files.project(doc(ts="2026-10-01T00:00:00Z"), self.q)[0])

    def test_start_is_included(self):
        self.assertIsNotNone(files.project(doc(ts="2026-09-01T00:00:00Z"), self.q)[0])

    def test_equivalent_offset_matches_window(self):
        row, _ = files.project(doc(ts="2026-09-01T05:30:00+05:30"), self.q)
        self.assertEqual(row["observed_at"], "2026-09-01T00:00:00+00:00")

    def test_naive_time_is_not_guessed(self):
        row, issue = files.project(doc(ts="2026-09-02 10:00:00"), self.q)
        self.assertIsNone(row); self.assertEqual(issue, "FILE_TIME_UNRESOLVED")

    def test_process_only_record_is_not_a_file(self):
        record = doc(); record["event"]["kind"] = "process_start"
        record["event"]["raw"] = {"image": "file.dll"}
        self.assertIsNone(files.project(record, self.q)[0])

    def test_page_cursor_resumes_after_consumed_not_lookahead(self):
        q = {**self.q, "limit": 1}
        result = files.scan_page([doc(3), doc(2), doc(1)], q, "ten_a")
        self.assertEqual(files.decode_cursor(result["next_cursor"], q, "ten_a"), f"{3:024x}")
        self.assertFalse(result["complete"])

    def test_equal_event_times_conserve_each_record_across_pages(self):
        q = {**self.q, "limit": 1}
        records = [doc(3), doc(2), doc(1)]
        seen = []
        while records:
            page = files.scan_page(records, q, "ten_a")
            seen.extend(r["record_id"] for r in page["observations"])
            if not page["next_cursor"]: break
            after = files.decode_cursor(page["next_cursor"], q, "ten_a")
            records = [d for d in records if d["_id"] < after]
        self.assertEqual(seen, [f"{i:024x}" for i in (3, 2, 1)])

    def test_scan_budget_empty_page_is_incomplete(self):
        q = {**self.q, "key": "unseen"}
        records = (doc(i) for i in range(1002, 0, -1))
        page = files.scan_page(records, q, "ten_a")
        self.assertEqual(page["scanned_records"], 1000)
        self.assertEqual(page["state"], "SCAN_INCOMPLETE")
        self.assertIsNotNone(page["next_cursor"])

    def test_empty_scan_has_no_coverage_claim(self):
        page = files.scan_page([], self.q, "ten_a")
        self.assertEqual(page["coverage"], "NOT_PROVEN")
        self.assertEqual(page["state"], "NO_MATCHING_FILE_OBSERVATIONS")

    def test_cursor_rejects_other_tenant_endpoint_window_or_filter(self):
        cursor = files.encode_cursor(f"{1:024x}", self.q, "ten_a")
        for q, tenant in [(self.q, "ten_b"), ({**self.q, "endpoint_id": "ep_b"}, "ten_a"),
                          ({**self.q, "time_start": T0 + 1}, "ten_a"),
                          ({**self.q, "key": "other"}, "ten_a")]:
            with self.subTest(query=q, tenant=tenant), self.assertRaises(files.InvalidFileQuery):
                files.decode_cursor(cursor, q, tenant)

    def test_malformed_or_oversized_cursors_are_rejected(self):
        for value in ["!", "x" * 513, "e30", "W10"]:
            with self.subTest(value=value[:10]), self.assertRaises(files.InvalidFileQuery):
                files.decode_cursor(value, self.q, "ten_a")

    def test_invalid_query_bounds_are_rejected(self):
        for start, end, limit in [(T1, T0, 100), (T0, T0, 100),
                                  (0, files.MAX_WINDOW_MS + 1, 100),
                                  (T0, T1, 0), (T0, T1, 201)]:
            with self.subTest(start=start, end=end, limit=limit), self.assertRaises(files.InvalidFileQuery):
                files.validate_query("ep_a", start, end, limit=limit)

    def test_source_record_is_not_modified(self):
        record = doc(); before = copy.deepcopy(record)
        files.project(record, self.q)
        self.assertEqual(record, before)

    def test_malformed_record_does_not_destroy_the_page(self):
        page = files.scan_page([{"_id": f"{2:024x}", "event": {"raw": "invalid"}}, doc(1)], self.q, "ten_a")
        self.assertEqual(len(page["observations"]), 1)
        self.assertEqual(page["issues"], {"FILE_RECORD_UNREADABLE": 1})


if __name__ == "__main__":
    unittest.main()

