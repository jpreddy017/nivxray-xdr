"""Pure correlation contract tests; no database or runtime coverage claims."""
import pathlib
import sys
import unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from services.edr.file_context import correlate, enrich

SHA = 'a' * 64
Q = {'time_start': 1788220800000, 'time_end': 1790812800000}

def event(n, kind, guid='guid-a', sha=None, ts='2026-09-02T10:00:00Z'):
    return {'_id': str(n), 'event': {'kind': kind, 'ts': ts,
        'process': {'guid': guid, 'pid': 123, 'image': 'file.exe', 'image_hashes': {'sha256': sha} if sha else {}},
        'artefacts': {'network': [{'dst_ip': '192.0.2.1', 'dst_port': 443, 'protocol': 'tcp'}]}}}

class ContextTests(unittest.TestCase):
    def rows(self): return [{'hashes': {'sha256': SHA}}]
    def test_exact_hash_and_guid_join_with_record_provenance(self):
        rows = correlate(self.rows(), [event(1,'process_create',sha=SHA),event(2,'network_connect')], Q)
        self.assertEqual(rows[0]['network_connections'][0]['record_id'], '2')
        self.assertEqual(rows[0]['executions'][0]['record_id'], '1')
    def test_pid_or_path_alone_never_joins(self):
        rows = correlate(self.rows(), [event(1,'process_create',sha=SHA),event(2,'network_connect',guid='other')], Q)
        self.assertEqual(rows[0]['network_connections'], [])
    def test_different_content_and_missing_file_hash(self):
        for rows in (self.rows(), [{'hashes': {}}]):
            result = correlate(rows, [event(1,'process_create',sha='b'*64),event(2,'network_connect')], Q)
            self.assertEqual(result[0]['network_connections'], [])
    def test_conflicting_guid_image_identity_is_rejected(self):
        rows = correlate(self.rows(), [event(1,'process_create',sha=SHA),event(2,'process_create',sha='b'*64),event(3,'network_connect')], Q)
        self.assertEqual(rows[0]['network_connections'], [])
    def test_outside_window_and_naive_timestamps_excluded(self):
        rows = correlate(self.rows(), [event(1,'process_create',sha=SHA),event(2,'network_connect',ts='2026-10-02T10:00:00Z'),event(3,'network_connect',ts='2026-09-02T10:00:00')], Q)
        self.assertEqual(rows[0]['network_connections'], [])
    def test_scan_bound_explicit(self):
        rows = correlate(self.rows(), [event(n,'network_connect') for n in range(1001)], Q)
        self.assertEqual(rows[0]['context_scanned_records'], 1000)
        self.assertEqual(rows[0]['context_coverage'], 'BOUNDED_SCAN_INCOMPLETE')
    def test_enrichment_preserves_authorized_predicate_and_closes_cursor(self):
        predicate = {'$and': [{'tenant_id': 'tenant-a'}, {'collector_id': 'endpoint-a'}]}
        class Cursor:
            closed = False
            def sort(self, *args): return self
            def limit(self, count):
                self.count = count
                return self
            def max_time_ms(self, timeout):
                self.timeout = timeout
                return self
            def __iter__(self): return iter([event(1,'process_create',sha=SHA),event(2,'network_connect')])
            def close(self): self.closed = True
        class Collection:
            cursor = Cursor()
            def find(self, received, projection):
                self.predicate = received
                return self.cursor
        collection = Collection()
        result = enrich(collection, predicate, self.rows(), Q)
        self.assertIs(collection.predicate, predicate)
        self.assertTrue(collection.cursor.closed)
        self.assertEqual(collection.cursor.count, 1001)
        self.assertEqual(collection.cursor.timeout, 3000)
        self.assertEqual(len(result[0]['network_connections']), 1)
    def test_result_bound_explicit(self):
        rows = correlate(self.rows(), [event(1,'process_create',sha=SHA)]+[event(n,'network_connect') for n in range(200)], Q)
        self.assertEqual(len(rows[0]['network_connections']), 100)
        self.assertTrue(rows[0]['context_results_truncated'])

if __name__ == '__main__': unittest.main()
