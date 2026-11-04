import unittest
from edr_plane.detection_result import require_detection_result


class DetectionCompletionTests(unittest.TestCase):
    def test_incomplete_pipeline_is_not_clean(self):
        for result in [
            {"blocker": "parser", "stages": [{"stage": "parser", "status": "FAILED"}]},
            {"blocker": "detection", "stages": [{"stage": "detection", "status": "FAILED"}]},
            {"detection": {"status": "NO_MATCH"}},
            {"stages": [{"stage": "detection", "status": "EXECUTED"}]},
            {"stages": [{"stage": "detection", "status": "EXECUTED"}],
             "detection": {"status": "EXECUTION_FAILED"}},
        ]:
            with self.subTest(result=result):
                with self.assertRaises(RuntimeError):
                    require_detection_result(result)

    def test_incident_gate_does_not_invalidate_completed_rules(self):
        detection = {"status": "NO_MATCH", "matched": False}
        result = {"blocker": "incident_gate", "detection": detection,
                  "stages": [{"stage": "detection", "status": "EXECUTED"}]}
        self.assertIs(require_detection_result(result), detection)

    def test_matched_rules_are_preserved(self):
        detection = {"status": "MATCHED", "matched": True,
                     "detections": [{"rule_id": "test-rule"}]}
        self.assertIs(require_detection_result({
            "detection": detection,
            "stages": [{"stage": "detection", "status": "EXECUTED"}],
        }), detection)
