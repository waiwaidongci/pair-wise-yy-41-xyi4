import sqlite3
import tempfile
import unittest
from pathlib import Path

from src.repository import Repository
from src.service import Service


class OfflineBatchTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmp.name) / "test.db")
        self.repo = Repository(self.db_path)
        self.service = Service(self.repo)

    def tearDown(self):
        self.repo.close()
        self.tmp.cleanup()

    def test_mixed_offline_batch_uses_current_server_version(self):
        payload = {
            "batch_id": "OFFLINE-1",
            "operations": [
                {
                    "op_id": "dev-1",
                    "local_ref": "dev-1",
                    "type": "偏差登记",
                    "title": "桥面裂缝",
                    "description": "无信号桥段巡检发现裂缝",
                    "severity": "warning",
                    "quantity": 12,
                    "threshold": 6,
                    "role": "sensor_operator",
                },
                {
                    "op_id": "warn-1",
                    "local_item_ref": "dev-1",
                    "type": "推进",
                    "role": "sensor_operator",
                },
                {
                    "op_id": "issue-1",
                    "local_item_ref": "dev-1",
                    "type": "异常事项",
                    "kind": "crack",
                    "detail": "裂缝仍在扩展",
                    "status": "open",
                    "role": "sensor_operator",
                },
                {
                    "op_id": "notice-1",
                    "local_item_ref": "dev-1",
                    "type": "record",
                    "kind": "交通通告",
                    "detail": "养护站已发布限载通告",
                    "status": "closed",
                    "role": "traffic_authority",
                },
                {
                    "op_id": "restrict-1",
                    "local_item_ref": "dev-1",
                    "type": "限行推进",
                    "expected_version": 1,
                    "role": "bridge_engineer",
                },
                {
                    "op_id": "skip-1",
                    "local_item_ref": "dev-1",
                    "type": "transition",
                    "target": "restored",
                    "role": "bridge_engineer",
                },
                {
                    "op_id": "forbidden-1",
                    "local_item_ref": "dev-1",
                    "type": "transition",
                    "target": "closed",
                    "role": "bridge_engineer",
                },
            ],
        }

        result = self.service.sync_offline_batch(payload, actor="inspection-car")
        self.assertEqual(result["status"], "processed_with_conflicts")
        self.assertEqual(result["applied_count"], 5)
        self.assertEqual(result["conflict_count"], 2)
        self.assertEqual(
            [conflict["op_id"] for conflict in result["conflicts"]],
            ["skip-1", "forbidden-1"],
        )
        self.assertEqual(result["conflicts"][0]["code"], "TRANSITION_OR_STATE_CONFLICT")
        self.assertEqual(result["conflicts"][1]["code"], "UNAUTHORIZED_OPERATION")

        item = self.service.list_items("viewer")[0]
        self.assertEqual(item["status"], "restricted")
        self.assertEqual(item["version"], 3)

        events = self.service.audit("viewer", item["id"])
        transition_events = [event for event in events if event["action"] == "transition"]
        self.assertEqual(len(transition_events), 2)
        self.assertEqual(transition_events[-1]["detail"]["client_expected_version"], 1)
        self.assertEqual(transition_events[-1]["detail"]["rebased_to_version"], 2)
        self.assertTrue(self.repo.verify_audit_chain())

    def test_same_batch_number_replays_first_result_without_new_audit(self):
        payload = {
            "batch_id": "OFFLINE-2",
            "operations": [
                {
                    "op_id": "dev-2",
                    "type": "create",
                    "title": "重复补传",
                    "description": "同批次号重传",
                    "severity": "normal",
                    "role": "sensor_operator",
                }
            ],
        }

        first = self.service.sync_offline_batch(payload, actor="car")
        before = len(self.service.audit("viewer"))
        second = self.service.sync_offline_batch(payload, actor="car")
        after = len(self.service.audit("viewer"))

        self.assertFalse(first["replayed"])
        self.assertTrue(second["replayed"])
        self.assertTrue(second["idempotent"])
        self.assertEqual(second["results"], first["results"])
        self.assertEqual(before, after)
        self.assertEqual(len(self.service.list_items("viewer")), 1)

    def test_audit_verification_reports_broken_event_id(self):
        self.service.create_item(
            {"title": "audit", "description": "chain", "severity": "normal"},
            "creator", "sensor_operator"
        )
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("UPDATE audit_events SET action='tampered' WHERE id=1")

        status = self.service.audit_chain_status("viewer")
        self.assertFalse(status["valid"])
        self.assertEqual(status["error_event_id"], 1)
        self.assertEqual(status["event_id"], 1)
        self.assertEqual(status["code"], "AUDIT_EVENT_TAMPERED")


if __name__ == "__main__":
    unittest.main()
