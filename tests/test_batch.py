import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.domain import ConflictError, PermissionDenied
from src.repository import Repository
from src.service import Service


class BatchUploadTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(str(Path(self.tmp.name) / "test.db"))
        self.service = Service(self.repo)
        self.item = self.service.create_item(
            {"title": "batch item", "description": "offline batch",
             "severity": "warning", "quantity": 5, "threshold": 10,
             "external_ref": "BATCH-ITEM"},
            "creator", "sensor_operator")

    def tearDown(self):
        self.repo.close()
        self.tmp.cleanup()

    def _ops(self):
        return [
            {"client_op_id": "op-record", "type": "record", "item_id": self.item["id"],
             "kind": "deviation", "detail": "桥墩偏差", "status": "open",
             "external_ref": "DEV-1"},
            {"client_op_id": "op-transition", "type": "transition",
             "item_id": self.item["id"], "target": "warning",
             "expected_version": 1},
        ]

    def test_batch_applies_valid_operations(self):
        result = self.service.upload_batch("B-001", self._ops(), "inspector",
                                           "sensor_operator")
        self.assertEqual(result["applied_count"], 2)
        self.assertEqual(result["conflict_count"], 0)
        self.assertEqual(result["conflicts"], [])
        stored = self.service.get_item(self.item["id"], "viewer")
        self.assertEqual(stored["status"], "warning")
        records = self.service.list_records(self.item["id"], "viewer")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["external_ref"], "DEV-1")
        # 改动与审计事件一起入库
        events = self.service.audit("viewer", self.item["id"])
        actions = [e["action"] for e in events]
        self.assertIn("record", actions)
        self.assertIn("transition", actions)
        self.assertTrue(self.repo.verify_audit_chain())

    def test_batch_idempotent_retransmission_uses_first_result(self):
        first = self.service.upload_batch("B-002", self._ops(), "inspector",
                                          "sensor_operator")
        record_count = len(self.service.list_records(self.item["id"], "viewer"))
        audit_count = len(self.service.audit("viewer", self.item["id"]))
        # 同批次号重传，即使内容不同也沿用首次结果
        second = self.service.upload_batch("B-002", [
            {"client_op_id": "op-other", "type": "record", "item_id": self.item["id"],
             "kind": "action", "detail": "不应入库", "status": "open",
             "external_ref": "DEV-SHOULD-NOT-EXIST"},
        ], "inspector", "sensor_operator")
        self.assertEqual(second, first)
        self.assertEqual(len(self.service.list_records(self.item["id"], "viewer")),
                         record_count)
        self.assertEqual(len(self.service.audit("viewer", self.item["id"])),
                         audit_count)
        # 首次结果中的记录仍然存在，重传没有改动已入库数据
        self.assertIsNotNone(self.repo.get_batch("B-002"))

    def test_batch_conflicts_unauthorized_and_skip_level(self):
        ops = [
            {"client_op_id": "op-ok", "type": "record", "item_id": self.item["id"],
             "kind": "deviation", "detail": "偏差", "status": "open",
             "external_ref": "DEV-OK"},
            {"client_op_id": "op-unauth", "type": "transition",
             "item_id": self.item["id"], "target": "warning",
             "expected_version": 1},
            {"client_op_id": "op-skip", "type": "transition",
             "item_id": self.item["id"], "target": "restricted",
             "expected_version": 1},
        ]
        # bridge_engineer 可登记事项，但无权发起 normal->warning，且 normal->restricted 跳级
        result = self.service.upload_batch("B-003", ops, "inspector",
                                            "bridge_engineer")
        self.assertEqual(result["applied_count"], 1)
        self.assertEqual(result["conflict_count"], 2)
        by_id = {c["client_op_id"]: c for c in result["conflicts"]}
        self.assertEqual(by_id["op-unauth"]["error"], PermissionDenied.kind)
        self.assertEqual(by_id["op-skip"]["error"], ConflictError.kind)
        # 冲突操作没有改动告警，也没有产生审计
        stored = self.service.get_item(self.item["id"], "viewer")
        self.assertEqual(stored["status"], "normal")
        self.assertEqual(stored["version"], 1)
        events = self.service.audit("viewer", self.item["id"])
        self.assertEqual([e["action"] for e in events].count("transition"), 0)

    def test_batch_version_advanced_rejudged_by_server_current(self):
        # 服务端在离线期间已把告警推进到 warning
        self.service.transition(self.item["id"], "warning", 1, "reviewer",
                                "sensor_operator")
        self.assertEqual(self.service.get_item(self.item["id"], "viewer")["status"],
                         "warning")
        # 离线补传仍按旧版本 expected_version=1 提交 normal->warning
        stale = [{"client_op_id": "op-stale", "type": "transition",
                  "item_id": self.item["id"], "target": "warning",
                  "expected_version": 1}]
        before = len(self.service.audit("viewer", self.item["id"]))
        result = self.service.upload_batch("B-004", stale, "inspector",
                                           "sensor_operator")
        self.assertEqual(result["applied_count"], 0)
        self.assertEqual(result["conflict_count"], 1)
        self.assertEqual(result["conflicts"][0]["client_op_id"], "op-stale")
        self.assertEqual(result["conflicts"][0]["error"], ConflictError.kind)
        # 告警未被改动，也没有补传的审计事件
        stored = self.service.get_item(self.item["id"], "viewer")
        self.assertEqual(stored["status"], "warning")
        self.assertEqual(stored["version"], 2)
        self.assertEqual(len(self.service.audit("viewer", self.item["id"])), before)

    def test_batch_duplicate_record_is_conflict_not_reapplied(self):
        ops = self._ops()
        self.service.upload_batch("B-005", ops, "inspector", "sensor_operator")
        self.assertEqual(self.service.get_item(self.item["id"], "viewer")["status"],
                         "warning")
        # 同 external_ref 再次补传（新批次号）：记录幂等，冲突而非重复入库。
        # 此时告警已在 B-005 中前进到 warning，故只补传记录，避免与流转混淆。
        duplicate_record = [ops[0]]
        result = self.service.upload_batch("B-006", duplicate_record, "inspector",
                                           "sensor_operator")
        self.assertEqual(result["applied_count"], 0)
        self.assertEqual(result["conflict_count"], 1)
        self.assertEqual(result["conflicts"][0]["client_op_id"], "op-record")
        self.assertEqual(result["conflicts"][0]["error"], ConflictError.kind)
        self.assertEqual(len(self.service.list_records(self.item["id"], "viewer")), 1)

    def test_batch_atomic_rollback_and_retry(self):
        ops = self._ops()
        before_records = len(self.service.list_records(self.item["id"], "viewer"))
        before_audits = len(self.service.audit("viewer", self.item["id"]))
        # 模拟提交批次结果时失败（系统异常），整批回滚
        with patch.object(Repository, "_insert_batch",
                          side_effect=RuntimeError("commit boom")):
            with self.assertRaises(RuntimeError):
                self.service.upload_batch("B-007", ops, "inspector",
                                           "sensor_operator")
        # 没有留下只改状态没审计的记录
        self.assertEqual(len(self.service.list_records(self.item["id"], "viewer")),
                         before_records)
        self.assertEqual(len(self.service.audit("viewer", self.item["id"])),
                         before_audits)
        self.assertIsNone(self.repo.get_batch("B-007"))
        # 失败后整批重试成功，且只生效一次
        result = self.service.upload_batch("B-007", ops, "inspector",
                                           "sensor_operator")
        self.assertEqual(result["applied_count"], 2)
        self.assertEqual(len(self.service.list_records(self.item["id"], "viewer")),
                         before_records + 1)
        self.assertEqual(len(self.service.audit("viewer", self.item["id"])),
                         before_audits + 2)

    def test_audit_chain_broken_at_on_tamper(self):
        self.service.add_record(self.item["id"], {"kind": "evidence", "detail": "d",
                                                  "status": "closed",
                                                  "external_ref": "EV-1"},
                                "recorder", "sensor_operator")
        self.service.transition(self.item["id"], "warning", 1, "reviewer",
                                "sensor_operator")
        status = self.service.audit_chain_status("viewer")
        self.assertTrue(status["chain_valid"])
        self.assertIsNone(status["broken_at"])
        events = self.service.audit("viewer")
        # 篡改中间一条审计事件的 detail
        target = events[1]
        with self.repo._lock, self.repo.conn:
            self.repo.conn.execute(
                "UPDATE audit_events SET detail=? WHERE id=?",
                ('{"tampered":true}', target["id"]))
        status = self.service.audit_chain_status("viewer")
        self.assertFalse(status["chain_valid"])
        self.assertEqual(status["broken_at"], target["id"])

    def test_audit_chain_broken_at_on_missing_row(self):
        self.service.add_record(self.item["id"], {"kind": "evidence", "detail": "d",
                                                  "status": "closed",
                                                  "external_ref": "EV-1"},
                                "recorder", "sensor_operator")
        self.service.transition(self.item["id"], "warning", 1, "reviewer",
                                "sensor_operator")
        events = self.service.audit("viewer")
        self.assertGreaterEqual(len(events), 3)
        # 删除中间一条审计事件（缺行）
        missing = events[1]
        follower = events[2]
        with self.repo._lock, self.repo.conn:
            self.repo.conn.execute(
                "DELETE FROM audit_events WHERE id=?", (missing["id"],))
        status = self.service.audit_chain_status("viewer")
        self.assertFalse(status["chain_valid"])
        # 缺行后，链在紧随其后的事件处断开
        self.assertEqual(status["broken_at"], follower["id"])


if __name__ == "__main__":
    unittest.main()
