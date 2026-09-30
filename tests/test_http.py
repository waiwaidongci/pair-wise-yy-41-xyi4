import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from src.http_api import make_handler
from src.repository import Repository
from src.service import Service

STATIC_DIR = str(Path(__file__).resolve().parent.parent / "static")


class HttpTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        repo = Repository(str(Path(self.tmp.name) / "test.db"))
        self.service = Service(repo)
        self.server = ThreadingHTTPServer(
            ("127.0.0.1", 0), make_handler(self.service, STATIC_DIR))
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.tmp.cleanup()

    def _request(self, method, path, body=None, actor=None, role=None):
        url = f"http://127.0.0.1:{self.port}{path}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if actor is not None:
            req.add_header("X-Actor", actor)
        if role is not None:
            req.add_header("X-Role", role)
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def _create_item(self, ref):
        status, body = self._request("POST", "/api/items", {
            "title": "http item", "description": "http flow",
            "severity": "warning", "quantity": 5, "threshold": 10,
            "external_ref": ref,
        }, "creator", "sensor_operator")
        self.assertEqual(status, 201)
        return body

    def test_health(self):
        status, body = self._request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ok")

    def test_audit_chain_status_endpoint(self):
        self._create_item("HTTP-1")
        status, body = self._request("GET", "/api/audit", actor="auditor",
                                      role="bridge_engineer")
        self.assertEqual(status, 200)
        self.assertIn("events", body)
        self.assertTrue(body["chain_valid"])
        self.assertIsNone(body["broken_at"])

    def test_batch_endpoint_applies_and_is_idempotent(self):
        item = self._create_item("HTTP-2")
        ops = [
            {"client_op_id": "r1", "type": "record", "item_id": item["id"],
             "kind": "deviation", "detail": "偏差", "status": "open",
             "external_ref": "HTTP-DEV-1"},
            {"client_op_id": "t1", "type": "transition", "item_id": item["id"],
             "target": "warning", "expected_version": 1},
        ]
        status, first = self._request("POST", "/api/batches", {
            "batch_id": "HTTP-B-1", "operations": ops,
        }, "inspector", "sensor_operator")
        self.assertEqual(status, 200)
        self.assertEqual(first["applied_count"], 2)
        self.assertEqual(first["conflict_count"], 0)
        # 同批次号重传沿用首次结果
        status, second = self._request("POST", "/api/batches", {
            "batch_id": "HTTP-B-1", "operations": ops,
        }, "inspector", "sensor_operator")
        self.assertEqual(status, 200)
        self.assertEqual(second, first)
        # 查询批次结果
        status, fetched = self._request("GET", "/api/batches/HTTP-B-1",
                                        actor="inspector", role="viewer")
        self.assertEqual(status, 200)
        self.assertEqual(fetched, first)

    def test_batch_endpoint_reports_conflicts(self):
        item = self._create_item("HTTP-3")
        ops = [
            {"client_op_id": "r1", "type": "record", "item_id": item["id"],
             "kind": "deviation", "detail": "偏差", "status": "open",
             "external_ref": "HTTP-DEV-OK"},
            {"client_op_id": "t-skip", "type": "transition", "item_id": item["id"],
             "target": "restricted", "expected_version": 1},
        ]
        status, body = self._request("POST", "/api/batches", {
            "batch_id": "HTTP-B-2", "operations": ops,
        }, "inspector", "bridge_engineer")
        self.assertEqual(status, 200)
        self.assertEqual(body["applied_count"], 1)
        self.assertEqual(body["conflict_count"], 1)
        self.assertEqual(body["conflicts"][0]["client_op_id"], "t-skip")
        self.assertEqual(body["conflicts"][0]["error"], "conflict")


if __name__ == "__main__":
    unittest.main()
