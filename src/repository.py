from __future__ import annotations

import contextlib
import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from .audit import make_entry, utc_now
from .domain import ConflictError, NotFoundError
from .rules import ID_PREFIX, STATES


class Repository:
    def __init__(self, db_path: str):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._tx_state = threading.local()
        self._savepoint_id = 0
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self._create_schema()

    def _create_schema(self) -> None:
        statuses = ",".join("'" + s.replace("'", "''") + "'" for s in STATES)
        with self.conn:
            self.conn.executescript(f"""
                CREATE TABLE IF NOT EXISTS items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    quantity REAL NOT NULL DEFAULT 0,
                    threshold REAL NOT NULL DEFAULT 1,
                    status TEXT NOT NULL CHECK(status IN ({statuses})),
                    version INTEGER NOT NULL DEFAULT 1,
                    external_ref TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS ux_items_external_ref
                    ON items(external_ref) WHERE external_ref IS NOT NULL;
                CREATE TABLE IF NOT EXISTS records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    kind TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open'
                        CHECK(status IN ('open','closed')),
                    external_ref TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(item_id, external_ref)
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    entity_id INTEGER NOT NULL,
                    actor TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_chain_meta (
                    id INTEGER PRIMARY KEY CHECK(id = 1),
                    last_event_id INTEGER NOT NULL,
                    last_entry_hash TEXT NOT NULL,
                    event_count INTEGER NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS batch_uploads (
                    batch_id TEXT PRIMARY KEY,
                    actor TEXT NOT NULL,
                    request_json TEXT NOT NULL,
                    response_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    processed_at TEXT NOT NULL
                );
            """)
            self._initialize_audit_meta()

    def _initialize_audit_meta(self) -> None:
        with self._lock:
            exists = self.conn.execute(
                "SELECT 1 FROM audit_chain_meta WHERE id=1"
            ).fetchone()
            if exists is not None:
                return
            row = self.conn.execute(
                "SELECT id, entry_hash FROM audit_events ORDER BY id DESC LIMIT 1"
            ).fetchone()
            if row is None:
                return
            count = self.conn.execute(
                "SELECT COUNT(*) AS n FROM audit_events"
            ).fetchone()["n"]
        with self.conn:
            self.conn.execute(
                """INSERT OR IGNORE INTO audit_chain_meta(id,last_event_id,
                   last_entry_hash,event_count,updated_at) VALUES(1,?,?,?,?)""",
                (row["id"], row["entry_hash"], int(count), utc_now()),
            )

    @contextlib.contextmanager
    def transaction(self):
        """Serialize writers and join an existing transaction on this thread."""
        with self._lock:
            if getattr(self._tx_state, "active", False):
                yield
                return
            self._tx_state.active = True
            try:
                with self.conn:
                    yield
            finally:
                self._tx_state.active = False

    @contextlib.contextmanager
    def savepoint(self):
        with self._lock:
            self._savepoint_id += 1
            name = f"sp_{self._savepoint_id}"
            self.conn.execute(f"SAVEPOINT {name}")
            try:
                yield
            except Exception:
                self.conn.execute(f"ROLLBACK TO SAVEPOINT {name}")
                self.conn.execute(f"RELEASE SAVEPOINT {name}")
                raise
            else:
                self.conn.execute(f"RELEASE SAVEPOINT {name}")

    @staticmethod
    def _item(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    def create_item(self, title: str, description: str, severity: str,
                    quantity: float, threshold: float, external_ref: Optional[str],
                    actor: str) -> Dict[str, Any]:
        now = utc_now()
        try:
            with self.transaction():
                cur = self.conn.execute(
                    """INSERT INTO items(title, description, severity, quantity, threshold,
                       status, version, external_ref, created_by, created_at, updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (title, description, severity, quantity, threshold, STATES[0], 1,
                     external_ref, actor, now, now),
                )
                item_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("external_ref已存在") from exc
        return self.get_item(item_id)

    def get_item(self, item_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        if row is None:
            raise NotFoundError("项目不存在")
        return self._item(row)

    def get_item_by_external_ref(self, external_ref: str) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM items WHERE external_ref=?", (external_ref,)
            ).fetchone()
        if row is None:
            raise NotFoundError("项目不存在")
        return self._item(row)

    def list_items(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM items"
        params: tuple = ()
        if status:
            sql += " WHERE status=?"
            params = (status,)
        sql += " ORDER BY id DESC"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [self._item(row) for row in rows]

    def transition_item(self, item_id: int, target: str, expected_version: int,
                        actor: str) -> Dict[str, Any]:
        now = utc_now()
        with self.transaction():
            cur = self.conn.execute(
                """UPDATE items SET status=?, version=version+1, updated_at=?
                   WHERE id=? AND version=?""",
                (target, now, item_id, expected_version),
            )
            if cur.rowcount == 0:
                exists = self.conn.execute("SELECT 1 FROM items WHERE id=?", (item_id,)).fetchone()
                if exists is None:
                    raise NotFoundError("项目不存在")
                raise ConflictError("版本冲突，请刷新后重试")
        return self.get_item(item_id)

    def add_record(self, item_id: int, kind: str, detail: str, status: str,
                   external_ref: Optional[str], actor: str) -> Dict[str, Any]:
        now = utc_now()
        self.get_item(item_id)
        try:
            with self.transaction():
                cur = self.conn.execute(
                    """INSERT INTO records(item_id, kind, detail, status, external_ref,
                       created_by, created_at) VALUES(?,?,?,?,?,?,?)""",
                    (item_id, kind, detail, status, external_ref, actor, now),
                )
                record_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("记录唯一标识已存在") from exc
        with self._lock:
            row = self.conn.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
        return dict(row)

    def list_records(self, item_id: int) -> List[Dict[str, Any]]:
        self.get_item(item_id)
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM records WHERE item_id=? ORDER BY id", (item_id,)
            ).fetchall()
        return [dict(row) for row in rows]

    def open_record_count(self, item_id: int) -> int:
        with self._lock:
            row = self.conn.execute(
                "SELECT COUNT(*) AS n FROM records WHERE item_id=? AND status='open'",
                (item_id,),
            ).fetchone()
        return int(row["n"])

    def append_audit(self, action: str, entity_type: str, entity_id: int,
                     actor: str, detail: dict) -> Dict[str, Any]:
        with self.transaction():
            row = self.conn.execute(
                "SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1"
            ).fetchone()
            previous = row["entry_hash"] if row else "GENESIS"
            event = make_entry(action, entity_type, entity_id, actor, detail, previous)
            cur = self.conn.execute(
                """INSERT INTO audit_events(action, entity_type, entity_id, actor, detail,
                   previous_hash, entry_hash, created_at) VALUES(?,?,?,?,?,?,?,?)""",
                (event["action"], event["entity_type"], event["entity_id"], event["actor"],
                 json.dumps(event["detail"], ensure_ascii=False, sort_keys=True),
                 event["previous_hash"], event["entry_hash"], event["created_at"]),
            )
            event_id = int(cur.lastrowid)
            count_row = self.conn.execute(
                "SELECT COUNT(*) AS n FROM audit_events"
            ).fetchone()
            now = event["created_at"]
            updated = self.conn.execute(
                """UPDATE audit_chain_meta
                   SET last_event_id=?, last_entry_hash=?, event_count=?, updated_at=?
                   WHERE id=1""",
                (event_id, event["entry_hash"], int(count_row["n"]), now),
            )
            if updated.rowcount == 0:
                self.conn.execute(
                    """INSERT INTO audit_chain_meta(id,last_event_id,last_entry_hash,
                       event_count,updated_at) VALUES(1,?,?,?,?)""",
                    (event_id, event["entry_hash"], int(count_row["n"]), now),
                )
        event["id"] = event_id
        return event

    def list_audit(self, entity_id: Optional[int] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM audit_events"
        params: tuple = ()
        if entity_id is not None:
            sql += " WHERE entity_id=?"
            params = (entity_id,)
        sql += " ORDER BY id"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["detail"] = json.loads(item["detail"])
            result.append(item)
        return result

    def audit_chain_status(self) -> Dict[str, Any]:
        from .audit import calculate_hash

        with self._lock:
            rows = self.conn.execute("SELECT * FROM audit_events ORDER BY id").fetchall()
            meta = self.conn.execute(
                "SELECT * FROM audit_chain_meta WHERE id=1"
            ).fetchone()

        previous = "GENESIS"
        expected_id = 1
        last_row: Optional[sqlite3.Row] = None
        for row in rows:
            if row["id"] > expected_id:
                return {
                    "valid": False,
                    "code": "AUDIT_MISSING_EVENT",
                    "error_event_id": expected_id,
                    "event_id": expected_id,
                    "missing_event_id": expected_id,
                    "next_event_id": row["id"],
                    "message": f"审计事件{expected_id}缺失，审计链在事件{row['id']}处中断",
                }
            if row["previous_hash"] != previous:
                return {
                    "valid": False,
                    "code": "AUDIT_CHAIN_MISMATCH",
                    "error_event_id": row["id"],
                    "event_id": row["id"],
                    "broken_event_id": row["id"],
                    "message": f"审计事件{row['id']}的前序哈希不匹配",
                }
            try:
                detail = json.loads(row["detail"])
            except (json.JSONDecodeError, TypeError) as exc:
                return {
                    "valid": False,
                    "code": "AUDIT_EVENT_TAMPERED",
                    "error_event_id": row["id"],
                    "event_id": row["id"],
                    "broken_event_id": row["id"],
                    "message": f"审计事件{row['id']}的内容已损坏或被修改",
                }
            payload = {
                "action": row["action"], "entity_type": row["entity_type"],
                "entity_id": row["entity_id"], "actor": row["actor"],
                "detail": detail, "created_at": row["created_at"],
            }
            if calculate_hash(previous, payload) != row["entry_hash"]:
                return {
                    "valid": False,
                    "code": "AUDIT_EVENT_TAMPERED",
                    "error_event_id": row["id"],
                    "event_id": row["id"],
                    "broken_event_id": row["id"],
                    "message": f"审计事件{row['id']}的哈希不匹配，内容可能已被修改",
                }
            previous = row["entry_hash"]
            expected_id = row["id"] + 1
            last_row = row

        if meta is not None:
            last_id = last_row["id"] if last_row is not None else 0
            count = len(rows)
            if int(meta["last_event_id"]) > last_id:
                missing_id = int(meta["last_event_id"])
                return {
                    "valid": False,
                    "code": "AUDIT_MISSING_EVENT",
                    "error_event_id": missing_id,
                    "event_id": missing_id,
                    "missing_event_id": missing_id,
                    "message": f"审计事件{missing_id}缺失，审计链尾部不完整",
                }
            if int(meta["last_event_id"]) < last_id:
                unexpected_id = int(meta["last_event_id"]) + 1
                return {
                    "valid": False,
                    "code": "AUDIT_UNEXPECTED_EVENT",
                    "error_event_id": unexpected_id,
                    "event_id": unexpected_id,
                    "broken_event_id": unexpected_id,
                    "message": f"审计事件{unexpected_id}不在已封存的审计链中",
                }
            if int(meta["event_count"]) != count or meta["last_entry_hash"] != previous:
                error_id = last_id or int(meta["last_event_id"])
                return {
                    "valid": False,
                    "code": "AUDIT_CHAIN_MISMATCH",
                    "error_event_id": error_id,
                    "event_id": error_id,
                    "broken_event_id": error_id,
                    "message": f"审计事件{error_id}的链尾校验不匹配",
                }

        return {
            "valid": True,
            "event_count": len(rows),
            "last_event_id": last_row["id"] if last_row is not None else 0,
            "last_entry_hash": previous,
        }

    def verify_audit_chain(self) -> bool:
        return self.audit_chain_status()["valid"]

    def get_batch_upload(self, batch_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM batch_uploads WHERE batch_id=?", (batch_id,)
            ).fetchone()
        return dict(row) if row is not None else None

    def save_batch_upload(self, batch_id: str, actor: str, request_json: str,
                          response_json: str, status: str) -> None:
        now = utc_now()
        with self.transaction():
            self.conn.execute(
                """INSERT INTO batch_uploads(batch_id, actor, request_json, response_json,
                   status, created_at, processed_at) VALUES(?,?,?,?,?,?,?)""",
                (batch_id, actor, request_json, response_json, status, now, now),
            )

    def close(self) -> None:
        with self._lock:
            self.conn.close()
