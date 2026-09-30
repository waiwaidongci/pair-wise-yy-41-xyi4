from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .audit import calculate_hash, make_entry, utc_now
from .domain import ConflictError, NotFoundError
from .rules import ID_PREFIX, STATES


class Repository:
    def __init__(self, db_path: str):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
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
                CREATE TABLE IF NOT EXISTS upload_batches (
                    batch_id TEXT PRIMARY KEY,
                    result TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
            """)

    @staticmethod
    def _item(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # 底层方法：调用方必须已持有 self._lock 并处于一个事务中。
    # 批量补传时整批操作共用一个事务，保证改动与审计事件同时入库、
    # 失败整体回滚，不留下只改状态没审计的记录。
    # ------------------------------------------------------------------

    def _fetch_item(self, item_id: int) -> Optional[Dict[str, Any]]:
        row = self.conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        return self._item(row) if row is not None else None

    def _insert_item(self, title: str, description: str, severity: str,
                     quantity: float, threshold: float, external_ref: Optional[str],
                     actor: str) -> int:
        now = utc_now()
        cur = self.conn.execute(
            """INSERT INTO items(title, description, severity, quantity, threshold,
               status, version, external_ref, created_by, created_at, updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (title, description, severity, quantity, threshold, STATES[0], 1,
             external_ref, actor, now, now),
        )
        return int(cur.lastrowid)

    def _insert_record(self, item_id: int, kind: str, detail: str, status: str,
                       external_ref: Optional[str], actor: str) -> int:
        now = utc_now()
        cur = self.conn.execute(
            """INSERT INTO records(item_id, kind, detail, status, external_ref,
               created_by, created_at) VALUES(?,?,?,?,?,?,?)""",
            (item_id, kind, detail, status, external_ref, actor, now),
        )
        return int(cur.lastrowid)

    def _update_item_status(self, item_id: int, target: str, expected_version: int,
                            actor: str) -> int:
        now = utc_now()
        cur = self.conn.execute(
            """UPDATE items SET status=?, version=version+1, updated_at=?
               WHERE id=? AND version=?""",
            (target, now, item_id, expected_version),
        )
        return cur.rowcount

    def _open_record_count(self, item_id: int) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) AS n FROM records WHERE item_id=? AND status='open'",
            (item_id,),
        ).fetchone()
        return int(row["n"])

    def _insert_audit(self, action: str, entity_type: str, entity_id: int,
                      actor: str, detail: dict) -> Dict[str, Any]:
        row = self.conn.execute(
            "SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        previous = row["entry_hash"] if row is not None else "GENESIS"
        event = make_entry(action, entity_type, entity_id, actor, detail, previous)
        cur = self.conn.execute(
            """INSERT INTO audit_events(action, entity_type, entity_id, actor, detail,
               previous_hash, entry_hash, created_at) VALUES(?,?,?,?,?,?,?,?)""",
            (event["action"], event["entity_type"], event["entity_id"], event["actor"],
             json.dumps(event["detail"], ensure_ascii=False, sort_keys=True),
             event["previous_hash"], event["entry_hash"], event["created_at"]),
        )
        event["id"] = int(cur.lastrowid)
        return event

    def _fetch_batch(self, batch_id: str) -> Optional[Dict[str, Any]]:
        row = self.conn.execute(
            "SELECT * FROM upload_batches WHERE batch_id=?", (batch_id,)).fetchone()
        if row is None:
            return None
        data = dict(row)
        data["result"] = json.loads(data["result"])
        return data

    def _insert_batch(self, batch_id: str, result: Dict[str, Any]) -> None:
        self.conn.execute(
            "INSERT INTO upload_batches(batch_id, result, created_at) VALUES(?,?,?)",
            (batch_id, json.dumps(result, ensure_ascii=False, sort_keys=True), utc_now()),
        )

    # ------------------------------------------------------------------
    # 对外事务性方法
    # ------------------------------------------------------------------

    def create_item(self, title: str, description: str, severity: str,
                    quantity: float, threshold: float, external_ref: Optional[str],
                    actor: str) -> Dict[str, Any]:
        with self._lock, self.conn:
            try:
                item_id = self._insert_item(title, description, severity, quantity,
                                            threshold, external_ref, actor)
            except sqlite3.IntegrityError as exc:
                raise ConflictError("external_ref已存在") from exc
            return self._fetch_item(item_id)

    def get_item(self, item_id: int) -> Dict[str, Any]:
        with self._lock:
            item = self._fetch_item(item_id)
            if item is None:
                raise NotFoundError("项目不存在")
            return item

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
        with self._lock, self.conn:
            rowcount = self._update_item_status(item_id, target, expected_version, actor)
            if rowcount == 0:
                exists = self.conn.execute("SELECT 1 FROM items WHERE id=?", (item_id,)).fetchone()
                if exists is None:
                    raise NotFoundError("项目不存在")
                raise ConflictError("版本冲突，请刷新后重试")
        return self.get_item(item_id)

    def add_record(self, item_id: int, kind: str, detail: str, status: str,
                   external_ref: Optional[str], actor: str) -> Dict[str, Any]:
        with self._lock, self.conn:
            if self._fetch_item(item_id) is None:
                raise NotFoundError("项目不存在")
            try:
                record_id = self._insert_record(item_id, kind, detail, status,
                                                external_ref, actor)
            except sqlite3.IntegrityError as exc:
                raise ConflictError("记录唯一标识已存在") from exc
            row = self.conn.execute(
                "SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
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
            return self._open_record_count(item_id)

    def append_audit(self, action: str, entity_type: str, entity_id: int,
                     actor: str, detail: dict) -> Dict[str, Any]:
        with self._lock, self.conn:
            return self._insert_audit(action, entity_type, entity_id, actor, detail)

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

    def get_batch(self, batch_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._fetch_batch(batch_id)

    def upload_batch(self, batch_id: str, operations: List[Dict[str, Any]],
                     actor: str, role: str,
                     judge: Callable[..., Dict[str, Any]]) -> Dict[str, Any]:
        """整批补传。

        同批次号重传沿用首次结果（幂等）。所有有效操作的改动与审计事件、
        以及批次结果在同一个事务中入库；judge 抛出的非业务异常会导致整批
        回滚，可整批重试。业务冲突（越权、跳级、版本前进等）由 judge 捕获
        并以 status=conflict 的形式进入结果，不影响同批其它有效操作。
        """
        with self._lock, self.conn:
            existing = self._fetch_batch(batch_id)
            if existing is not None:
                return existing["result"]
            results: List[Dict[str, Any]] = []
            for op in operations:
                outcome = judge(op, actor, role, self)
                results.append(outcome)
            conflicts = [r for r in results if r.get("status") == "conflict"]
            applied = [r for r in results if r.get("status") == "applied"]
            result: Dict[str, Any] = {
                "batch_id": batch_id,
                "results": results,
                "applied_count": len(applied),
                "conflict_count": len(conflicts),
                "conflicts": conflicts,
            }
            try:
                self._insert_batch(batch_id, result)
            except sqlite3.IntegrityError:
                existing = self._fetch_batch(batch_id)
                if existing is not None:
                    return existing["result"]
                raise
            return result

    def audit_chain_broken_at(self) -> Optional[int]:
        """核验审计链，返回首个出错的事件编号；链完整返回 None。

        缺行（前一行丢失）或行被篡改（内容被改）都会在当前事件处断开，
        返回该事件的 id。
        """
        with self._lock:
            rows = self.conn.execute("SELECT * FROM audit_events ORDER BY id").fetchall()
            previous = "GENESIS"
            for row in rows:
                if row["previous_hash"] != previous:
                    return int(row["id"])
                payload = {
                    "action": row["action"], "entity_type": row["entity_type"],
                    "entity_id": row["entity_id"], "actor": row["actor"],
                    "detail": json.loads(row["detail"]), "created_at": row["created_at"],
                }
                if calculate_hash(previous, payload) != row["entry_hash"]:
                    return int(row["id"])
                previous = row["entry_hash"]
        return None

    def verify_audit_chain(self) -> bool:
        return self.audit_chain_broken_at() is None

    def close(self) -> None:
        with self._lock:
            self.conn.close()
