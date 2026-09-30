from __future__ import annotations

import sqlite3
from typing import Any, Dict, List, Optional

from .domain import (ConflictError, NotFoundError, PermissionDenied,
                     ValidationError, ensure_role, normalize_severity,
                     require_number, require_text)
from .repository import Repository
from .rules import (AUDIT_ROLES, CREATE_ROLES, ENTITY, RECORD_ROLES, STATES,
                    TITLE, VIEW_ROLES, completion_blockers, escalation_required,
                    priority_score, response_deadline_hours, role_for_transition,
                    validate_transition)


class Service:
    def __init__(self, repository: Repository):
        self.repository = repository

    def _view(self, role: str) -> None:
        ensure_role(role, VIEW_ROLES)

    def create_item(self, payload: Dict[str, Any], actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, CREATE_ROLES)
        actor = require_text(actor, "actor", 100)
        title = require_text(payload.get("title"), "title", 200)
        description = require_text(payload.get("description"), "description")
        severity = normalize_severity(payload.get("severity"))
        quantity = require_number(payload.get("quantity", 0), "quantity")
        threshold = require_number(payload.get("threshold", 1), "threshold", 0.000001)
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        item = self.repository.create_item(title, description, severity, quantity,
                                           threshold, external_ref, actor)
        self.repository.append_audit("create", ENTITY, item["id"], actor, {
            "title": title, "severity": severity, "quantity": quantity,
            "priority": priority_score(severity, quantity, threshold),
        })
        return self.enrich(item)

    def add_record(self, item_id: int, payload: Dict[str, Any], actor: str,
                   role: str) -> Dict[str, Any]:
        ensure_role(role, RECORD_ROLES)
        actor = require_text(actor, "actor", 100)
        kind = require_text(payload.get("kind"), "kind", 100)
        detail = require_text(payload.get("detail"), "detail")
        status = payload.get("status", "open")
        if status not in ("open", "closed"):
            raise ValueError("status必须是open或closed")
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        record = self.repository.add_record(item_id, kind, detail, status,
                                            external_ref, actor)
        self.repository.append_audit("record", ENTITY, item_id, actor, {
            "record_id": record["id"], "kind": kind, "status": status,
        })
        return record

    def transition(self, item_id: int, target: str, expected_version: int,
                   actor: str, role: str) -> Dict[str, Any]:
        actor = require_text(actor, "actor", 100)
        item = self.repository.get_item(item_id)
        validate_transition(item["status"], target)
        ensure_role(role, role_for_transition(target))
        if not isinstance(expected_version, int) or expected_version < 1:
            raise ValueError("expected_version必须是正整数")
        blockers = completion_blockers(target, self.repository.open_record_count(item_id))
        if blockers:
            from .domain import ConflictError
            raise ConflictError("；".join(blockers))
        updated = self.repository.transition_item(item_id, target, expected_version, actor)
        self.repository.append_audit("transition", ENTITY, item_id, actor, {
            "from": item["status"], "to": target,
            "escalation_required": escalation_required(
                item["severity"], item["quantity"], item["threshold"]),
        })
        return self.enrich(updated)

    def get_item(self, item_id: int, role: str) -> Dict[str, Any]:
        self._view(role)
        return self.enrich(self.repository.get_item(item_id))

    def list_items(self, role: str, status: Optional[str] = None) -> list:
        self._view(role)
        return [self.enrich(item) for item in self.repository.list_items(status)]

    def list_records(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_records(item_id)

    def audit(self, role: str, item_id: Optional[int] = None) -> list:
        ensure_role(role, AUDIT_ROLES)
        return self.repository.list_audit(item_id)

    def audit_chain_status(self, role: str) -> Dict[str, Any]:
        ensure_role(role, AUDIT_ROLES)
        broken_at = self.repository.audit_chain_broken_at()
        return {"chain_valid": broken_at is None, "broken_at": broken_at}

    def get_batch(self, batch_id: str, role: str) -> Dict[str, Any]:
        self._view(role)
        batch = self.repository.get_batch(batch_id)
        if batch is None:
            raise NotFoundError("批次不存在")
        return batch["result"]

    def upload_batch(self, batch_id: str, operations: List[Dict[str, Any]],
                     actor: str, role: str) -> Dict[str, Any]:
        """离线整批补传。

        每条操作按角色与流转规则逐条判定：越权或跳级的进入冲突清单，
        不影响同批其它有效操作；所有有效操作的改动与审计事件在同一事务
        入库，失败整批回滚。同批次号重传沿用首次结果。
        """
        actor = require_text(actor, "actor", 100)
        batch_id = require_text(batch_id, "batch_id", 100)
        if not isinstance(operations, list) or len(operations) == 0:
            raise ValidationError("operations必须是非空列表")
        for i, op in enumerate(operations):
            if not isinstance(op, dict):
                raise ValidationError(f"operations[{i}]必须是JSON对象")
            op_type = op.get("type")
            if op_type not in ("record", "transition"):
                raise ValidationError(f"operations[{i}]的type必须是record或transition")

        def judge(op: Dict[str, Any], _actor: str, _role: str,
                  repo: Repository) -> Dict[str, Any]:
            try:
                if op["type"] == "record":
                    return self._judge_record(op, _actor, _role, repo)
                return self._judge_transition(op, _actor, _role, repo)
            except (ValidationError, NotFoundError, PermissionDenied, ConflictError) as exc:
                return {
                    "status": "conflict",
                    "client_op_id": op.get("client_op_id"),
                    "kind": op["type"],
                    "error": exc.kind,
                    "message": exc.message,
                }

        return self.repository.upload_batch(batch_id, operations, actor, role, judge)

    def _judge_record(self, op: Dict[str, Any], actor: str, role: str,
                      repo: Repository) -> Dict[str, Any]:
        ensure_role(role, RECORD_ROLES)
        item_id = op.get("item_id")
        if not isinstance(item_id, int) or isinstance(item_id, bool) or item_id < 1:
            raise ValidationError("item_id必须是正整数")
        kind = require_text(op.get("kind"), "kind", 100)
        detail = require_text(op.get("detail"), "detail")
        status = op.get("status", "open")
        if status not in ("open", "closed"):
            raise ValidationError("status必须是open或closed")
        external_ref = op.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        if repo._fetch_item(item_id) is None:
            raise NotFoundError("项目不存在")
        try:
            record_id = repo._insert_record(item_id, kind, detail, status,
                                             external_ref, actor)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("记录唯一标识已存在") from exc
        record = dict(repo.conn.execute(
            "SELECT * FROM records WHERE id=?", (record_id,)).fetchone())
        repo._insert_audit("record", ENTITY, item_id, actor, {
            "record_id": record_id, "kind": kind, "status": status,
        })
        return {"status": "applied", "client_op_id": op.get("client_op_id"),
                "kind": "record", "record": record}

    def _judge_transition(self, op: Dict[str, Any], actor: str, role: str,
                          repo: Repository) -> Dict[str, Any]:
        item_id = op.get("item_id")
        if not isinstance(item_id, int) or isinstance(item_id, bool) or item_id < 1:
            raise ValidationError("item_id必须是正整数")
        target = op.get("target")
        if not isinstance(target, str) or target not in STATES:
            raise ValidationError("未知状态")
        expected_version = op.get("expected_version")
        if (not isinstance(expected_version, int) or isinstance(expected_version, bool)
                or expected_version < 1):
            raise ValidationError("expected_version必须是正整数")
        item = repo._fetch_item(item_id)
        if item is None:
            raise NotFoundError("项目不存在")
        # 离线期间告警版本可能已前进，按服务端当前状态重新判定流转与角色，
        # 越权或跳级（含目标已被服务端越过）的进入冲突清单。
        validate_transition(item["status"], target)
        ensure_role(role, role_for_transition(target))
        blockers = completion_blockers(target, repo._open_record_count(item_id))
        if blockers:
            raise ConflictError("；".join(blockers))
        rowcount = repo._update_item_status(item_id, target, item["version"], actor)
        if rowcount == 0:
            raise ConflictError("版本冲突，请刷新后重试")
        updated = repo._fetch_item(item_id)
        repo._insert_audit("transition", ENTITY, item_id, actor, {
            "from": item["status"], "to": target,
            "escalation_required": escalation_required(
                item["severity"], item["quantity"], item["threshold"]),
        })
        return {"status": "applied", "client_op_id": op.get("client_op_id"),
                "kind": "transition", "item": Service.enrich(updated)}

    @staticmethod
    def enrich(item: Dict[str, Any]) -> Dict[str, Any]:
        result = dict(item)
        result["priority"] = priority_score(
            item["severity"], item["quantity"], item["threshold"])
        result["deadline_hours"] = response_deadline_hours(
            item["severity"], item["quantity"], item["threshold"])
        result["escalation_required"] = escalation_required(
            item["severity"], item["quantity"], item["threshold"])
        return result
