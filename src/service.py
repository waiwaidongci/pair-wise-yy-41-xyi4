from __future__ import annotations

import json
from typing import Any, Dict, Optional

from .domain import (ConflictError, DomainError, NotFoundError,
                     PermissionDenied, ensure_role, normalize_severity,
                     require_number, require_text)
from .repository import Repository
from .rules import (AUDIT_ROLES, CREATE_ROLES, ENTITY, RECORD_ROLES, TITLE,
                    VIEW_ROLES, completion_blockers, escalation_required,
                    priority_score, response_deadline_hours, role_for_transition,
                    validate_transition)


TRAFFIC_NOTICE_KINDS = {
    "traffic_notice",
    "traffic_announcement",
    "traffic_authority_notice",
    "traffic_control",
    "traffic_control_notice",
    "traffic_order",
    "notice",
    "announcement",
    "restriction_notice",
    "交通通告",
    "交通公告",
    "限行通告",
    "限载通告",
    "交通管制通告",
}
OPERATION_ALIASES = {
    "create": "create",
    "create_item": "create",
    "deviation": "create",
    "register_deviation": "create",
    "偏差": "create",
    "偏差登记": "create",
    "登记偏差": "create",
    "deviation_register": "create",
    "record": "record",
    "add_record": "record",
    "issue": "record",
    "异常": "record",
    "异常事项": "record",
    "登记异常": "record",
    "anomaly": "record",
    "exception": "record",
    "abnormal_item": "record",
    "transition": "transition",
    "advance": "transition",
    "advance_restriction": "transition",
    "restriction": "transition",
    "限行": "transition",
    "限行推进": "transition",
    "推进": "transition",
    "traffic_restriction": "transition",
    "restrict": "transition",
    "promote": "transition",
}


class Service:
    def __init__(self, repository: Repository):
        self.repository = repository

    def _view(self, role: str) -> None:
        ensure_role(role, VIEW_ROLES)

    def create_item(self, payload: Dict[str, Any], actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, CREATE_ROLES)
        actor = require_text(actor, "actor", 100)
        normalize_severity(payload.get("severity"))
        with self.repository.transaction():
            item = self._create_item(payload, actor, audit_extra=None)
        return self.enrich(item)

    def _create_item(self, payload: Dict[str, Any], actor: str,
                     audit_extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        title = require_text(
            payload.get("title") or payload.get("name"), "title", 200
        )
        description = require_text(
            payload.get("description") or payload.get("detail")
            or payload.get("details"), "description"
        )
        severity = normalize_severity(payload.get("severity", "normal"))
        quantity = require_number(
            payload.get("quantity", payload.get("value", payload.get("deviation", 0))),
            "quantity"
        )
        threshold = require_number(
            payload.get("threshold", payload.get("threshold_value", 1)),
            "threshold", 0.000001
        )
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        item = self.repository.create_item(title, description, severity, quantity,
                                           threshold, external_ref, actor)
        detail = {
            "title": title, "severity": severity, "quantity": quantity,
            "threshold": threshold,
            "priority": priority_score(severity, quantity, threshold),
        }
        if external_ref is not None:
            detail["external_ref"] = external_ref
        if audit_extra:
            detail.update(audit_extra)
        self.repository.append_audit("create", ENTITY, item["id"], actor, detail)
        return item

    def add_record(self, item_id: int, payload: Dict[str, Any], actor: str,
                   role: str) -> Dict[str, Any]:
        actor = require_text(actor, "actor", 100)
        kind = require_text(payload.get("kind"), "kind", 100)
        self._ensure_record_role(role, kind)
        with self.repository.transaction():
            record = self._add_record(item_id, payload, actor, audit_extra=None)
        return record

    @staticmethod
    def _ensure_record_role(role: str, kind: str) -> None:
        allowed = set(RECORD_ROLES)
        if kind in TRAFFIC_NOTICE_KINDS:
            allowed.add("traffic_authority")
        ensure_role(role, allowed)

    def _add_record(self, item_id: int, payload: Dict[str, Any], actor: str,
                    audit_extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        kind = require_text(
            payload.get("kind") or payload.get("record_kind")
            or payload.get("category"), "kind", 100
        )
        detail = require_text(
            payload.get("detail") or payload.get("details")
            or payload.get("content") or payload.get("message"), "detail"
        )
        status = payload.get("status", "open")
        if status not in ("open", "closed"):
            raise ValueError("status必须是open或closed")
        external_ref = (payload.get("external_ref") or payload.get("record_ref")
                        or payload.get("client_ref"))
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        record = self.repository.add_record(item_id, kind, detail, status,
                                            external_ref, actor)
        audit_detail = {
            "record_id": record["id"], "kind": kind, "status": status,
        }
        if external_ref is not None:
            audit_detail["external_ref"] = external_ref
        if audit_extra:
            audit_detail.update(audit_extra)
        self.repository.append_audit("record", ENTITY, item_id, actor, audit_detail)
        return record

    def transition(self, item_id: int, target: str, expected_version: int,
                   actor: str, role: str) -> Dict[str, Any]:
        actor = require_text(actor, "actor", 100)
        target = require_text(target, "target", 50)
        if not isinstance(expected_version, int) or isinstance(expected_version, bool) or expected_version < 1:
            raise ValueError("expected_version必须是正整数")
        with self.repository.transaction():
            item = self.repository.get_item(item_id)
            validate_transition(item["status"], target)
            ensure_role(role, role_for_transition(target))
            blockers = completion_blockers(
                target, self.repository.open_record_count(item_id)
            )
            if blockers:
                raise ConflictError("；".join(blockers))
            updated = self._transition(item, target, expected_version, actor,
                                       client_version=expected_version,
                                       audit_extra=None)
        return self.enrich(updated)

    def _transition(self, item: Dict[str, Any], target: str,
                    expected_version: Optional[int], actor: str,
                    client_version: Optional[int] = None,
                    audit_extra: Optional[Dict[str, Any]] = None,
                    require_traffic_notice: bool = False) -> Dict[str, Any]:
        blockers = list(completion_blockers(
            target, self.repository.open_record_count(item["id"])
        ))
        if require_traffic_notice and target in ("restricted", "closed"):
            records = self.repository.list_records(item["id"])
            if not any(record["kind"] in TRAFFIC_NOTICE_KINDS for record in records):
                blockers.append("限行或封闭决策必须绑定交通通告记录")
        if blockers:
            raise ConflictError("；".join(blockers))

        # 离线补传不沿用车辆端陈旧版本：以服务端当前版本做条件更新。
        server_version = item["version"]
        updated = self.repository.transition_item(
            item["id"], target, expected_version, actor
        )
        detail = {
            "from": item["status"], "to": target,
            "server_version_before": server_version,
            "escalation_required": escalation_required(
                item["severity"], item["quantity"], item["threshold"]),
        }
        if client_version is not None and client_version != server_version:
            detail["client_expected_version"] = client_version
            detail["rebased_to_version"] = server_version
        if audit_extra:
            detail.update(audit_extra)
        self.repository.append_audit("transition", ENTITY, item["id"], actor, detail)
        return updated

    def sync_offline_batch(self, payload: Dict[str, Any], actor: Optional[str] = None,
                           role: Optional[str] = None) -> Dict[str, Any]:
        return self.sync_batch(payload, actor, role)

    def upload_offline_batch(self, payload: Dict[str, Any], actor: Optional[str] = None,
                             role: Optional[str] = None) -> Dict[str, Any]:
        return self.sync_batch(payload, actor, role)

    def process_offline_batch(self, payload: Dict[str, Any], actor: Optional[str] = None,
                              role: Optional[str] = None) -> Dict[str, Any]:
        return self.sync_batch(payload, actor, role)

    def upload_batch(self, payload: Dict[str, Any], actor: Optional[str] = None,
                     role: Optional[str] = None) -> Dict[str, Any]:
        return self.sync_batch(payload, actor, role)

    def process_batch(self, payload: Dict[str, Any], actor: Optional[str] = None,
                      role: Optional[str] = None) -> Dict[str, Any]:
        return self.sync_batch(payload, actor, role)

    def offline_sync(self, payload: Dict[str, Any], actor: Optional[str] = None,
                     role: Optional[str] = None) -> Dict[str, Any]:
        return self.sync_batch(payload, actor, role)

    def sync_offline(self, payload: Dict[str, Any], actor: Optional[str] = None,
                     role: Optional[str] = None) -> Dict[str, Any]:
        return self.sync_batch(payload, actor, role)

    def apply_batch(self, payload: Dict[str, Any], actor: Optional[str] = None,
                    role: Optional[str] = None) -> Dict[str, Any]:
        return self.sync_batch(payload, actor, role)

    def sync_batch(self, payload: Dict[str, Any], actor: Optional[str] = None,
                   role: Optional[str] = None) -> Dict[str, Any]:
        batch_id = (payload.get("batch_id") or payload.get("batch_no")
                    or payload.get("batch_number") or payload.get("batchNo")
                    or payload.get("sync_id") or payload.get("id"))
        batch_id = require_text(batch_id, "batch_id", 100)
        raw_operations = (payload.get("operations") or payload.get("ops")
                          or payload.get("items") or payload.get("events")
                          or payload.get("actions") or payload.get("entries")
                          or payload.get("records"))
        if not isinstance(raw_operations, list) or not raw_operations:
            raise ValueError("operations必须是非空数组")

        batch_actor = require_text(
            actor or payload.get("actor") or payload.get("operator")
            or "offline-vehicle", "actor", 100
        )
        canonical_request = json.dumps(
            payload, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":")
        )

        with self.repository.transaction():
            existing = self.repository.get_batch_upload(batch_id)
            if existing is not None:
                if existing["request_json"] != canonical_request:
                    raise ConflictError(f"批次号{batch_id}已存在但请求内容不同")
                result = json.loads(existing["response_json"])
                result["replayed"] = True
                result["idempotent"] = True
                result["replay"] = True
                return result

            local_refs: Dict[str, int] = {}
            results = []
            conflicts = []

            for index, raw_op in enumerate(raw_operations):
                op_id = str(index + 1)
                op_type = "unknown"
                op: Dict[str, Any] = {}
                op_result = None

                try:
                    if not isinstance(raw_op, dict):
                        raise ValueError("每条操作必须是JSON对象")
                    op = dict(raw_op)
                    op_id = str(op.get("op_id") or op.get("operation_id")
                                or op.get("client_op_id") or index + 1)
                    with self.repository.savepoint():
                        op_type = self._operation_type(op)
                        op_actor = require_text(
                            op.get("actor") or op.get("operator")
                            or op.get("created_by") or batch_actor, "actor", 100
                        )
                        op_role = (op.get("role") or op.get("actor_role") or role
                                   or payload.get("role") or "")
                        common_audit = {
                            "batch_id": batch_id, "op_id": op_id, "source": "offline"
                        }
                        if op_type == "create":
                            self._validate_batch_role(op_role, CREATE_ROLES)
                            created = self._create_item(op, op_actor, common_audit)
                            op_result = self.enrich(created)
                            local_ref = (op.get("local_ref") or op.get("local_alert_ref")
                                         or op.get("client_ref") or op.get("ref"))
                            if local_ref is not None:
                                local_refs[str(local_ref)] = created["id"]
                        elif op_type == "record":
                            self._resolve_item_ref(op, local_refs)
                            kind = require_text(op.get("kind"), "kind", 100)
                            self._ensure_record_role(op_role, kind)
                            item_id = int(op["item_id"])
                            op_result = self._add_record(item_id, op, op_actor, common_audit)
                        else:
                            self._resolve_item_ref(op, local_refs)
                            item_id = int(op["item_id"])
                            item = self.repository.get_item(item_id)
                            target = (op.get("target") or op.get("to")
                                      or op.get("next_status") or op.get("new_status"))
                            if target in (None, ""):
                                target = self._next_state(item["status"])
                            target = require_text(target, "target", 50)
                            validate_transition(item["status"], target)
                            self._validate_batch_role(op_role, role_for_transition(target))
                            client_version = op.get(
                                "expected_version",
                                op.get("client_version", op.get(
                                    "base_version", op.get("offline_version")
                                ))
                            )
                            if client_version is not None and (
                                not isinstance(client_version, int)
                                or isinstance(client_version, bool)
                                or client_version < 1
                            ):
                                raise ValueError("expected_version必须是正整数")
                            op_result = self.enrich(self._transition(
                                item, target, item["version"], op_actor,
                                client_version=client_version,
                                audit_extra=common_audit,
                                require_traffic_notice=True,
                            ))
                    applied = {
                        "index": index,
                        "op_id": op_id,
                        "type": op_type,
                        "status": "applied",
                        "result": op_result,
                    }
                    results.append(applied)
                except (DomainError, ValueError) as exc:
                    conflict = self._conflict(index, op_id, op_type, exc, op, local_refs)
                    conflicts.append(conflict)
                    results.append(dict(conflict, status="conflict"))

            status = "accepted" if not conflicts else "processed_with_conflicts"
            partial = bool(conflicts)
            applied_ops = [item for item in results if item.get("status") == "applied"]
            result = {
                "batch_id": batch_id,
                "status": status,
                "ok": not conflicts,
                "partial_success": partial,
                "has_conflicts": partial,
                "replayed": False,
                "idempotent": False,
                "applied_count": len(applied_ops),
                "successful_count": len(applied_ops),
                "accepted_count": len(applied_ops),
                "conflict_count": len(conflicts),
                "results": results,
                "applied": applied_ops,
                "successful": applied_ops,
                "conflicts": conflicts,
                "conflict_items": conflicts,
                "failures": conflicts,
            }
            response_json = json.dumps(
                result, ensure_ascii=False, sort_keys=True, default=str,
                separators=(",", ":")
            )
            self.repository.save_batch_upload(
                batch_id, batch_actor, canonical_request, response_json, status
            )
            return result

    @staticmethod
    def _operation_type(op: Dict[str, Any]) -> str:
        value = (op.get("type") or op.get("op") or op.get("operation")
                 or op.get("operation_type") or op.get("action") or op.get("kind_type"))
        if value in (None, ""):
            if any(key in op for key in ("target", "to", "advance", "next_status", "new_status")):
                value = "transition"
            elif "kind" in op or "detail" in op:
                value = "record"
            elif "title" in op:
                value = "create"
        value = str(value).strip().lower() if isinstance(value, str) else value
        normalized = OPERATION_ALIASES.get(value)
        if normalized is None:
            raise ValueError(f"不支持的离线操作类型: {value}")
        return normalized

    @staticmethod
    def _next_state(current: str) -> str:
        from .rules import TRANSITIONS

        next_states = TRANSITIONS.get(current, [])
        if not next_states:
            raise ConflictError(f"状态{current}已不能继续推进")
        return next_states[0]

    def _resolve_item_ref(self, op: Dict[str, Any], local_refs: Dict[str, int]) -> None:
        if op.get("item_id") not in (None, ""):
            try:
                op["item_id"] = int(op["item_id"])
            except (TypeError, ValueError) as exc:
                raise ValueError("item_id必须是整数") from exc
            return
        if op.get("alert_id") not in (None, ""):
            try:
                op["item_id"] = int(op["alert_id"])
                return
            except (TypeError, ValueError) as exc:
                raise ValueError("alert_id必须是整数") from exc
        local_ref = (op.get("local_item_ref") or op.get("local_alert_ref")
                     or op.get("local_ref") or op.get("client_ref") or op.get("ref"))
        if local_ref is not None and str(local_ref) in local_refs:
            op["item_id"] = local_refs[str(local_ref)]
            return
        external_ref = (op.get("item_external_ref") or op.get("alert_external_ref")
                        or op.get("external_ref") or op.get("item_ref")
                        or op.get("alert_ref"))
        if external_ref not in (None, ""):
            item = self.repository.get_item_by_external_ref(str(external_ref))
            op["item_id"] = item["id"]
            return
        raise NotFoundError("缺少item_id或可解析的告警引用")

    @staticmethod
    def _first_present(payload: Dict[str, Any], *keys: str) -> Any:
        for key in keys:
            if key in payload:
                return payload[key]
        return None

    @staticmethod
    def _validate_batch_role(actual_role: str, allowed) -> None:
        if not actual_role:
            raise PermissionDenied("当前操作缺少角色")
        ensure_role(actual_role, allowed)

    def _conflict(self, index: int, op_id: str, op_type: str, exc: Exception,
                  op: Dict[str, Any], local_refs: Dict[str, int]) -> Dict[str, Any]:
        if isinstance(exc, PermissionDenied):
            code = "UNAUTHORIZED_OPERATION"
            reason = "permission_denied"
        elif isinstance(exc, NotFoundError):
            code = "REFERENCE_NOT_FOUND"
            reason = "reference_not_found"
        elif isinstance(exc, ConflictError):
            code = "TRANSITION_OR_STATE_CONFLICT"
            reason = "state_transition_conflict"
        else:
            code = "INVALID_OPERATION"
            reason = "invalid_operation"
        conflict = {
            "index": index,
            "op_id": op_id,
            "operation_id": op_id,
            "type": op_type,
            "error": exc.__class__.__name__,
            "code": code,
            "error_code": code,
            "reason": reason,
            "message": str(exc),
        }
        item_id = op.get("item_id")
        if item_id not in (None, ""):
            try:
                conflict["item_id"] = int(item_id)
            except (TypeError, ValueError):
                pass
        expected = self._first_present(
            op, "expected_version", "client_version", "base_version", "offline_version"
        )
        if expected is not None:
            conflict["expected_version"] = expected
        return conflict

    def get_item(self, item_id: int, role: str) -> Dict[str, Any]:
        self._view(role)
        return self.enrich(self.repository.get_item(item_id))

    def list_items(self, role: str, status: Optional[str] = None) -> list:
        self._view(role)
        return [self.enrich(item) for item in self.repository.list_items(status)]

    def list_records(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_records(item_id)

    def audit(self, role: str, item_id: Optional[int] = None,
              verify: bool = False):
        ensure_role(role, AUDIT_ROLES)
        if verify:
            return self.repository.audit_chain_status()
        return self.repository.list_audit(item_id)

    def audit_chain_status(self, role: str) -> Dict[str, Any]:
        ensure_role(role, AUDIT_ROLES)
        return self.repository.audit_chain_status()

    def verify_audit_chain(self, role: str) -> Dict[str, Any]:
        return self.audit_chain_status(role)

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
