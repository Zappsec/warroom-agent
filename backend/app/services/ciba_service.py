from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import HTTPException
from sqlalchemy import update
from sqlalchemy.orm import Session

from app.config import get_settings
from app.integrations.auth0_ciba_adapter import Auth0CIBAAdapter
from app.models.audit_entry import AuditEntry
from app.models.planned_action import PlannedAction
from app.security.auth0_jwt import decode_jwt_token, extract_permission_set
from app.security.fga_client import FGAAuthorizationError, fga_client
from app.services.execution_engine import _execute_single_action

logger = logging.getLogger(__name__)

EXECUTE_REMEDIATION = "execute:remediation"
SENSITIVE_GITHUB_ACTIONS = {"github_app_repo_update", "github_network_repo_update"}

CIBA_METADATA_KEY = "ciba"
CIBA_METADATA_VERSION = 1

CIBA_STATE_AUTHORIZATION_PENDING = "authorization_pending"
CIBA_STATE_APPROVAL_RECEIVED = "approval_received"
CIBA_STATE_EXECUTION_IN_PROGRESS = "execution_in_progress"
CIBA_STATE_EXECUTED = "executed"
CIBA_STATE_EXECUTION_FAILED = "execution_failed"
CIBA_STATE_DENIED = "denied"
CIBA_STATE_EXPIRED = "expired"
CIBA_STATE_FAILED = "failed"

TERMINAL_CIBA_STATES = {
    CIBA_STATE_EXECUTED,
    CIBA_STATE_EXECUTION_FAILED,
    CIBA_STATE_DENIED,
    CIBA_STATE_EXPIRED,
    CIBA_STATE_FAILED,
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def _parse_iso(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value)
    except Exception:
        return None


def _load_metadata(action: PlannedAction) -> dict[str, Any]:
    raw = action.metadata_json or "{}"
    if isinstance(raw, dict):
        return raw
    try:
        return json.loads(raw)
    except Exception:
        return {}


def _save_metadata(action: PlannedAction, metadata: dict[str, Any]) -> None:
    action.metadata_json = json.dumps(metadata)


def _sanitize_binding_message(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9+\-_\.,:# ]", "-", value or "")
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if not cleaned:
        cleaned = "warroom-remediation-approval"
    return cleaned[:64]


def _build_binding_message(action: PlannedAction) -> str:
    short_incident = (action.incident_id or "incident").split("-")[0]
    short_action = action.action_type.replace("_", "-")
    return _sanitize_binding_message(f"{short_incident}:{short_action}:approve")


def _add_audit_entry(
    db: Session,
    *,
    incident_id: str,
    action_id: str,
    actor_type: str,
    actor_id: str | None,
    actor_name: str,
    event_name: str,
    target_system: str,
    details: dict[str, Any],
    execution_status: str | None = None,
) -> None:
    db.add(
        AuditEntry(
            id=str(uuid.uuid4()),
            incident_id=incident_id,
            action_id=action_id,
            actor_type=actor_type,
            actor_id=actor_id,
            actor_name=actor_name,
            event_name=event_name,
            target_system=target_system,
            details_json=json.dumps(details),
            execution_status=execution_status,
            timestamp=_utcnow(),
        )
    )


class CIBAService:
    def __init__(self):
        settings = get_settings()
        self.adapter = Auth0CIBAAdapter()
        self.app_remediation_owner_sub = (
            settings.AUTH0_APP_REMEDIATION_OWNER_SUB or fga_client.app_remediation_owner_sub
        )
        self.network_remediation_owner_sub = (
            settings.AUTH0_NETWORK_REMEDIATION_OWNER_SUB or fga_client.network_remediation_owner_sub
        )

    @property
    def enabled(self) -> bool:
        return self.adapter.is_configured

    def is_enabled_for_action(self, action: PlannedAction) -> bool:
        return self.enabled and action.action_type in SENSITIVE_GITHUB_ACTIONS

    def start_for_action(
        self,
        *,
        db: Session,
        action: PlannedAction,
        initiated_by: dict[str, Any],
    ) -> dict[str, Any]:
        self._ensure_supported_action(action)

        # Defence-in-depth: verify the console operator is authorized for
        # this specific remediation before sending any CIBA request.
        operator_sub = initiated_by.get("sub")
        if operator_sub:
            fga_client.require_action_execution(
                user_sub=operator_sub,
                action=action,
            )

        if action.approval_status != "approved":
            raise HTTPException(status_code=400, detail="Action must be approved before CIBA starts")

        if action.execution_status in {"executed", "executing"}:
            raise HTTPException(status_code=409, detail=f"Action already {action.execution_status}")

        metadata = _load_metadata(action)
        existing = self._get_ciba_record(metadata)
        existing_status = self._status(existing)
        expires_at = _parse_iso(existing.get("request", {}).get("expires_at"))
        now = _utcnow()

        if (
            existing.get("request", {}).get("auth_req_id")
            and existing_status not in TERMINAL_CIBA_STATES
            and expires_at
            and expires_at > now
        ):
            logger.info(
                "[CIBA SERVICE] reusing pending request action_id=%s auth_req_id=%s status=%s execution_status=%s",
                action.id,
                existing.get("request", {}).get("auth_req_id"),
                existing_status,
                action.execution_status,
            )
            return self._status_payload(action, existing)

        owner_sub, owner_resolution_source = self._resolve_owner_sub(action, metadata)
        binding_message = _build_binding_message(action)

        adapter_result = self.adapter.start_backchannel_authentication(
            user_sub=owner_sub,
            binding_message=binding_message,
        )
        if not adapter_result.get("success"):
            raise HTTPException(
                status_code=502,
                detail=f"Failed to start CIBA request: {adapter_result.get('error', 'unknown error')}",
            )

        ciba_record = {
            "version": CIBA_METADATA_VERSION,
            "provider": "auth0_ciba",
            "status": CIBA_STATE_AUTHORIZATION_PENDING,
            "request": {
                "auth_req_id": adapter_result.get("auth_req_id"),
                "binding_message": binding_message,
                "requested_at": _iso(now),
                "expires_at": _iso(now + timedelta(seconds=int(adapter_result.get("expires_in", 300)))),
                "poll_interval_seconds": int(
                    adapter_result.get("interval", self.adapter.default_poll_interval)
                ),
                "last_polled_at": None,
                "last_poll_error": None,
                "last_poll_error_description": None,
            },
            "principal": {
                "console_operator_sub": initiated_by.get("sub"),
                "console_operator_email": initiated_by.get("email"),
                "console_operator_name": initiated_by.get("name"),
                "target_owner_sub": owner_sub,
                "owner_resolution_source": owner_resolution_source,
                "approved_sub": None,
                "approved_email": None,
                "execution_sub": None,
                "execution_email": None,
                "execution_mode": "remediation_owner_ciba_token",
            },
            "approval": {
                "approved_at": None,
            },
            "execution": {
                "execution_id": str(uuid.uuid4()),
                "status": "not_started",
                "started_at": None,
                "completed_at": None,
                "result": None,
            },
        }
        metadata[CIBA_METADATA_KEY] = ciba_record
        _save_metadata(action, metadata)

        logger.info(
            "[CIBA SERVICE] started action_id=%s incident_id=%s auth_req_id=%s console_operator_sub=%s target_owner_sub=%s owner_resolution_source=%s execution_mode=%s",
            action.id,
            action.incident_id,
            ciba_record["request"]["auth_req_id"],
            ciba_record["principal"]["console_operator_sub"],
            ciba_record["principal"]["target_owner_sub"],
            ciba_record["principal"]["owner_resolution_source"],
            ciba_record["principal"]["execution_mode"],
        )

        _add_audit_entry(
            db,
            incident_id=action.incident_id,
            action_id=action.id,
            actor_type="human",
            actor_id=initiated_by.get("sub"),
            actor_name=initiated_by.get("name") or initiated_by.get("email") or "Operator",
            event_name=f"CIBA requested: {action.title}",
            target_system="Auth0 CIBA",
            execution_status="pending",
            details={
                "initiatedBySub": initiated_by.get("sub"),
                "initiatedByEmail": initiated_by.get("email"),
                "targetOwnerSub": owner_sub,
                "ownerResolutionSource": owner_resolution_source,
                "authReqId": ciba_record["request"]["auth_req_id"],
                "bindingMessage": binding_message,
                "executionMode": ciba_record["principal"]["execution_mode"],
                "executionId": ciba_record["execution"]["execution_id"],
            },
        )
        db.commit()
        db.refresh(action)
        return self._status_payload(action, ciba_record)

    def get_status_for_action(
        self,
        *,
        db: Session,
        action: PlannedAction,
        polled_by: dict[str, Any],
    ) -> dict[str, Any]:
        self._ensure_supported_action(action)

        metadata = _load_metadata(action)
        ciba_record = self._get_ciba_record(metadata)
        if not ciba_record.get("request", {}).get("auth_req_id"):
            raise HTTPException(status_code=404, detail="No CIBA request found for action")

        status_name = self._status(ciba_record)
        logger.info(
            "[CIBA SERVICE] status check action_id=%s status=%s action_execution_status=%s polled_by_sub=%s console_operator_sub=%s target_owner_sub=%s approved_sub=%s execution_sub=%s execution_id=%s",
            action.id,
            status_name,
            action.execution_status,
            polled_by.get("sub"),
            ciba_record.get("principal", {}).get("console_operator_sub"),
            ciba_record.get("principal", {}).get("target_owner_sub"),
            ciba_record.get("principal", {}).get("approved_sub"),
            ciba_record.get("principal", {}).get("execution_sub"),
            ciba_record.get("execution", {}).get("execution_id"),
        )

        if status_name == CIBA_STATE_EXECUTION_IN_PROGRESS:
            return self._handle_execution_in_progress(
                db=db,
                action=action,
                metadata=metadata,
                ciba_record=ciba_record,
            )

        if status_name in TERMINAL_CIBA_STATES:
            return self._status_payload(action, ciba_record)

        expires_at = _parse_iso(ciba_record.get("request", {}).get("expires_at"))
        now = _utcnow()
        if expires_at and expires_at <= now:
            ciba_record["status"] = CIBA_STATE_EXPIRED
            ciba_record["request"]["last_poll_error"] = "expired_token"
            ciba_record["request"]["last_poll_error_description"] = "CIBA request expired before approval"
            metadata[CIBA_METADATA_KEY] = ciba_record
            _save_metadata(action, metadata)
            _add_audit_entry(
                db,
                incident_id=action.incident_id,
                action_id=action.id,
                actor_type="system",
                actor_id=None,
                actor_name="WarRoom Agent",
                event_name=f"CIBA expired: {action.title}",
                target_system="Auth0 CIBA",
                execution_status="failed",
                details={
                    "polledBySub": polled_by.get("sub"),
                    "targetOwnerSub": ciba_record.get("principal", {}).get("target_owner_sub"),
                    "executionId": ciba_record.get("execution", {}).get("execution_id"),
                },
            )
            db.commit()
            db.refresh(action)
            return self._status_payload(action, ciba_record)

        poll_result = self.adapter.poll_backchannel_authentication(
            auth_req_id=str(ciba_record["request"]["auth_req_id"])
        )
        ciba_record["request"]["last_polled_at"] = _iso(now)
        ciba_record["request"]["poll_interval_seconds"] = int(
            poll_result.get(
                "interval",
                ciba_record.get("request", {}).get("poll_interval_seconds")
                or self.adapter.default_poll_interval,
            )
        )

        if poll_result.get("success"):
            try:
                return self._handle_approved_token(
                    db=db,
                    action=action,
                    metadata=metadata,
                    ciba_record=ciba_record,
                    access_token=str(poll_result.get("access_token") or ""),
                )
            except Exception as exc:
                logger.exception("[CIBA SERVICE] approved token handling failed action_id=%s", action.id)
                ciba_record["status"] = CIBA_STATE_FAILED
                ciba_record["request"]["last_poll_error"] = "ciba_approved_execution_failed"
                ciba_record["request"]["last_poll_error_description"] = str(exc)
                metadata[CIBA_METADATA_KEY] = ciba_record
                _save_metadata(action, metadata)
                if action.execution_status == "executing":
                    action.execution_status = "failed"
                    action.executed_at = _utcnow()
                _add_audit_entry(
                    db,
                    incident_id=action.incident_id,
                    action_id=action.id,
                    actor_type="system",
                    actor_id=None,
                    actor_name="WarRoom Agent",
                    event_name=f"CIBA failed after approval: {action.title}",
                    target_system="Auth0 CIBA",
                    execution_status="failed",
                    details={
                        "polledBySub": polled_by.get("sub"),
                        "targetOwnerSub": ciba_record.get("principal", {}).get("target_owner_sub"),
                        "executionId": ciba_record.get("execution", {}).get("execution_id"),
                        "error": ciba_record["request"]["last_poll_error"],
                        "errorDescription": ciba_record["request"]["last_poll_error_description"],
                    },
                )
                db.commit()
                db.refresh(action)
                return self._status_payload(action, ciba_record)

        if poll_result.get("pending"):
            ciba_record["status"] = CIBA_STATE_AUTHORIZATION_PENDING
            ciba_record["request"]["last_poll_error"] = poll_result.get("error")
            ciba_record["request"]["last_poll_error_description"] = poll_result.get("error_description")
            metadata[CIBA_METADATA_KEY] = ciba_record
            _save_metadata(action, metadata)
            db.commit()
            logger.info(
                "[CIBA SERVICE] still pending action_id=%s auth_req_id=%s interval=%s",
                action.id,
                ciba_record["request"]["auth_req_id"],
                ciba_record["request"]["poll_interval_seconds"],
            )
            return self._status_payload(action, ciba_record)

        terminal_error = str(poll_result.get("error") or "ciba_failed")
        ciba_record["status"] = CIBA_STATE_DENIED if terminal_error == "access_denied" else CIBA_STATE_FAILED
        if terminal_error == "expired_token":
            ciba_record["status"] = CIBA_STATE_EXPIRED
        ciba_record["request"]["last_poll_error"] = terminal_error
        ciba_record["request"]["last_poll_error_description"] = poll_result.get("error_description")
        metadata[CIBA_METADATA_KEY] = ciba_record
        _save_metadata(action, metadata)
        _add_audit_entry(
            db,
            incident_id=action.incident_id,
            action_id=action.id,
            actor_type="system",
            actor_id=None,
            actor_name="WarRoom Agent",
            event_name=f"CIBA {ciba_record['status']}: {action.title}",
            target_system="Auth0 CIBA",
            execution_status="failed",
            details={
                "polledBySub": polled_by.get("sub"),
                "targetOwnerSub": ciba_record.get("principal", {}).get("target_owner_sub"),
                "executionId": ciba_record.get("execution", {}).get("execution_id"),
                "error": terminal_error,
                "errorDescription": ciba_record["request"]["last_poll_error_description"],
            },
        )
        db.commit()
        db.refresh(action)
        logger.warning(
            "[CIBA SERVICE] terminal failure action_id=%s status=%s error=%s",
            action.id,
            ciba_record["status"],
            terminal_error,
        )
        return self._status_payload(action, ciba_record)

    def _handle_approved_token(
        self,
        *,
        db: Session,
        action: PlannedAction,
        metadata: dict[str, Any],
        ciba_record: dict[str, Any],
        access_token: str,
    ) -> dict[str, Any]:
        if not access_token:
            raise HTTPException(status_code=502, detail="CIBA approval returned no access token")

        try:
            token_payload = decode_jwt_token(access_token)
        except Exception as exc:
            logger.exception("[CIBA SERVICE] failed to decode approved CIBA token action_id=%s", action.id)
            raise HTTPException(status_code=502, detail=f"Invalid CIBA access token: {exc}") from exc

        permission_set = extract_permission_set(token_payload)
        if EXECUTE_REMEDIATION not in permission_set:
            logger.error(
                "[CIBA SERVICE] approved token missing scope action_id=%s approved_sub=%s granted=%s",
                action.id,
                token_payload.get("sub"),
                sorted(permission_set),
            )
            raise HTTPException(
                status_code=403,
                detail="Approved CIBA token is missing execute:remediation",
            )

        approved_sub = token_payload.get("sub")
        approved_email = token_payload.get("email")
        target_owner_sub = ciba_record.get("principal", {}).get("target_owner_sub")
        owner_resolution_source = ciba_record.get("principal", {}).get("owner_resolution_source")
        execution_id = ciba_record.get("execution", {}).get("execution_id")

        logger.info(
            "[CIBA PRINCIPAL] action_id=%s target_owner_sub=%s owner_resolution_source=%s approved_sub=%s approved_email=%s console_operator_sub=%s execution_mode=remediation_owner_ciba_token execution_id=%s",
            action.id,
            target_owner_sub,
            owner_resolution_source,
            approved_sub,
            approved_email,
            ciba_record.get("principal", {}).get("console_operator_sub"),
            execution_id,
        )

        if target_owner_sub and approved_sub != target_owner_sub:
            logger.error(
                "[CIBA PRINCIPAL] mismatch action_id=%s target_owner_sub=%s approved_sub=%s",
                action.id,
                target_owner_sub,
                approved_sub,
            )
            raise HTTPException(
                status_code=403,
                detail="Approved CIBA principal does not match the expected remediation owner",
            )

        try:
            fga_client.require_action_execution(user_sub=approved_sub, action=action)
        except FGAAuthorizationError:
            logger.exception(
                "[CIBA PRINCIPAL] FGA denied action_id=%s approved_sub=%s",
                action.id,
                approved_sub,
            )
            raise

        if action.execution_status in {"executing", "executed"}:
            logger.warning(
                "[CIBA SERVICE] execution already started action_id=%s execution_status=%s execution_id=%s",
                action.id,
                action.execution_status,
                execution_id,
            )
            if action.execution_status == "executing":
                ciba_record["status"] = CIBA_STATE_EXECUTION_IN_PROGRESS
                ciba_record["execution"]["status"] = "in_progress"
            elif action.execution_status == "executed":
                ciba_record["status"] = CIBA_STATE_EXECUTED
                ciba_record["execution"]["status"] = "executed"
                ciba_record["execution"]["completed_at"] = _iso(action.executed_at or _utcnow())
            metadata[CIBA_METADATA_KEY] = ciba_record
            _save_metadata(action, metadata)
            db.commit()
            return self._status_payload(action, ciba_record)

        claim_time = _utcnow()
        ciba_record["status"] = CIBA_STATE_EXECUTION_IN_PROGRESS
        ciba_record["approval"]["approved_at"] = _iso(claim_time)
        ciba_record["request"]["last_poll_error"] = None
        ciba_record["request"]["last_poll_error_description"] = None
        ciba_record["principal"]["approved_sub"] = approved_sub
        ciba_record["principal"]["approved_email"] = approved_email
        ciba_record["principal"]["execution_sub"] = approved_sub
        ciba_record["principal"]["execution_email"] = approved_email
        ciba_record["execution"]["status"] = "in_progress"
        ciba_record["execution"]["started_at"] = _iso(claim_time)
        ciba_record["execution"]["completed_at"] = None
        ciba_record["execution"]["result"] = None

        claimed = self._claim_execution_start(
            db=db,
            action=action,
            metadata=metadata,
            ciba_record=ciba_record,
        )
        if not claimed:
            db.expire_all()
            action = db.query(PlannedAction).filter(PlannedAction.id == action.id).first()
            if not action:
                raise HTTPException(status_code=404, detail="Action not found after execution claim")
            current_metadata = self._get_ciba_record(_load_metadata(action))
            logger.warning(
                "[CIBA CLAIM] execution claim lost action_id=%s execution_status=%s execution_id=%s",
                action.id,
                action.execution_status,
                current_metadata.get("execution", {}).get("execution_id"),
            )
            return self._status_payload(action, current_metadata)

        db.expire_all()
        action = db.query(PlannedAction).filter(PlannedAction.id == action.id).first()
        if not action:
            raise HTTPException(status_code=404, detail="Action not found after execution claim")
        metadata = _load_metadata(action)
        ciba_record = self._get_ciba_record(metadata)

        _add_audit_entry(
            db,
            incident_id=action.incident_id,
            action_id=action.id,
            actor_type="human",
            actor_id=approved_sub,
            actor_name=approved_email or approved_sub or "Remediation Owner",
            event_name=f"CIBA approved: {action.title}",
            target_system="Auth0 CIBA",
            execution_status="requested",
            details={
                "approvedSub": approved_sub,
                "approvedEmail": approved_email,
                "targetOwnerSub": target_owner_sub,
                "ownerResolutionSource": owner_resolution_source,
                "executionPrincipalSub": approved_sub,
                "executionPrincipalEmail": approved_email,
                "executionId": execution_id,
                "executionMode": ciba_record.get("principal", {}).get("execution_mode"),
            },
        )
        db.commit()

        logger.info(
            "[CIBA EXECUTION] action_id=%s execution_id=%s execution_principal_sub=%s execution_principal_email=%s console_operator_sub=%s target_owner_sub=%s owner_resolution_source=%s",
            action.id,
            execution_id,
            approved_sub,
            approved_email,
            ciba_record.get("principal", {}).get("console_operator_sub"),
            ciba_record.get("principal", {}).get("target_owner_sub"),
            ciba_record.get("principal", {}).get("owner_resolution_source"),
        )

        operator_context = {
            "sub": approved_sub,
            "email": approved_email,
            "name": token_payload.get("name"),
            "auth0_access_token": access_token,
        }

        try:
            result = _execute_single_action(action, operator_context=operator_context)
            action.execution_status = "executed" if result.get("success") else "failed"
            action.executed_at = _utcnow()
            ciba_record["status"] = (
                CIBA_STATE_EXECUTED if result.get("success") else CIBA_STATE_EXECUTION_FAILED
            )
            ciba_record["execution"]["status"] = (
                "executed" if result.get("success") else "failed"
            )
            ciba_record["execution"]["completed_at"] = _iso(action.executed_at)
            ciba_record["execution"]["result"] = result
        except Exception as exc:
            logger.exception("[CIBA SERVICE] execution failed after approval action_id=%s", action.id)
            action.execution_status = "failed"
            action.executed_at = _utcnow()
            result = {"success": False, "error": str(exc)}
            ciba_record["status"] = CIBA_STATE_EXECUTION_FAILED
            ciba_record["execution"]["status"] = "failed"
            ciba_record["execution"]["completed_at"] = _iso(action.executed_at)
            ciba_record["execution"]["result"] = result

        metadata[CIBA_METADATA_KEY] = ciba_record
        _save_metadata(action, metadata)
        _add_audit_entry(
            db,
            incident_id=action.incident_id,
            action_id=action.id,
            actor_type="system",
            actor_id=approved_sub,
            actor_name="WarRoom Agent",
            event_name=f"Action {'executed' if action.execution_status == 'executed' else 'failed'}: {action.title}",
            target_system=action.provider or action.target_system or "",
            execution_status=action.execution_status,
            details={
                "requestedBySub": ciba_record.get("principal", {}).get("console_operator_sub"),
                "requestedByEmail": ciba_record.get("principal", {}).get("console_operator_email"),
                "approvedBySub": approved_sub,
                "approvedByEmail": approved_email,
                "executionPrincipalSub": approved_sub,
                "executionPrincipalEmail": approved_email,
                "executionMode": ciba_record.get("principal", {}).get("execution_mode"),
                "executionId": execution_id,
                "fga_enforced": True,
                "privileged_auth_mode": "ciba",
                "result": result,
            },
        )
        db.commit()
        db.refresh(action)

        logger.info(
            "[CIBA SERVICE] execution complete action_id=%s execution_id=%s status=%s action_execution_status=%s",
            action.id,
            execution_id,
            ciba_record["status"],
            action.execution_status,
        )
        return self._status_payload(action, ciba_record)

    def _handle_execution_in_progress(
        self,
        *,
        db: Session,
        action: PlannedAction,
        metadata: dict[str, Any],
        ciba_record: dict[str, Any],
    ) -> dict[str, Any]:
        execution_id = ciba_record.get("execution", {}).get("execution_id")
        if action.execution_status == "executed":
            ciba_record["status"] = CIBA_STATE_EXECUTED
            ciba_record["execution"]["status"] = "executed"
            ciba_record["execution"]["completed_at"] = _iso(action.executed_at or _utcnow())
            metadata[CIBA_METADATA_KEY] = ciba_record
            _save_metadata(action, metadata)
            db.commit()
            return self._status_payload(action, ciba_record)

        if action.execution_status == "failed":
            ciba_record["status"] = CIBA_STATE_EXECUTION_FAILED
            ciba_record["execution"]["status"] = "failed"
            ciba_record["execution"]["completed_at"] = _iso(action.executed_at or _utcnow())
            metadata[CIBA_METADATA_KEY] = ciba_record
            _save_metadata(action, metadata)
            db.commit()
            return self._status_payload(action, ciba_record)

        logger.info(
            "[CIBA SERVICE] execution in progress action_id=%s execution_id=%s action_execution_status=%s",
            action.id,
            execution_id,
            action.execution_status,
        )
        return self._status_payload(action, ciba_record)

    def _ensure_supported_action(self, action: PlannedAction) -> None:
        if not self.enabled:
            raise HTTPException(status_code=409, detail="CIBA is not enabled")
        if action.action_type not in SENSITIVE_GITHUB_ACTIONS:
            raise HTTPException(
                status_code=400,
                detail="CIBA is only supported for sensitive GitHub remediation actions",
            )

    def _resolve_owner_sub(self, action: PlannedAction, metadata: dict[str, Any]) -> tuple[str, str]:
        metadata_owner_sub = metadata.get("ciba_owner_sub")
        if metadata_owner_sub:
            logger.info(
                "[CIBA OWNER] action_id=%s type=%s resolved_owner_sub=%s source=action_metadata.ciba_owner_sub",
                action.id,
                action.action_type,
                metadata_owner_sub,
            )
            return str(metadata_owner_sub), "action_metadata.ciba_owner_sub"

        if action.action_type == "github_app_repo_update":
            logger.info(
                "[CIBA OWNER] action_id=%s type=%s resolved_owner_sub=%s source=config.app_remediation_owner",
                action.id,
                action.action_type,
                self.app_remediation_owner_sub,
            )
            return str(self.app_remediation_owner_sub), "config.app_remediation_owner"

        if action.action_type == "github_network_repo_update":
            logger.info(
                "[CIBA OWNER] action_id=%s type=%s resolved_owner_sub=%s source=config.network_remediation_owner",
                action.id,
                action.action_type,
                self.network_remediation_owner_sub,
            )
            return str(self.network_remediation_owner_sub), "config.network_remediation_owner"

        owner_sub = fga_client.owner_sub_for_action(action)
        if not owner_sub:
            logger.error("[CIBA SERVICE] could not resolve target owner action_id=%s", action.id)
            raise HTTPException(
                status_code=500,
                detail="Could not resolve remediation owner for CIBA",
            )
        logger.info(
            "[CIBA OWNER] action_id=%s type=%s resolved_owner_sub=%s source=fga_client_fallback",
            action.id,
            action.action_type,
            owner_sub,
        )
        return str(owner_sub), "fga_client_fallback"

    def _claim_execution_start(
        self,
        *,
        db: Session,
        action: PlannedAction,
        metadata: dict[str, Any],
        ciba_record: dict[str, Any],
    ) -> bool:
        metadata[CIBA_METADATA_KEY] = ciba_record
        metadata_json = json.dumps(metadata)
        stmt = (
            update(PlannedAction)
            .where(
                PlannedAction.id == action.id,
                PlannedAction.approval_status == "approved",
                PlannedAction.execution_status == "pending",
            )
            .values(
                execution_status="executing",
                metadata_json=metadata_json,
            )
        )
        result = db.execute(stmt)
        db.commit()
        rowcount = int(result.rowcount or 0)
        logger.info(
            "[CIBA CLAIM] action_id=%s execution_id=%s expected_previous_execution_status=pending rowcount=%s",
            action.id,
            ciba_record.get("execution", {}).get("execution_id"),
            rowcount,
        )
        return rowcount == 1

    def _get_ciba_record(self, metadata: dict[str, Any]) -> dict[str, Any]:
        record = metadata.get(CIBA_METADATA_KEY)
        return record if isinstance(record, dict) else {}

    def _status(self, ciba_record: dict[str, Any]) -> str:
        return str(ciba_record.get("status") or "")

    def _status_payload(self, action: PlannedAction, ciba_record: dict[str, Any]) -> dict[str, Any]:
        status_name = self._status(ciba_record)
        return {
            "actionId": action.id,
            "incidentId": action.incident_id,
            "state": status_name,
            "executionStatus": action.execution_status,
            "consoleOperatorSub": ciba_record.get("principal", {}).get("console_operator_sub"),
            "ownerSub": ciba_record.get("principal", {}).get("target_owner_sub"),
            "approvedPrincipalSub": ciba_record.get("principal", {}).get("approved_sub"),
            "executionPrincipalSub": ciba_record.get("principal", {}).get("execution_sub"),
            "executionMode": ciba_record.get("principal", {}).get("execution_mode"),
            "ownerResolutionSource": ciba_record.get("principal", {}).get("owner_resolution_source"),
            "executionId": ciba_record.get("execution", {}).get("execution_id"),
            "bindingMessage": ciba_record.get("request", {}).get("binding_message"),
            "expiresAt": ciba_record.get("request", {}).get("expires_at"),
            "approvedAt": ciba_record.get("approval", {}).get("approved_at"),
            "executedAt": ciba_record.get("execution", {}).get("completed_at"),
            "pollIntervalSeconds": int(
                ciba_record.get("request", {}).get("poll_interval_seconds")
                or self.adapter.default_poll_interval
            ),
            "terminal": status_name in TERMINAL_CIBA_STATES,
            "authorized": status_name in {
                CIBA_STATE_APPROVAL_RECEIVED,
                CIBA_STATE_EXECUTION_IN_PROGRESS,
                CIBA_STATE_EXECUTED,
                CIBA_STATE_EXECUTION_FAILED,
            },
            "executed": status_name == CIBA_STATE_EXECUTED,
            "error": ciba_record.get("request", {}).get("last_poll_error"),
            "errorDescription": ciba_record.get("request", {}).get("last_poll_error_description"),
        }


ciba_service = CIBAService()
