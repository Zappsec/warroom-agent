from __future__ import annotations

from datetime import datetime, timezone
import json
import uuid
import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.services.ciba_service import ciba_service
from app.models.audit_entry import AuditEntry
from app.models.incident import Incident
from app.models.planned_action import PlannedAction
from app.security.auth0_jwt import require_scopes
from app.security.fga_client import fga_client, FGAAuthorizationError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/actions", tags=["actions"])

READ_INCIDENTS = "read:incidents"
APPROVE_ACTIONS = "approve:actions"
EXECUTE_ACTIONS = "execute:actions"
EXECUTE_REMEDIATION = "execute:remediation"


def _serialize_action(a: PlannedAction) -> dict:
    return {
        "id": a.id,
        "incidentId": a.incident_id,
        "type": a.action_type,
        "title": a.title or "",
        "description": a.description or "",
        "riskLevel": a.risk_level,
        "status": a.approval_status,
        "executionStatus": a.execution_status,
        "provider": a.provider or "",
        "scopesUsed": json.loads(a.scopes_used_json) if a.scopes_used_json else [],
        "recipients": json.loads(a.recipients_json) if a.recipients_json else [],
        "metadata": json.loads(a.metadata_json) if a.metadata_json else {},
        "createdAt": a.created_at.isoformat() + "Z" if a.created_at else "",
        "executedAt": (a.executed_at.isoformat() + "Z") if a.executed_at else None,
    }


def _build_operator_context(current_user: dict) -> dict:
    return {
        "sub": current_user.get("sub"),
        "email": current_user.get("email"),
        "name": current_user.get("name"),
        "auth0_access_token": current_user.get("_raw_access_token"),
    }


def _has_scope(current_user: dict, scope_name: str) -> bool:
    granted: set[str] = set()

    scope_str = current_user.get("scope") or ""
    if isinstance(scope_str, str):
        granted.update(s.strip() for s in scope_str.split() if s.strip())

    scp = current_user.get("scp")
    if isinstance(scp, str):
        granted.update(s.strip() for s in scp.split() if s.strip())
    elif isinstance(scp, list):
        granted.update(str(s).strip() for s in scp if str(s).strip())

    permissions = current_user.get("permissions") or []
    if isinstance(permissions, list):
        granted.update(str(p).strip() for p in permissions if str(p).strip())

    logger.warning(
        "[SCOPE DEBUG] sub=%s scope=%s scp=%s permissions=%s computed_granted=%s looking_for=%s found=%s",
        current_user.get("sub"),
        current_user.get("scope"),
        current_user.get("scp"),
        current_user.get("permissions"),
        sorted(granted),
        scope_name,
        scope_name in granted,
    )

    return scope_name in granted


def _is_sensitive_remediation(action: PlannedAction) -> bool:
    sensitive = action.action_type in {"github_app_repo_update", "github_network_repo_update"}

    logger.warning(
        "[SENSITIVITY DEBUG] action_id=%s type=%s risk=%s sensitive=%s",
        getattr(action, "id", None),
        getattr(action, "action_type", None),
        getattr(action, "risk_level", None),
        sensitive,
    )

    return sensitive


def _is_ciba_execution_path(action: PlannedAction) -> bool:
    enabled = ciba_service.is_enabled_for_action(action)
    logger.warning(
        "[CIBA DEBUG] action_id=%s type=%s ciba_enabled=%s",
        getattr(action, "id", None),
        getattr(action, "action_type", None),
        enabled,
    )
    return enabled


@router.get("")
def list_actions(
    status: str | None = Query(None),
    incident_id: str | None = Query(None),
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_scopes(READ_INCIDENTS)),
):
    query = db.query(PlannedAction).order_by(PlannedAction.created_at.desc())
    if status:
        query = query.filter(PlannedAction.approval_status == status)
    if incident_id:
        query = query.filter(PlannedAction.incident_id == incident_id)

    actions = query.all()
    return {
        "data": [_serialize_action(a) for a in actions],
        "error": None,
        "meta": {
            "total": len(actions),
            "viewer": current_user.get("email") or current_user.get("sub"),
        },
    }


@router.post("/{action_id}/approve")
def approve_action(
    action_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_scopes(APPROVE_ACTIONS)),
):
    action = db.query(PlannedAction).filter(PlannedAction.id == action_id).first()
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")

    actor_name = current_user.get("name") or current_user.get("email") or "Operator"
    actor_id = current_user.get("sub")

    fga_client.require_incident_approval(
        user_sub=actor_id,
        incident_id=action.incident_id,
    )

    action.approval_status = "approved"

    audit = AuditEntry(
        id=str(uuid.uuid4()),
        incident_id=action.incident_id,
        action_id=action.id,
        actor_type="human",
        actor_id=actor_id,
        actor_name=actor_name,
        event_name=f"Action approved: {action.title}",
        target_system=action.provider or action.target_system or "",
        approval_status="approved",
        details_json=json.dumps(
            {
                "approvedBy": actor_name,
                "approvedBySub": actor_id,
                "approvedByEmail": current_user.get("email"),
                "fga_enforced": True,
                "fga_relation": "can_approve",
                "fga_object": f"incident:{action.incident_id}",
            }
        ),
        timestamp=datetime.now(timezone.utc),
    )
    db.add(audit)
    db.commit()
    db.refresh(action)

    return {"data": _serialize_action(action), "error": None, "meta": {}}


@router.post("/{action_id}/deny")
def deny_action(
    action_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_scopes(APPROVE_ACTIONS)),
):
    action = db.query(PlannedAction).filter(PlannedAction.id == action_id).first()
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")

    actor_name = current_user.get("name") or current_user.get("email") or "Operator"
    actor_id = current_user.get("sub")

    fga_client.require_incident_approval(
        user_sub=actor_id,
        incident_id=action.incident_id,
    )

    action.approval_status = "denied"

    audit = AuditEntry(
        id=str(uuid.uuid4()),
        incident_id=action.incident_id,
        action_id=action.id,
        actor_type="human",
        actor_id=actor_id,
        actor_name=actor_name,
        event_name=f"Action denied: {action.title}",
        target_system=action.provider or action.target_system or "",
        approval_status="denied",
        details_json=json.dumps(
            {
                "deniedBy": actor_name,
                "deniedBySub": actor_id,
                "deniedByEmail": current_user.get("email"),
                "fga_enforced": True,
                "fga_relation": "can_approve",
                "fga_object": f"incident:{action.incident_id}",
            }
        ),
        timestamp=datetime.now(timezone.utc),
    )
    db.add(audit)
    db.commit()
    db.refresh(action)

    return {"data": _serialize_action(action), "error": None, "meta": {}}


@router.post("/{action_id}/prepare-execute")
def prepare_execute_action(
    action_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_scopes(EXECUTE_ACTIONS)),
):
    action = db.query(PlannedAction).filter(PlannedAction.id == action_id).first()
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")

    if action.approval_status != "approved":
        raise HTTPException(status_code=400, detail="Action must be approved before execution")

    sensitive = _is_sensitive_remediation(action)
    ciba_enabled = bool(sensitive and _is_ciba_execution_path(action))
    operator_context = _build_operator_context(current_user)

    # Always enforce FGA on the logged-in operator, even when CIBA will
    # delegate execution to the remediation owner.  This ensures the
    # operator is authorized for this specific remediation before any
    # CIBA approval request is sent.
    fga_client.require_action_execution(
        user_sub=operator_context["sub"],
        action=action,
    )

    has_step_up_scope = _has_scope(current_user, EXECUTE_REMEDIATION)
    privileged_auth_mode = "ciba" if ciba_enabled else ("redirect" if sensitive else None)
    step_up_required = bool(sensitive and (not ciba_enabled) and not has_step_up_scope)
    ready_to_execute = bool((not sensitive) or (sensitive and not ciba_enabled and has_step_up_scope))

    logger.warning(
        "[PREPARE EXECUTE DEBUG] action_id=%s incident_id=%s type=%s risk=%s sensitive=%s ciba_enabled=%s privileged_auth_mode=%s operator_sub=%s has_step_up_scope=%s stepUpRequired=%s readyToExecute=%s requiredScope=%s user_scope=%s user_permissions=%s",
        action.id,
        action.incident_id,
        action.action_type,
        action.risk_level,
        sensitive,
        ciba_enabled,
        privileged_auth_mode,
        operator_context["sub"],
        has_step_up_scope,
        step_up_required,
        ready_to_execute,
        EXECUTE_REMEDIATION if sensitive else None,
        current_user.get("scope"),
        current_user.get("permissions"),
    )

    return {
        "data": {
            "actionId": action.id,
            "incidentId": action.incident_id,
            "sensitive": sensitive,
            "stepUpRequired": step_up_required,
            "requiredScope": EXECUTE_REMEDIATION if sensitive else None,
            "readyToExecute": ready_to_execute,
            "privilegedAuthMode": privileged_auth_mode,
            "cibaEnabled": ciba_enabled,
        },
        "error": None,
        "meta": {},
    }


@router.post("/{action_id}/start-ciba")
def start_ciba_action(
    action_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_scopes(EXECUTE_ACTIONS)),
):
    action = db.query(PlannedAction).filter(PlannedAction.id == action_id).first()
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")

    # Enforce FGA on the operator initiating the CIBA flow — the operator
    # must be authorized to execute this specific remediation.
    fga_client.require_action_execution(
        user_sub=current_user.get("sub"),
        action=action,
    )

    logger.warning(
        "[START CIBA DEBUG] action_id=%s incident_id=%s requested_by_sub=%s requested_by_email=%s",
        action.id,
        action.incident_id,
        current_user.get("sub"),
        current_user.get("email"),
    )

    result = ciba_service.start_for_action(
        db=db,
        action=action,
        initiated_by=current_user,
    )
    return {"data": result, "error": None, "meta": {}}


@router.get("/{action_id}/ciba-status")
def get_ciba_action_status(
    action_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_scopes(EXECUTE_ACTIONS)),
):
    action = db.query(PlannedAction).filter(PlannedAction.id == action_id).first()
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")

    logger.warning(
        "[CIBA STATUS DEBUG] action_id=%s incident_id=%s polled_by_sub=%s polled_by_email=%s",
        action.id,
        action.incident_id,
        current_user.get("sub"),
        current_user.get("email"),
    )

    result = ciba_service.get_status_for_action(
        db=db,
        action=action,
        polled_by=current_user,
    )
    return {"data": result, "error": None, "meta": {}}


@router.post("/{action_id}/execute")
def execute_action(
    action_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_scopes(EXECUTE_ACTIONS)),
):
    action = db.query(PlannedAction).filter(PlannedAction.id == action_id).first()
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")

    if action.approval_status != "approved":
        raise HTTPException(status_code=400, detail="Action must be approved before execution")

    operator_context = _build_operator_context(current_user)

    sensitive = _is_sensitive_remediation(action)
    ciba_enabled = bool(sensitive and _is_ciba_execution_path(action))
    has_step_up_scope = _has_scope(current_user, EXECUTE_REMEDIATION)

    logger.warning(
        "[EXECUTE DEBUG] action_id=%s incident_id=%s operator_sub=%s type=%s risk=%s sensitive=%s ciba_enabled=%s has_step_up_scope=%s scope=%s scp=%s permissions=%s needs=%s",
        action.id,
        action.incident_id,
        current_user.get("sub"),
        action.action_type,
        action.risk_level,
        sensitive,
        ciba_enabled,
        has_step_up_scope,
        current_user.get("scope"),
        current_user.get("scp"),
        current_user.get("permissions"),
        EXECUTE_REMEDIATION,
    )

    if ciba_enabled:
        raise HTTPException(
            status_code=409,
            detail="Sensitive GitHub remediation execution must use the CIBA start/status flow while CIBA is enabled",
        )

    if sensitive and not has_step_up_scope:
        raise HTTPException(
            status_code=403,
            detail="Step-up authentication required for sensitive remediation execution",
        )

    fga_client.require_action_execution(
        user_sub=operator_context["sub"],
        action=action,
    )

    from app.services.execution_engine import _execute_single_action

    action.execution_status = "executing"
    db.commit()

    try:
        result = _execute_single_action(
            action,
            operator_context=operator_context,
        )
        action.execution_status = "executed" if result.get("success") else "failed"
        action.executed_at = datetime.now(timezone.utc)
    except FGAAuthorizationError:
        action.execution_status = "failed"
        raise
    except Exception as exc:
        action.execution_status = "failed"
        result = {"success": False, "error": str(exc)}

    audit = AuditEntry(
        id=str(uuid.uuid4()),
        incident_id=action.incident_id,
        action_id=action.id,
        actor_type="system",
        actor_id=current_user.get("sub"),
        actor_name="WarRoom Agent",
        event_name=f"Action {'executed' if action.execution_status == 'executed' else 'failed'}: {action.title}",
        target_system=action.provider or action.target_system or "",
        execution_status=action.execution_status,
        details_json=json.dumps(
            {
                "requestedBy": current_user.get("name") or current_user.get("email"),
                "requestedBySub": current_user.get("sub"),
                "requestedByEmail": current_user.get("email"),
                "fga_enforced": sensitive,
                "step_up_scope_present": has_step_up_scope,
                "result": result,
            }
        ),
        timestamp=datetime.now(timezone.utc),
    )
    db.add(audit)
    db.commit()
    db.refresh(action)

    return {
        "data": _serialize_action(action),
        "error": None,
        "meta": {"executionResult": result},
    }


@router.post("/execute-all/{incident_id}")
def execute_all_actions(
    incident_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_scopes(EXECUTE_ACTIONS)),
):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    from app.services.execution_engine import execute_approved_actions

    operator_context = _build_operator_context(current_user)

    results = execute_approved_actions(
        incident_id,
        operator_context=operator_context,
    )

    audit = AuditEntry(
        id=str(uuid.uuid4()),
        incident_id=incident_id,
        actor_type="human",
        actor_id=current_user.get("sub"),
        actor_name=current_user.get("name") or current_user.get("email") or "Operator",
        event_name=f"Bulk execution requested for incident {incident_id}",
        target_system="Execution Engine",
        execution_status="requested",
        details_json=json.dumps(
            {
                "requestedByEmail": current_user.get("email"),
                "requestedBySub": current_user.get("sub"),
                "resultCount": len(results),
            }
        ),
        timestamp=datetime.now(timezone.utc),
    )
    db.add(audit)
    db.commit()

    return {
        "data": results,
        "error": None,
        "meta": {
            "incidentId": incident_id,
            "total": len(results),
        },
    }
