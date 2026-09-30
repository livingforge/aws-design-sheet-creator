"""Standalone RDS DBInstance KMS key / storage encryption pilot rule."""
from __future__ import annotations

from typing import Any

from .models import Design, FieldValue, Resource, ValueState


RULE = "RDS_DBINSTANCE_KMS_REQUIRES_ENCRYPTION"
TYPE = "AWS::RDS::DBInstance"
KMS = "/properties/KmsKeyId"
ENCRYPTED = "/properties/StorageEncrypted"
ENGINE = "/properties/Engine"
EXCEPTIONS = (
    "/properties/DBClusterIdentifier",
    "/properties/DBSnapshotIdentifier",
    "/properties/SourceDBInstanceIdentifier",
    "/properties/SourceDbiResourceId",
    "/properties/SourceDBInstanceAutomatedBackupsArn",
)


def _evidence(field: FieldValue | None) -> list[str]:
    if field is None:
        return []
    return [*field.intent_evidence_ids,
            *(e for candidate in field.candidates for e in candidate.evidence_ids)]


def _result(resource: Resource, verdict: str, reason: str, *,
            dependencies: list[str] = (), evidence_ids: list[str] = ()) -> dict[str, Any]:
    return {"rule_id": RULE, "resource_id": resource.id, "path": ENCRYPTED,
            "verdict": verdict, "reason": reason,
            "dependencies": list(dict.fromkeys(dependencies)),
            "evidence_ids": list(dict.fromkeys(evidence_ids))}


def _unresolved(field: FieldValue | None) -> bool:
    return field is not None and field.state not in (
        ValueState.KNOWN, ValueState.MISSING, ValueState.NOT_APPLICABLE)


def evaluate_rds_dbinstance_kms_encryption(design: Design, resource: Resource) -> dict[str, Any]:
    """Check the KmsKeyId ⇒ StorageEncrypted=true rule for ordinary creation.

    Snapshot/replica/cluster cases inherit encryption or use a different owner,
    so this rule deliberately reports them as outside its applicable scope.
    """
    if resource.type != TYPE:
        return _result(resource, "NOT_APPLICABLE", "resource type does not match")

    kms_field = resource.field(KMS)
    kms_refs = [rel for rel in design.relations
                if rel.source_resource_id == resource.id and rel.source_path == KMS]
    evidence = _evidence(kms_field)
    evidence.extend(e for ref in kms_refs for e in ref.evidence_ids)

    exception_paths: list[str] = []
    pending: list[str] = []
    for path in EXCEPTIONS:
        field = resource.field(path)
        evidence.extend(_evidence(field))
        refs = [rel for rel in design.relations
                if rel.source_resource_id == resource.id and rel.source_path == path]
        evidence.extend(e for ref in refs for e in ref.evidence_ids)
        if _unresolved(field) or len(refs) > 1:
            pending.append(path)
        elif refs:
            exception_paths.append(path)
        elif field is not None and field.state == ValueState.KNOWN:
            value = field.selected().value
            if isinstance(value, str) and value.strip():
                exception_paths.append(path)
            else:
                pending.append(path)

    engine = resource.field(ENGINE)
    evidence.extend(_evidence(engine))
    if engine is not None and engine.state == ValueState.KNOWN:
        value = engine.selected().value
        if isinstance(value, str) and value.lower().startswith("aurora"):
            exception_paths.append(ENGINE)
    elif _unresolved(engine):
        pending.append(ENGINE)

    if exception_paths:
        return _result(resource, "NOT_APPLICABLE", "encryption is inherited or managed by a DB cluster",
                       evidence_ids=evidence)
    if kms_field is None or kms_field.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        if not kms_refs:
            return _result(resource, "NOT_APPLICABLE", "KmsKeyId is not specified",
                           evidence_ids=evidence)
    if _unresolved(kms_field) or len(kms_refs) > 1:
        return _result(resource, "NEEDS_REVIEW", "KMS key selection is unresolved",
                       dependencies=[KMS], evidence_ids=evidence)
    if kms_field is not None and kms_field.state == ValueState.KNOWN:
        kms_value = kms_field.selected().value
        if not isinstance(kms_value, str) or not kms_value.strip():
            return _result(resource, "NEEDS_REVIEW", "KmsKeyId has an invalid value",
                           dependencies=[KMS], evidence_ids=evidence)
        if kms_refs:
            return _result(resource, "NEEDS_REVIEW", "KmsKeyId has both a value and a logical reference",
                           dependencies=[KMS], evidence_ids=evidence)
    if pending:
        return _result(resource, "NEEDS_REVIEW", "creation mode is unresolved",
                       dependencies=pending, evidence_ids=evidence)

    encrypted = resource.field(ENCRYPTED)
    evidence.extend(_evidence(encrypted))
    if encrypted is None or encrypted.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        return _result(resource, "FAIL", "KmsKeyId requires StorageEncrypted=true",
                       evidence_ids=evidence)
    if encrypted.state != ValueState.KNOWN:
        return _result(resource, "NEEDS_REVIEW", "StorageEncrypted is unresolved",
                       dependencies=[ENCRYPTED], evidence_ids=evidence)
    value = encrypted.selected().value
    if value is True:
        if kms_refs:
            ref = kms_refs[0]
            if ref.expected_target_type and ref.expected_target_type != "AWS::KMS::Key":
                return _result(resource, "FAIL", "KmsKeyId reference has the wrong target type",
                               evidence_ids=evidence)
            target = next((item for item in design.resources if item.id == ref.target_resource_id), None)
            if target is None:
                return _result(resource, "NEEDS_REVIEW", "KMS key reference is unresolved",
                               dependencies=[KMS], evidence_ids=evidence)
            if target.type != "AWS::KMS::Key":
                return _result(resource, "FAIL", "KmsKeyId reference does not target a KMS key",
                               evidence_ids=evidence)
        return _result(resource, "PASS", "KmsKeyId has StorageEncrypted=true",
                       evidence_ids=evidence)
    if value is False:
        return _result(resource, "FAIL", "KmsKeyId requires StorageEncrypted=true",
                       evidence_ids=evidence)
    return _result(resource, "NEEDS_REVIEW", "StorageEncrypted is not a resolved boolean",
                   dependencies=[ENCRYPTED], evidence_ids=evidence)
