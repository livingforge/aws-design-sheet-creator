"""Independent first-wave service rules. Schema and generic reference checks stay separate."""
from __future__ import annotations

from typing import Any

from .models import Design, FieldValue, Resource, ValueState


def _evidence(field: FieldValue | None) -> list[str]:
    if field is None:
        return []
    return list(dict.fromkeys([*field.intent_evidence_ids,
                               *(e for candidate in field.candidates for e in candidate.evidence_ids)]))


def _result(rule: str, resource: Resource, path: str, verdict: str, reason: str,
            *, dependencies: list[str] | None = None,
            evidence_ids: list[str] | None = None) -> dict[str, Any]:
    return {"rule_id": rule, "resource_id": resource.id, "path": path,
            "verdict": verdict, "reason": reason,
            "dependencies": dependencies or [], "evidence_ids": evidence_ids or []}


def _relations(design: Design, resource: Resource, path: str):
    return [relation for relation in design.relations
            if relation.source_resource_id == resource.id and
            (relation.source_path == path or relation.source_path.startswith(path + "/"))]


def evaluate_iam_policy_attachment(design: Design, resource: Resource) -> dict[str, Any]:
    """AWS::IAM::Policy needs at least one group, role, or user attachment."""
    rule = "IAM_POLICY_ATTACHMENT"
    path = "/properties"
    if resource.type != "AWS::IAM::Policy":
        return _result(rule, resource, path, "NOT_APPLICABLE", "resource type does not match")

    names = ("Groups", "Roles", "Users")
    pending: list[str] = []
    evidence: list[str] = []
    has_known_attachment = False
    has_unresolved_reference = False
    resources = {item.id: item for item in design.resources}
    expected = {"Groups": "AWS::IAM::Group", "Roles": "AWS::IAM::Role",
                "Users": "AWS::IAM::User"}
    for name in names:
        item_path = f"/properties/{name}"
        field = resource.field(item_path)
        evidence.extend(_evidence(field))
        references = _relations(design, resource, item_path)
        evidence.extend(e for ref in references for e in ref.evidence_ids)
        if field is not None:
            if field.state == ValueState.KNOWN:
                value = field.selected().value
                if isinstance(value, list) and value:
                    has_known_attachment = True
                elif not isinstance(value, list):
                    pending.append(item_path)  # The schema check reports the wrong type.
            elif field.state not in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
                pending.append(item_path)
        for ref in references:
            target = resources.get(ref.target_resource_id)
            if target and target.type == expected[name] and target.scope == resource.scope:
                has_known_attachment = True
            else:
                has_unresolved_reference = True
                pending.append(ref.source_path)

    evidence = list(dict.fromkeys(evidence))
    if has_known_attachment:
        return _result(rule, resource, path, "PASS", "at least one attachment target is specified",
                       evidence_ids=evidence)
    if pending:
        return _result(rule, resource, path, "NEEDS_REVIEW", "attachment target is unresolved",
                       dependencies=list(dict.fromkeys(pending)), evidence_ids=evidence)
    return _result(rule, resource, path, "FAIL", "Groups, Roles, or Users must contain an attachment target",
                   evidence_ids=evidence)


def evaluate_elbv2_secure_listener_certificate(design: Design, resource: Resource) -> dict[str, Any]:
    """HTTPS/TLS listeners require exactly one default certificate."""
    rule = "ELBV2_SECURE_LISTENER_CERTIFICATE"
    protocol_path = "/properties/Protocol"
    cert_path = "/properties/Certificates"
    if resource.type != "AWS::ElasticLoadBalancingV2::Listener":
        return _result(rule, resource, protocol_path, "NOT_APPLICABLE", "resource type does not match")
    protocol = resource.field(protocol_path)
    if protocol is None or protocol.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        return _result(rule, resource, protocol_path, "NEEDS_REVIEW", "listener protocol is not specified",
                       dependencies=[protocol_path], evidence_ids=_evidence(protocol))
    if protocol.state != ValueState.KNOWN:
        return _result(rule, resource, protocol_path, "NEEDS_REVIEW", "listener protocol is unresolved",
                       dependencies=[protocol_path], evidence_ids=_evidence(protocol))
    if protocol.selected().value not in ("HTTPS", "TLS"):
        return _result(rule, resource, cert_path, "NOT_APPLICABLE", "listener is not HTTPS or TLS",
                       evidence_ids=_evidence(protocol))

    certificate = resource.field(cert_path)
    evidence = _evidence(protocol) + _evidence(certificate)
    references = _relations(design, resource, cert_path)
    evidence.extend(e for ref in references for e in ref.evidence_ids)
    evidence = list(dict.fromkeys(evidence))
    if certificate is None or certificate.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        return _result(rule, resource, cert_path, "FAIL", "secure listener needs one default certificate",
                       evidence_ids=evidence)
    if certificate.state != ValueState.KNOWN:
        return _result(rule, resource, cert_path, "NEEDS_REVIEW", "certificate list is unresolved",
                       dependencies=[cert_path], evidence_ids=evidence)
    value = certificate.selected().value
    if not isinstance(value, list):
        return _result(rule, resource, cert_path, "NEEDS_REVIEW", "certificate list has an invalid shape",
                       dependencies=[cert_path], evidence_ids=evidence)
    if len(value) != 1:
        return _result(rule, resource, cert_path, "FAIL", "secure listener needs exactly one default certificate",
                       evidence_ids=evidence)
    entry = value[0]
    if not isinstance(entry, dict):
        return _result(rule, resource, cert_path, "NEEDS_REVIEW", "certificate entry has an invalid shape",
                       dependencies=[cert_path], evidence_ids=evidence)
    arn = entry.get("CertificateArn")
    if isinstance(arn, str) and arn:
        return _result(rule, resource, cert_path, "PASS", "one default certificate is specified",
                       evidence_ids=evidence)
    if any(ref.source_path == cert_path + "/0/CertificateArn" for ref in references):
        return _result(rule, resource, cert_path, "PASS", "one default certificate is referenced",
                       evidence_ids=evidence)
    return _result(rule, resource, cert_path, "NEEDS_REVIEW", "default certificate ARN is unresolved",
                   dependencies=[cert_path + "/0/CertificateArn"], evidence_ids=evidence)
