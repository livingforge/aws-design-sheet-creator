"""EC2 Route destination and target selection rule.

Source: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-route.html
"""
from __future__ import annotations

from typing import Any

from .models import Design, Resource, ValueState


RULE_ID = "EC2_ROUTE_DESTINATION_AND_TARGET"
DESTINATIONS = (
    "DestinationCidrBlock", "DestinationIpv6CidrBlock", "DestinationPrefixListId",
)
TARGETS = (
    "CarrierGatewayId", "CoreNetworkArn", "EgressOnlyInternetGatewayId",
    "GatewayId", "InstanceId", "LocalGatewayId", "NatGatewayId",
    "NetworkInterfaceId", "OdbNetworkArn", "TransitGatewayId",
    "VpcEndpointId", "VpcPeeringConnectionId",
)


def _result(resource: Resource, verdict: str, reason: str, *,
            dependencies: list[str] | None = None,
            evidence_ids: list[str] | None = None) -> dict[str, Any]:
    return {"rule_id": RULE_ID, "resource_id": resource.id, "path": "/properties",
            "verdict": verdict, "reason": reason,
            "dependencies": dependencies or [], "evidence_ids": evidence_ids or []}


def _selection(design: Design, resource: Resource, names: tuple[str, ...]):
    """Classify each candidate property once, including relation-only inputs."""
    known: list[str] = []
    uncertain: list[str] = []
    evidence: list[str] = []
    for name in names:
        path = f"/properties/{name}"
        field = resource.field(path)
        relations = [relation for relation in design.relations
                     if relation.source_resource_id == resource.id and relation.source_path == path]
        if field:
            evidence.extend(field.intent_evidence_ids)
            evidence.extend(e for candidate in field.candidates for e in candidate.evidence_ids)
        evidence.extend(e for relation in relations for e in relation.evidence_ids)
        if field and relations:
            # A literal and a logical reference both claim this property.
            uncertain.append(path)
        elif field and field.state == ValueState.KNOWN:
            value = field.selected().value
            if isinstance(value, str) and value:
                known.append(path)
            else:
                # The schema reports a malformed scalar; do not assert selection.
                uncertain.append(path)
        elif field and field.state not in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
            uncertain.append(path)
        elif len(relations) == 1:
            known.append(path)
        elif len(relations) > 1:
            uncertain.append(path)
    return known, uncertain, evidence


def evaluate_ec2_route_destination_and_target(design: Design, resource: Resource) -> dict[str, Any]:
    """Require one destination and exactly one target for AWS::EC2::Route."""
    if resource.type != "AWS::EC2::Route":
        return _result(resource, "NOT_APPLICABLE", "resource type does not match")

    destinations, pending_destinations, destination_evidence = _selection(design, resource, DESTINATIONS)
    targets, pending_targets, target_evidence = _selection(design, resource, TARGETS)
    evidence = list(dict.fromkeys(destination_evidence + target_evidence))
    # Proven excess cannot be resolved by other missing or uncertain values.
    if len(destinations) > 1:
        return _result(resource, "FAIL", "more than one destination is specified",
                       evidence_ids=evidence)
    if len(targets) > 1:
        return _result(resource, "FAIL", "more than one target is specified",
                       evidence_ids=evidence)
    if not destinations and not pending_destinations:
        return _result(resource, "FAIL", "a destination CIDR block or prefix list ID is required",
                       evidence_ids=evidence)
    if not targets and not pending_targets:
        return _result(resource, "FAIL", "exactly one route target is required",
                       evidence_ids=evidence)
    pending = pending_destinations + pending_targets
    if pending:
        return _result(resource, "NEEDS_REVIEW", "destination or target selection is unresolved",
                       dependencies=pending, evidence_ids=evidence)
    return _result(resource, "PASS", "one destination and one target are specified",
                   evidence_ids=evidence)
