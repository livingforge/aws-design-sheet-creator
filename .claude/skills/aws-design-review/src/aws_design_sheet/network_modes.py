"""Checks for VPC IPv4 allocation choices and explicit subnet IPv6 CIDRs."""
from __future__ import annotations

import ipaddress

from .models import Design, FieldValue, Resource, ValueState

VPC_CIDR = "/properties/CidrBlock"
VPC_IPAM = "/properties/Ipv4IpamPoolId"
SUBNET_IPV6 = "/properties/Ipv6CidrBlock"
ASSIGN_IPV6 = "/properties/AssignIpv6AddressOnCreation"
ASSOCIATION_IPV6 = "/properties/Ipv6CidrBlock"
VPC_REF = "/properties/VpcId"


def _evidence(field: FieldValue | None) -> list[str]:
    if field is None:
        return []
    return list(dict.fromkeys([*field.intent_evidence_ids,
                               *(item for candidate in field.candidates for item in candidate.evidence_ids)]))


def _choice(field: FieldValue | None) -> bool | None:
    if field is None or field.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        return False
    if field.state != ValueState.KNOWN:
        return None
    selected = field.selected().value
    return bool(selected) if isinstance(selected, str) else None


def _finding(rule: str, resource: Resource, path: str, verdict: str, reason: str,
             *, evidence: list[str] | None = None, dependencies: list[str] | None = None,
             expected=None, actual=None) -> dict:
    return {"rule_id": rule, "resource_id": resource.id, "path": path,
            "verdict": verdict, "reason": reason, "evidence_ids": evidence or [],
            "dependencies": dependencies or [], "expected": expected, "actual": actual}


def vpc_ipv4_source(resource: Resource) -> dict:
    """A VPC needs exactly one explicit IPv4 source."""
    cidr, ipam = resource.field(VPC_CIDR), resource.field(VPC_IPAM)
    choices = [_choice(cidr), _choice(ipam)]
    evidence = list(dict.fromkeys(_evidence(cidr) + _evidence(ipam)))
    if choices == [True, True]:
        verdict, reason = "FAIL", "CIDR and IPv4 IPAM pool are both specified"
    elif None in choices:
        verdict, reason = "NEEDS_REVIEW", "IPv4 allocation source is unresolved"
    elif any(choices):
        verdict, reason = "PASS", "one IPv4 allocation source is specified"
    else:
        verdict, reason = "FAIL", "CIDR or IPv4 IPAM pool is required"
    return _finding("VPC_IPV4_SOURCE", resource, VPC_CIDR, verdict, reason,
                    evidence=evidence,
                    dependencies=[path for path, choice in zip((VPC_CIDR, VPC_IPAM), choices)
                                  if choice is None])


def _known_ipv6(resource: Resource, path: str) -> tuple[ipaddress.IPv6Network | None, dict | None]:
    field = resource.field(path)
    if not field or field.state != ValueState.KNOWN:
        return None, None
    raw = field.selected().value
    try:
        network = ipaddress.ip_network(raw, strict=True) if isinstance(raw, str) else None
    except ValueError:
        network = None
    if not isinstance(network, ipaddress.IPv6Network):
        return None, _finding("IPV6_CIDR_FORMAT", resource, path, "FAIL",
                              "invalid or noncanonical IPv6 CIDR", evidence=_evidence(field), actual=raw)
    return network, None


def subnet_ipv6_checks(design: Design) -> list[dict]:
    """Validate explicit ranges, VPC containment, and sibling overlap.

    Dynamically allocated and external VPC ranges remain unresolved.
    """
    by_id = {resource.id: resource for resource in design.resources}
    vpc_refs: dict[str, list] = {}
    for relation in design.relations:
        if relation.source_path == VPC_REF:
            vpc_refs.setdefault(relation.source_resource_id, []).append(relation)

    def vpc_for(resource: Resource) -> Resource | None:
        refs = vpc_refs.get(resource.id, [])
        if len(refs) != 1:
            return None
        ref = refs[0]
        target = by_id.get(ref.target_resource_id)
        if target is None and ref.unresolved_name:
            matches = [item for item in design.resources if item.type == "AWS::EC2::VPC"
                       and item.name == ref.unresolved_name and item.scope == resource.scope]
            target = matches[0] if len(matches) == 1 else None
        return target if target and target.type == "AWS::EC2::VPC" and target.scope == resource.scope else None

    results: list[dict] = []
    ranges: dict[str, list[tuple[ipaddress.IPv6Network, Resource]]] = {}
    associations: dict[str, list[ipaddress.IPv6Network]] = {}
    unknown_associations: set[str] = set()
    for resource in design.resources:
        if resource.type != "AWS::EC2::VPCCidrBlock":
            continue
        network, error = _known_ipv6(resource, ASSOCIATION_IPV6)
        if error:
            results.append(error)
        vpc = vpc_for(resource)
        if network and vpc:
            associations.setdefault(vpc.id, []).append(network)
        elif vpc:
            unknown_associations.add(vpc.id)

    for subnet in design.resources:
        if subnet.type != "AWS::EC2::Subnet":
            continue
        field = subnet.field(SUBNET_IPV6)
        assign = subnet.field(ASSIGN_IPV6)
        if assign and assign.state == ValueState.KNOWN and assign.selected().value is True:
            if field is None or field.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
                results.append(_finding("SUBNET_IPV6_ASSIGNMENT", subnet, SUBNET_IPV6, "FAIL",
                                        "IPv6 CIDR is required when automatic IPv6 assignment is enabled",
                                        evidence=_evidence(assign)))
            elif field.state != ValueState.KNOWN:
                results.append(_finding("SUBNET_IPV6_ASSIGNMENT", subnet, SUBNET_IPV6,
                                        "NEEDS_REVIEW", "IPv6 CIDR is unresolved",
                                        evidence=list(dict.fromkeys(_evidence(assign) + _evidence(field))),
                                        dependencies=[SUBNET_IPV6]))
            else:
                results.append(_finding("SUBNET_IPV6_ASSIGNMENT", subnet, SUBNET_IPV6,
                                        "PASS", "IPv6 CIDR is specified for automatic assignment",
                                        evidence=list(dict.fromkeys(_evidence(assign) + _evidence(field)))))
        elif assign and assign.state not in (ValueState.KNOWN, ValueState.MISSING,
                                              ValueState.NOT_APPLICABLE):
            results.append(_finding("SUBNET_IPV6_ASSIGNMENT", subnet, ASSIGN_IPV6,
                                    "NEEDS_REVIEW", "automatic IPv6 assignment is unresolved",
                                    evidence=_evidence(assign), dependencies=[ASSIGN_IPV6]))
        if field is None or field.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
            continue
        if field.state != ValueState.KNOWN:
            results.append(_finding("IPV6_CIDR_CONTAINMENT", subnet, SUBNET_IPV6,
                                    "NEEDS_REVIEW", "subnet IPv6 CIDR is unresolved",
                                    evidence=_evidence(field), dependencies=[SUBNET_IPV6]))
            continue
        network, error = _known_ipv6(subnet, SUBNET_IPV6)
        if error:
            results.append(error)
            continue
        vpc = vpc_for(subnet)
        if vpc:
            ranges.setdefault(vpc.id, []).append((network, subnet))
        parents = associations.get(vpc.id, []) if vpc else []
        if not parents:
            results.append(_finding("IPV6_CIDR_CONTAINMENT", subnet, SUBNET_IPV6,
                                    "NEEDS_REVIEW", "VPC IPv6 range is unavailable",
                                    evidence=_evidence(field), dependencies=[VPC_REF, SUBNET_IPV6]))
        else:
            contained = any(network.subnet_of(parent) for parent in parents)
            uncertain = not contained and vpc.id in unknown_associations
            results.append(_finding("IPV6_CIDR_CONTAINMENT", subnet, SUBNET_IPV6,
                                    "PASS" if contained else "NEEDS_REVIEW" if uncertain else "FAIL",
                                    "subnet IPv6 CIDR lies within VPC" if contained else
                                    "another VPC IPv6 range is unresolved" if uncertain else
                                    "subnet IPv6 CIDR outside VPC",
                                    evidence=_evidence(field), expected=[str(p) for p in parents],
                                    actual=str(network), dependencies=[VPC_REF] if uncertain else []))

    for entries in ranges.values():
        for index, (network, subnet) in enumerate(entries):
            for other, other_subnet in entries[:index]:
                if network.overlaps(other):
                    results.append(_finding("IPV6_CIDR_OVERLAP", subnet, SUBNET_IPV6, "FAIL",
                                            "subnet IPv6 CIDRs overlap",
                                            evidence=list(dict.fromkeys(_evidence(subnet.field(SUBNET_IPV6)) +
                                                                        _evidence(other_subnet.field(SUBNET_IPV6)))),
                                            actual=[subnet.id, other_subnet.id]))
    return results
