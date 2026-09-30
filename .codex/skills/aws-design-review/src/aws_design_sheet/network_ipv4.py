"""IPv4 CIDR blocks of a VPC: the primary block plus VPCCidrBlock associations.

Rules follow the Amazon VPC User Guide, "VPC CIDR blocks": block size, reserved
ranges, overlap between associated blocks and the association restrictions
that depend on the primary block's range. Blocks allocated from IPAM pools or
left unresolved make the VPC's address set incomplete, so a subnet outside the
known blocks then needs review instead of failing.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field as dataclass_field

from .models import Design, FieldValue, Resource, ValueState


SOURCE = "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-cidr-blocks.html"
CIDR = "/properties/CidrBlock"
IPAM = "/properties/Ipv4IpamPoolId"
VPC_REF = "/properties/VpcId"
RFC1918 = tuple(ipaddress.ip_network(item) for item in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
RESERVED = tuple(ipaddress.ip_network(item) for item in
                 ("0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4"))
BENCHMARK = ipaddress.ip_network("198.19.0.0/16")


@dataclass
class Block:
    network: ipaddress.IPv4Network
    resource: Resource
    field: FieldValue
    primary: bool


@dataclass
class VpcAddresses:
    blocks: list[Block] = dataclass_field(default_factory=list)
    incomplete: bool = False


def _evidence(*fields: FieldValue | None) -> list[str]:
    return list(dict.fromkeys(e for item in fields if item is not None for e in
                              [*item.intent_evidence_ids,
                               *(x for candidate in item.candidates for x in candidate.evidence_ids)]))


def _finding(rule: str, resource: Resource, verdict: str, reason: str, *, fields=(),
             expected=None, actual=None, dependencies=None) -> dict:
    return {"rule_id": rule, "resource_id": resource.id, "path": CIDR, "verdict": verdict,
            "reason": reason, "evidence_ids": _evidence(*fields), "expected": expected,
            "actual": actual, "dependencies": dependencies or []}


def _ipv4(resource: Resource) -> tuple[str, ipaddress.IPv4Network | None, FieldValue | None]:
    """Classify a block as known, absent, dynamic (IPAM) or unresolved."""
    cidr, ipam = resource.field(CIDR), resource.field(IPAM)
    if cidr is not None and cidr.state == ValueState.KNOWN:
        raw = cidr.selected().value
        try:
            network = ipaddress.ip_network(raw, strict=True) if isinstance(raw, str) else None
        except ValueError:
            network = None
        if isinstance(network, ipaddress.IPv4Network):
            return "known", network, cidr
        return "invalid", None, cidr
    if cidr is not None and cidr.state not in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        return "unresolved", None, cidr
    if ipam is not None and ipam.state not in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        return "dynamic", None, ipam
    return "absent", None, None


def _restricted(primary: ipaddress.IPv4Network, block: ipaddress.IPv4Network,
                others: list[ipaddress.IPv4Network]) -> str | None:
    """The documented association restriction that applies, if any."""
    if block.subnet_of(ipaddress.ip_network("10.0.0.0/16")) and any(
            other.subnet_of(ipaddress.ip_network("10.0.0.0/15")) for other in others):
        return "10.0.0.0/16 cannot be added when a block from 10.0.0.0/15 is associated"
    private = next((item for item in RFC1918 if primary.subnet_of(item)), None)
    if private is not None:
        if block.overlaps(BENCHMARK):
            return "198.19.0.0/16 is restricted for this primary range"
        if any(block.overlaps(item) for item in RFC1918 if item != private):
            return f"other RFC 1918 ranges are restricted when the primary block is in {private}"
        if private == ipaddress.ip_network("172.16.0.0/12") and block.overlaps(
                ipaddress.ip_network("172.31.0.0/16")):
            return "172.31.0.0/16 is restricted when the primary block is in 172.16.0.0/12"
        return None
    if any(block.overlaps(item) for item in RFC1918):
        return "RFC 1918 ranges are restricted when the primary block is not an RFC 1918 range"
    if not primary.subnet_of(BENCHMARK) and block.overlaps(BENCHMARK):
        return "198.19.0.0/16 is restricted for this primary range"
    return None


def vpc_ipv4_addresses(design: Design) -> tuple[dict[str, VpcAddresses], list[dict]]:
    """Collect each VPC's IPv4 blocks and evaluate the block rules."""
    by_id = {resource.id: resource for resource in design.resources}
    refs: dict[str, list] = {}
    for relation in design.relations:
        if relation.source_path == VPC_REF:
            refs.setdefault(relation.source_resource_id, []).append(relation)
    addresses = {resource.id: VpcAddresses() for resource in design.resources
                 if resource.type == "AWS::EC2::VPC"}
    findings: list[dict] = []

    def vpc_for(resource: Resource) -> Resource | None:
        found = refs.get(resource.id, [])
        if len(found) != 1:
            return None
        target = by_id.get(found[0].target_resource_id)
        if target is None and found[0].unresolved_name:
            matches = [item for item in design.resources if item.type == "AWS::EC2::VPC"
                       and item.name == found[0].unresolved_name and item.scope == resource.scope]
            target = matches[0] if len(matches) == 1 else None
        return target if target and target.type == "AWS::EC2::VPC" and target.scope == resource.scope else None

    def size_and_reserved(resource: Resource, network: ipaddress.IPv4Network, field: FieldValue):
        valid = 16 <= network.prefixlen <= 28
        findings.append(_finding("VPC_IPV4_CIDR_SIZE", resource, "PASS" if valid else "FAIL",
                                 "block size is between /16 and /28" if valid else
                                 "block size must be between /16 and /28",
                                 fields=(field,), expected="/16-/28", actual=str(network)))
        reserved = [str(item) for item in RESERVED if network.overlaps(item)]
        findings.append(_finding("VPC_IPV4_CIDR_RESERVED", resource, "FAIL" if reserved else "PASS",
                                 "block uses a range that cannot be assigned to a VPC" if reserved else
                                 "block avoids ranges that cannot be assigned to a VPC",
                                 fields=(field,), actual=reserved or str(network)))

    for vpc in (r for r in design.resources if r.type == "AWS::EC2::VPC"):
        kind, network, field = _ipv4(vpc)
        if kind == "known":
            addresses[vpc.id].blocks.append(Block(network, vpc, field, True))
            size_and_reserved(vpc, network, field)
        elif kind != "invalid":
            addresses[vpc.id].incomplete = True

    secondary: list[tuple[Resource, Block | None, FieldValue | None]] = []
    for association in (r for r in design.resources if r.type == "AWS::EC2::VPCCidrBlock"):
        kind, network, field = _ipv4(association)
        if kind == "absent":
            continue
        vpc = vpc_for(association)
        if vpc is None:
            for item in design.resources:
                if item.type == "AWS::EC2::VPC" and item.scope == association.scope:
                    addresses[item.id].incomplete = True
            if kind == "known":
                size_and_reserved(association, network, field)
                findings.append(_finding("VPC_SECONDARY_CIDR_RANGE", association, "NEEDS_REVIEW",
                                         "associated VPC is unresolved", fields=(field,),
                                         dependencies=[VPC_REF]))
            continue
        if kind == "known":
            block = Block(network, association, field, False)
            addresses[vpc.id].blocks.append(block)
            size_and_reserved(association, network, field)
            secondary.append((vpc, block, field))
        elif kind != "invalid":
            addresses[vpc.id].incomplete = True

    for vpc, block, field in secondary:
        state = addresses[vpc.id]
        others = [item for item in state.blocks if item is not block]
        overlapping = [item.resource.id for item in others if item.network.overlaps(block.network)]
        findings.append(_finding("VPC_SECONDARY_CIDR_OVERLAP", block.resource,
                                 "FAIL" if overlapping else "PASS",
                                 "block overlaps another block of the VPC" if overlapping else
                                 "block does not overlap the VPC's known blocks",
                                 fields=(field,), actual=overlapping or str(block.network)))
        primary = next((item for item in state.blocks if item.primary), None)
        if primary is None:
            findings.append(_finding("VPC_SECONDARY_CIDR_RANGE", block.resource, "NEEDS_REVIEW",
                                     "primary VPC CIDR block is not known", fields=(field,),
                                     dependencies=[CIDR]))
            continue
        reason = _restricted(primary.network, block.network, [item.network for item in others])
        findings.append(_finding("VPC_SECONDARY_CIDR_RANGE", block.resource,
                                 "FAIL" if reason else "PASS",
                                 reason or "block is permitted for the primary block's range",
                                 fields=(field, primary.field), expected=str(primary.network),
                                 actual=str(block.network)))
    return addresses, findings
