import copy
import json
from pathlib import Path

import pytest

from aws_design_sheet.checker import Checker
from aws_design_sheet.models import Design


ROOT = Path(__file__).resolve().parents[1]


def known(path, value, candidate):
    return {"path": path, "state": "KNOWN", "selected_candidate_id": candidate,
            "candidates": [{"id": candidate, "raw": str(value), "value": value,
                            "evidence_ids": ["e-vpc"]}]}


def design(subnet_cidr="10.0.1.0/24", *blocks):
    """valid.json (VPC 10.0.0.0/16) plus VPCCidrBlock associations given as (id, fields)."""
    data = json.loads((ROOT / "examples/valid.json").read_text(encoding="utf-8"))
    data["resources"][1]["fields"][0]["candidates"][0]["value"] = subnet_cidr
    scope = data["resources"][0]["scope"]
    for resource_id, fields in blocks:
        data["resources"].append({"id": resource_id, "type": "AWS::EC2::VPCCidrBlock",
                                  "name": resource_id, "scope": copy.deepcopy(scope), "fields": fields})
        data["relations"].append({"id": "ref-" + resource_id, "source_resource_id": resource_id,
                                  "source_path": "/properties/VpcId", "target_resource_id": "vpc-main"})
    return data


def cidr(resource_id, value):
    return resource_id, [known("/properties/CidrBlock", value, resource_id)]


def results(data, rule, resource_id=None):
    output = Checker(ROOT / "schemas", ROOT / "profiles/vpc-subnet.json").check(Design.model_validate(data))
    return [row["verdict"] for row in output["results"] if row["rule_id"] == rule and
            (resource_id is None or row["resource_id"] == resource_id)]


def test_subnet_in_secondary_block_is_contained():
    assert results(design("10.1.0.0/24"), "CIDR_CONTAINMENT") == ["FAIL"]
    assert results(design("10.1.0.0/24", cidr("second", "10.1.0.0/16")), "CIDR_CONTAINMENT") == ["PASS"]
    assert results(design("10.2.0.0/24", cidr("second", "10.1.0.0/16")), "CIDR_CONTAINMENT") == ["FAIL"]


def test_dynamic_or_unresolved_secondary_block_prevents_false_failure():
    pool = ("pool", [known("/properties/Ipv4IpamPoolId", "ipam-pool-0123", "pool")])
    assert results(design("10.9.0.0/24", pool), "CIDR_CONTAINMENT") == ["NEEDS_REVIEW"]
    assert results(design("10.0.1.0/24", pool), "CIDR_CONTAINMENT") == ["PASS"]
    pending = ("pending", [{"path": "/properties/CidrBlock", "state": "UNRESOLVED"}])
    assert results(design("10.9.0.0/24", pending), "CIDR_CONTAINMENT") == ["NEEDS_REVIEW"]
    ipv6_only = ("v6", [known("/properties/AmazonProvidedIpv6CidrBlock", True, "v6")])
    assert results(design("10.9.0.0/24", ipv6_only), "CIDR_CONTAINMENT") == ["FAIL"]


def test_block_size_and_reserved_ranges():
    assert results(design(), "VPC_IPV4_CIDR_SIZE", "vpc-main") == ["PASS"]
    assert results(design("10.0.1.0/24", cidr("wide", "10.4.0.0/14")), "VPC_IPV4_CIDR_SIZE", "wide") == ["FAIL"]
    assert results(design("10.0.1.0/24", cidr("tiny", "10.4.0.0/29")), "VPC_IPV4_CIDR_SIZE", "tiny") == ["FAIL"]
    assert results(design("10.0.1.0/24", cidr("link", "169.254.0.0/16")),
                   "VPC_IPV4_CIDR_RESERVED", "link") == ["FAIL"]
    assert results(design(), "VPC_IPV4_CIDR_RESERVED", "vpc-main") == ["PASS"]


def test_secondary_block_overlap():
    assert results(design("10.0.1.0/24", cidr("dup", "10.0.128.0/17")),
                   "VPC_SECONDARY_CIDR_OVERLAP", "dup") == ["FAIL"]
    assert results(design("10.0.1.0/24", cidr("a", "10.2.0.0/16"), cidr("b", "10.2.0.0/17")),
                   "VPC_SECONDARY_CIDR_OVERLAP", "b") == ["FAIL"]
    assert results(design("10.0.1.0/24", cidr("ok", "10.2.0.0/16")),
                   "VPC_SECONDARY_CIDR_OVERLAP", "ok") == ["PASS"]


@pytest.mark.parametrize("primary,secondary,verdict", [
    ("10.0.0.0/16", "10.2.0.0/16", "PASS"),
    ("10.0.0.0/16", "100.64.0.0/16", "PASS"),
    ("10.0.0.0/16", "203.0.113.0/24", "PASS"),
    ("10.0.0.0/16", "172.16.0.0/16", "FAIL"),
    ("10.0.0.0/16", "192.168.0.0/16", "FAIL"),
    ("10.0.0.0/16", "198.19.0.0/16", "FAIL"),
    ("10.1.0.0/16", "10.0.0.0/16", "FAIL"),
    ("172.16.0.0/16", "172.31.0.0/16", "FAIL"),
    ("172.16.0.0/16", "172.20.0.0/16", "PASS"),
    ("172.16.0.0/16", "10.0.0.0/16", "FAIL"),
    ("192.168.0.0/16", "172.16.0.0/16", "FAIL"),
    ("198.19.0.0/16", "10.0.0.0/16", "FAIL"),
    ("198.19.0.0/16", "100.64.0.0/16", "PASS"),
    ("100.64.0.0/16", "10.0.0.0/16", "FAIL"),
    ("100.64.0.0/16", "198.19.0.0/16", "FAIL"),
    ("100.64.0.0/16", "100.65.0.0/16", "PASS"),
])
def test_association_restrictions_follow_primary_range(primary, secondary, verdict):
    data = design("10.0.1.0/24", cidr("second", secondary))
    data["resources"][0]["fields"][0]["candidates"][0]["value"] = primary
    assert results(data, "VPC_SECONDARY_CIDR_RANGE", "second") == [verdict]


def test_primary_from_ipam_leaves_range_restriction_unresolved():
    data = design("10.0.1.0/24", cidr("second", "10.2.0.0/16"))
    data["resources"][0]["fields"][0] = {"path": "/properties/CidrBlock", "state": "MISSING"}
    data["resources"][0]["fields"].append(known("/properties/Ipv4IpamPoolId", "ipam-pool-1", "pool"))
    assert results(data, "VPC_SECONDARY_CIDR_RANGE", "second") == ["NEEDS_REVIEW"]
    assert results(data, "CIDR_CONTAINMENT") == ["NEEDS_REVIEW"]
