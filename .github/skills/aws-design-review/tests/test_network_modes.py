import copy
import json
from pathlib import Path

from aws_design_sheet.checker import Checker
from aws_design_sheet.models import Design


ROOT = Path(__file__).resolve().parents[1]


def design():
    return json.loads((ROOT / "examples/valid.json").read_text(encoding="utf-8"))


def known(path, value, candidate):
    return {"path": path, "state": "KNOWN", "selected_candidate_id": candidate,
            "candidates": [{"id": candidate, "raw": str(value), "value": value,
                            "evidence_ids": ["e-vpc"]}]}


def verdicts(data, rule):
    result = Checker(ROOT / "schemas", ROOT / "profiles/vpc-subnet.json").check(
        Design.model_validate(data))
    return [item for item in result["results"] if item["rule_id"] == rule]


def test_vpc_ipv4_source_choices():
    data = design()
    assert verdicts(data, "VPC_IPV4_SOURCE")[0]["verdict"] == "PASS"
    data["resources"][0]["fields"].append(known("/properties/Ipv4IpamPoolId", "ipam-pool-123", "pool"))
    assert verdicts(data, "VPC_IPV4_SOURCE")[0]["verdict"] == "FAIL"
    data["resources"][0]["fields"][0] = {"path": "/properties/CidrBlock", "state": "MISSING"}
    assert verdicts(data, "VPC_IPV4_SOURCE")[0]["verdict"] == "PASS"
    data["resources"][0]["fields"][-1]["state"] = "UNRESOLVED"
    data["resources"][0]["fields"][-1]["selected_candidate_id"] = None
    assert verdicts(data, "VPC_IPV4_SOURCE")[0]["verdict"] == "NEEDS_REVIEW"


def test_ipv6_containment_overlap_and_invalid_cidr():
    data = design()
    subnet = data["resources"][1]
    subnet["fields"].append(known("/properties/Ipv6CidrBlock", "2001:db8:1:1::/64", "ip6"))
    association = {"id": "vpc-ipv6", "type": "AWS::EC2::VPCCidrBlock", "name": "ipv6",
                   "scope": copy.deepcopy(data["resources"][0]["scope"]),
                   "fields": [known("/properties/Ipv6CidrBlock", "2001:db8:1::/56", "parent6")]}
    data["resources"].append(association)
    data["relations"].append({"id": "assoc-vpc", "source_resource_id": "vpc-ipv6",
                              "source_path": "/properties/VpcId", "target_resource_id": "vpc-main"})
    assert verdicts(data, "IPV6_CIDR_CONTAINMENT")[0]["verdict"] == "PASS"

    other = copy.deepcopy(subnet)
    other["id"] = "subnet-b"
    other["name"] = "app-b"
    other["fields"][-1]["candidates"][0]["value"] = "2001:db8:1:1::/64"
    data["resources"].append(other)
    data["relations"].append({"id": "rel-b", "source_resource_id": "subnet-b",
                              "source_path": "/properties/VpcId", "target_resource_id": "vpc-main"})
    assert verdicts(data, "IPV6_CIDR_OVERLAP")[0]["verdict"] == "FAIL"
    other["fields"][-1]["candidates"][0]["value"] = "2001:db8:2::/64"
    assert any(item["verdict"] == "FAIL" for item in verdicts(data, "IPV6_CIDR_CONTAINMENT"))
    other["fields"][-1]["candidates"][0]["value"] = "2001:db8:1:1::1/64"
    assert any(item["resource_id"] == "subnet-b" for item in verdicts(data, "IPV6_CIDR_FORMAT"))


def test_ipv6_allocation_unknown_stays_review():
    data = design()
    data["resources"][1]["fields"].append(known("/properties/Ipv6CidrBlock", "2001:db8:1:1::/64", "ip6"))
    assert verdicts(data, "IPV6_CIDR_CONTAINMENT")[0]["verdict"] == "NEEDS_REVIEW"


def test_unknown_second_vpc_range_prevents_false_failure():
    data = design()
    data["resources"][1]["fields"].append(known("/properties/Ipv6CidrBlock", "2001:db8:2::/64", "ip6"))
    for resource_id, cidr in (("known", "2001:db8:1::/56"), ("dynamic", None)):
        association = {"id": resource_id, "type": "AWS::EC2::VPCCidrBlock", "name": resource_id,
                       "scope": copy.deepcopy(data["resources"][0]["scope"]),
                       "fields": [known("/properties/Ipv6CidrBlock", cidr, resource_id)] if cidr else []}
        data["resources"].append(association)
        data["relations"].append({"id": "ref-" + resource_id,
                                  "source_resource_id": resource_id, "source_path": "/properties/VpcId",
                                  "target_resource_id": "vpc-main"})
    assert verdicts(data, "IPV6_CIDR_CONTAINMENT")[0]["verdict"] == "NEEDS_REVIEW"


def test_automatic_ipv6_assignment_requires_subnet_range():
    data = design()
    subnet = data["resources"][1]
    subnet["fields"].append(known("/properties/AssignIpv6AddressOnCreation", True, "assign6"))
    assert verdicts(data, "SUBNET_IPV6_ASSIGNMENT")[0]["verdict"] == "FAIL"
    subnet["fields"].append(known("/properties/Ipv6CidrBlock", "2001:db8:1::/64", "ip6"))
    assert verdicts(data, "SUBNET_IPV6_ASSIGNMENT")[0]["verdict"] == "PASS"
