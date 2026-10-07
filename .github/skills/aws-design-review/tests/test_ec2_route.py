import hashlib

from aws_design_sheet.models import Design
from aws_design_sheet.checks.ec2.route import evaluate_ec2_route_destination_and_target


def design(fields=None, relations=None, resource_type="AWS::EC2::Route"):
    fields = fields or {}
    text = "route design"
    values = []
    for index, (name, specification) in enumerate(fields.items()):
        path = f"/properties/{name}"
        if isinstance(specification, tuple):
            state, raw = specification
        else:
            state, raw = "KNOWN", specification
        item = {"path": path, "state": state}
        if state == "KNOWN":
            item.update(selected_candidate_id=f"c-{index}", candidates=[{
                "id": f"c-{index}", "raw": str(raw), "value": raw, "evidence_ids": ["e-1"]}])
        elif state in ("CONFLICT", "INFERRED"):
            candidates = [{"id": f"c-{index}-a", "raw": "one", "value": "one", "evidence_ids": ["e-1"]}]
            if state == "CONFLICT":
                candidates.append({"id": f"c-{index}-b", "raw": "two", "value": "two", "evidence_ids": ["e-1"]})
            item["candidates"] = candidates
        values.append(item)
    relation_items = [{"id": f"r-{i}", "source_resource_id": "route",
                       "source_path": f"/properties/{name}", "unresolved_name": "x",
                       "expected_target_type": "AWS::EC2::NatGateway", "evidence_ids": ["e-1"]}
                      for i, name in enumerate(relations or [], 1)]
    return Design.model_validate({
        "project": "test", "environment": "prod", "account": "111111111111",
        "documents": [{"id": "d-1", "name": "note", "version": "1", "sha256": hashlib.sha256(text.encode()).hexdigest(),
                       "text": text, "extracted_ranges": [[1, 1]]}],
        "evidence": [{"id": "e-1", "document_id": "d-1", "start_line": 1,
                      "end_line": 1, "excerpt": text}],
        "resources": [{"id": "route", "type": resource_type, "name": "route", "scope": {
            "environment": "prod", "account": "111111111111", "region": "ap-northeast-1"},
                       "fields": values}], "relations": relation_items})


def evaluate(data):
    return evaluate_ec2_route_destination_and_target(data, data.resources[0])


def test_one_destination_and_target_pass_with_evidence():
    result = evaluate(design({"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-1",
                              "RouteTableId": "rtb-1"}))
    assert result["verdict"] == "PASS"
    assert result["evidence_ids"] == ["e-1"]
    assert result["path"] == "/properties"


def test_relation_only_property_counts_as_specified():
    result = evaluate(design({"DestinationCidrBlock": "0.0.0.0/0"}, relations=["NatGatewayId"]))
    assert result["verdict"] == "PASS"


def test_missing_destination_or_target_fails():
    assert evaluate(design({"NatGatewayId": "nat-1"}))["verdict"] == "FAIL"
    assert evaluate(design({"DestinationCidrBlock": "0.0.0.0/0"}))["verdict"] == "FAIL"
    assert evaluate(design({"RouteTableId": "rtb-1"}))["verdict"] == "FAIL"


def test_proven_excess_fails_even_with_uncertain_other_values():
    result = evaluate(design({"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1",
                              "NatGatewayId": "nat-1", "InstanceId": ("CONFLICT", None)}))
    assert result["verdict"] == "FAIL"
    result = evaluate(design({"DestinationCidrBlock": "0.0.0.0/0",
                              "DestinationPrefixListId": "pl-1", "NatGatewayId": "nat-1"}))
    assert result["verdict"] == "FAIL"


def test_uncertain_selection_needs_review_with_dependency():
    result = evaluate(design({"DestinationCidrBlock": "0.0.0.0/0",
                              "NatGatewayId": ("INFERRED", None)}))
    assert result["verdict"] == "NEEDS_REVIEW"
    assert result["dependencies"] == ["/properties/NatGatewayId"]
    result = evaluate(design({"DestinationIpv6CidrBlock": ("UNRESOLVED", None),
                              "NatGatewayId": "nat-1"}))
    assert result["verdict"] == "NEEDS_REVIEW"


def test_invalid_scalar_is_left_for_schema_checker():
    result = evaluate(design({"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": []}))
    assert result["verdict"] == "NEEDS_REVIEW"


def test_other_type_is_not_applicable():
    result = evaluate(design(resource_type="AWS::EC2::VPC"))
    assert result["verdict"] == "NOT_APPLICABLE"
