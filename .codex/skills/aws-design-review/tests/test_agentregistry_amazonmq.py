import json
from pathlib import Path

from aws_design_sheet.checker import Checker
from aws_design_sheet.models import Design


ROOT = Path(__file__).resolve().parents[1]


def known(path, value):
    return {"path": path, "state": "KNOWN", "selected_candidate_id": "value",
            "candidates": [{"id": "value", "raw": str(value), "value": value,
                            "evidence_ids": ["e-vpc"]}]}


def results(resource_type, fields, target_type=None):
    data = json.loads((ROOT / "examples/valid.json").read_text(encoding="utf-8"))
    scope = data["resources"][0]["scope"]
    data["resources"].append({"id": "subject", "type": resource_type,
                              "name": "subject", "scope": scope, "fields": fields})
    if target_type:
        data["resources"].append({"id": "target", "type": target_type,
                                  "name": "target", "scope": scope, "fields": []})
        data["relations"].append({"id": "broker-ref", "source_resource_id": "subject",
                                  "source_path": "/properties/Broker", "target_resource_id": "target"})
    output = Checker(ROOT / "schemas", ROOT / "profiles/vpc-subnet.json").check(
        Design.model_validate(data))
    return [row for row in output["results"] if row["resource_id"] == "subject"]


def verdict(resource_type, rule, fields):
    return next(row["verdict"] for row in results(resource_type, fields)
                if row["rule_id"] == rule)


def test_registry_custom_jwt_requires_authorizer_configuration():
    resource = "AWS::AgentRegistry::Registry"
    rule = "AGENT_REGISTRY_CUSTOM_JWT_AUTHORIZER"
    jwt = known("/properties/AuthorizerType", "CUSTOM_JWT")
    config = "/properties/DiscoveryConfiguration"
    assert verdict(resource, rule, []) == "NOT_APPLICABLE"
    assert verdict(resource, rule, [jwt]) == "FAIL"
    assert verdict(resource, rule, [jwt, known(config, {})]) == "FAIL"
    assert verdict(resource, rule, [jwt, known(config, {"AuthorizerConfiguration": {}})]) == "FAIL"
    assert verdict(resource, rule, [jwt, known(config, {"AuthorizerConfiguration": {
        "CustomJWTAuthorizer": {"DiscoveryUrl": "https://example.com/.well-known/openid-configuration"}}})]) == "PASS"
    assert verdict(resource, rule, [jwt, {"path": config, "state": "UNRESOLVED"}]) == "NEEDS_REVIEW"


def test_registry_record_requires_one_matching_descriptor():
    resource = "AWS::AgentRegistry::RegistryRecord"
    rule = "AGENT_REGISTRY_RECORD_DESCRIPTOR"
    record_type = known("/properties/RecordType", "MCP")
    descriptor_path = "/properties/Descriptors"
    assert verdict(resource, rule, [record_type, known(descriptor_path, {"McpServer": {}})]) == "PASS"
    assert verdict(resource, rule, [record_type, known(descriptor_path, {"Custom": {}})]) == "FAIL"
    assert verdict(resource, rule, [record_type, known(descriptor_path, {})]) == "FAIL"
    assert verdict(resource, rule, [record_type, known(descriptor_path, {"McpServer": {}, "Custom": {}})]) == "FAIL"
    assert verdict(resource, rule, [known("/properties/RecordType", "GATEWAY"),
                                    known(descriptor_path, {"McpServer": {}})]) == "NEEDS_REVIEW"


def test_amazonmq_replication_primary():
    resource = "AWS::AmazonMQ::Broker"
    rule = "AMAZONMQ_CRDR_PRIMARY_BROKER"
    mode = known("/properties/DataReplicationMode", "CRDR")
    primary = "/properties/DataReplicationPrimaryBrokerArn"
    assert verdict(resource, rule, []) == "NOT_APPLICABLE"
    assert verdict(resource, rule, [mode]) == "FAIL"
    assert verdict(resource, rule, [mode, known(primary, "arn:aws:mq:us-west-2:111111111111:broker:primary:id")]) == "PASS"
    assert verdict(resource, rule, [mode, {"path": primary, "state": "UNRESOLVED"}]) == "NEEDS_REVIEW"


def test_configuration_association_broker_reference():
    source = "AWS::AmazonMQ::ConfigurationAssociation"
    good = [row for row in results(source, [], "AWS::AmazonMQ::Broker") if row["rule_id"] == "REFERENCE"]
    bad = [row for row in results(source, [], "AWS::EC2::VPC") if row["rule_id"] == "REFERENCE"]
    assert good[0]["verdict"] == "PASS"
    assert bad[0]["verdict"] == "FAIL"
