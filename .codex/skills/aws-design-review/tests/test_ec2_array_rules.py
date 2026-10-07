"""Aggregate and nested Tier 1 conditions."""
from aws_design_sheet.models import Candidate, FieldValue, Resource, Scope, ValueState
from aws_design_sheet.checks.ec2.array_rules import evaluate_ec2_fleet_override_limit, evaluate_ipam_resolver_rule_conditions, evaluate_spot_fleet_private_ips


SCOPE = Scope(environment="prod", account="111111111111", region="ap-northeast-1")


def field(name, value):
    path = "/properties/" + name
    return FieldValue(path=path, state=ValueState.KNOWN,
                      candidates=[Candidate(id=path, raw="given", value=value, evidence_ids=["e1"])],
                      selected_candidate_id=path)


def resource(type, **properties):
    return Resource(id="r", name="r", type="AWS::EC2::" + type, scope=SCOPE,
                    fields=[field(k, v) for k, v in properties.items()])


def test_fleet_override_count_across_configs():
    configs = [{"Overrides": [{}] * 200}, {"Overrides": [{}] * 101}]
    fleet = resource("EC2Fleet", Type="request", LaunchTemplateConfigs=configs)
    finding = evaluate_ec2_fleet_override_limit(fleet)
    assert finding["verdict"] == "FAIL"
    assert "301" in finding["reason"]
    fleet.fields[1] = field("LaunchTemplateConfigs", [{"Overrides": [{}] * 200},
                                                      {"Overrides": [{}] * 100}])
    assert evaluate_ec2_fleet_override_limit(fleet)["verdict"] == "PASS"
    fleet.fields[0] = field("Type", "instant")
    assert evaluate_ec2_fleet_override_limit(fleet)["verdict"] == "NOT_APPLICABLE"
    fleet.fields[1] = FieldValue(path="/properties/LaunchTemplateConfigs", state=ValueState.UNRESOLVED)
    fleet.fields[0] = field("Type", "request")
    assert evaluate_ec2_fleet_override_limit(fleet)["verdict"] == "NEEDS_REVIEW"


def test_ipam_rule_conditions_follow_parent_type():
    resolver = resource("IPAMPrefixListResolver", Rules=[
        {"RuleType": "ipam-pool-cidr", "Conditions": [{"IpamPoolId": "pool"}]},
        {"RuleType": "ipam-resource-cidr", "Conditions": [{"ResourceId": "vpc"}]}])
    assert evaluate_ipam_resolver_rule_conditions(resolver)["verdict"] == "PASS"
    resolver.fields[0] = field("Rules", [{"RuleType": "ipam-pool-cidr",
                                          "Conditions": [{"ResourceId": "vpc"}]}])
    assert evaluate_ipam_resolver_rule_conditions(resolver)["verdict"] == "FAIL"
    resolver.fields[0] = field("Rules", [{"RuleType": "static-cidr", "Conditions": [{"Cidr": "10.0.0.0/8"}]}])
    assert evaluate_ipam_resolver_rule_conditions(resolver)["verdict"] == "FAIL"
    resolver.fields[0] = FieldValue(path="/properties/Rules", state=ValueState.UNRESOLVED)
    assert evaluate_ipam_resolver_rule_conditions(resolver)["verdict"] == "NEEDS_REVIEW"


def test_spot_fleet_private_ip_array_conditions():
    specs = [{"NetworkInterfaces": [{"PrivateIpAddresses": [
        {"PrivateIpAddress": "10.0.0.5", "Primary": True},
        {"PrivateIpAddress": "10.0.0.6", "Primary": True}],
        "SecondaryPrivateIpAddressCount": 1}]}]
    fleet = resource("SpotFleet", SpotFleetRequestConfigData={"LaunchSpecifications": specs})
    results = evaluate_spot_fleet_private_ips(fleet)
    assert results[0]["verdict"] == "FAIL"
    specs[0]["NetworkInterfaces"][0]["PrivateIpAddresses"][1]["Primary"] = False
    assert evaluate_spot_fleet_private_ips(fleet)[1]["verdict"] == "FAIL"
    del specs[0]["NetworkInterfaces"][0]["SecondaryPrivateIpAddressCount"]
    assert all(item["verdict"] == "PASS" for item in evaluate_spot_fleet_private_ips(fleet))
