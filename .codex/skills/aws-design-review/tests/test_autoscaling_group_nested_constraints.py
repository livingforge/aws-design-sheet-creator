"""Nested Auto Scaling group conditions and Checker connection."""
import hashlib
from pathlib import Path

from aws_design_sheet.checker import Checker
from aws_design_sheet.models import Candidate, Design, Document, Evidence, FieldValue, Resource, Scope, ValueState
from aws_design_sheet.checks.autoscaling.group_nested_constraints import evaluate_group_nested_constraints

ROOT = Path(__file__).resolve().parents[1]


def group(**properties):
    fields = []
    for key, value in properties.items():
        path = "/properties/" + key
        fields.append(FieldValue(path=path, state=ValueState.KNOWN,
                                 candidates=[Candidate(id=path, raw=str(value), value=value, evidence_ids=["e1"])],
                                 selected_candidate_id=path))
    return Resource(id="group", name="group", type="AWS::AutoScaling::AutoScalingGroup",
                    scope=Scope(environment="prod", account="111111111111", region="ap-northeast-1"),
                    fields=fields)


def design(resource):
    content = "Auto Scaling group design"
    return Design(project="pilot", environment="prod", account=resource.scope.account,
                  documents=[Document(id="d1", name="input", version="1", text=content,
                                      sha256=hashlib.sha256(content.encode()).hexdigest())],
                  evidence=[Evidence(id="e1", document_id="d1", start_line=1, end_line=1, excerpt=content)],
                  resources=[resource])


def result(resource):
    return {row["rule_id"] + row["path"]: row["verdict"]
            for row in evaluate_group_nested_constraints(design(resource), resource)}


def test_maintenance_percentages():
    key = "AUTOSCALING_GROUP_MAINTENANCE_PERCENTAGES/properties/InstanceMaintenancePolicy"
    assert result(group(InstanceMaintenancePolicy={"MinHealthyPercentage": 50, "MaxHealthyPercentage": 150}))[key] == "PASS"
    assert result(group(InstanceMaintenancePolicy={"MinHealthyPercentage": 0, "MaxHealthyPercentage": 200}))[key] == "FAIL"
    assert result(group(InstanceMaintenancePolicy={"MinHealthyPercentage": 50}))[key] == "FAIL"
    assert result(group(InstanceMaintenancePolicy={"MinHealthyPercentage": {"$state": "UNRESOLVED"},
                                                   "MaxHealthyPercentage": 150}))[key] == "NEEDS_REVIEW"


def test_override_weights_and_strategy():
    base = {"LaunchTemplate": {"Overrides": [
        {"InstanceType": "m6i.large", "WeightedCapacity": "2"},
        {"InstanceType": "m6i.xlarge"}]}}
    weight = "AUTOSCALING_GROUP_WEIGHTED_CAPACITY_ALL/properties/MixedInstancesPolicy/LaunchTemplate/Overrides"
    assert result(group(MixedInstancesPolicy=base))[weight] == "FAIL"
    base["LaunchTemplate"]["Overrides"][1]["WeightedCapacity"] = "4"
    assert result(group(MixedInstancesPolicy=base))[weight] == "PASS"
    base["LaunchTemplate"]["Overrides"][1]["InstanceRequirements"] = {"VCpuCount": {"Min": 2}}
    base["InstancesDistribution"] = {"OnDemandAllocationStrategy": "prioritized",
                                     "SpotAllocationStrategy": "capacity-optimized-prioritized"}
    rows = result(group(MixedInstancesPolicy=base))
    assert rows["AUTOSCALING_GROUP_INSTANCE_REQUIREMENTS_STRATEGY/properties/MixedInstancesPolicy/InstancesDistribution/OnDemandAllocationStrategy"] == "FAIL"
    assert rows["AUTOSCALING_GROUP_INSTANCE_REQUIREMENTS_STRATEGY/properties/MixedInstancesPolicy/InstancesDistribution/SpotAllocationStrategy"] == "FAIL"
    base["LaunchTemplate"]["Overrides"][1].pop("InstanceRequirements")
    assert set(result(group(MixedInstancesPolicy=base)).values()) == {"PASS"}


def test_checker_includes_nested_group_finding():
    resource = group(MinSize=1, MaxSize=3, LaunchTemplate={"LaunchTemplateId": "lt-123", "Version": "1"},
                     InstanceMaintenancePolicy={"MinHealthyPercentage": 0, "MaxHealthyPercentage": 200})
    checked = Checker(ROOT / "schemas", ROOT / "profiles/vpc-subnet.json").check(design(resource))
    assert any(row["rule_id"] == "AUTOSCALING_GROUP_MAINTENANCE_PERCENTAGES"
               and row["verdict"] == "FAIL" for row in checked["results"])


def test_group_wide_override_limits():
    path = "/properties/MixedInstancesPolicy/LaunchTemplate/Overrides"
    types = "AUTOSCALING_GROUP_INSTANCE_TYPE_LIMIT" + path
    requirements = "AUTOSCALING_GROUP_INSTANCE_REQUIREMENTS_LIMIT" + path

    def check(overrides):
        return result(group(MixedInstancesPolicy={"LaunchTemplate": {"Overrides": overrides}}))

    assert check([{"InstanceType": f"m6i.{i}"} for i in range(40)])[types] == "PASS"
    assert check([{"InstanceType": f"m6i.{i}"} for i in range(41)])[types] == "FAIL"
    req = {"VCpuCount": {"Min": 2}, "MemoryMiB": {"Min": 4096}}
    assert check([{"InstanceRequirements": req} for _ in range(4)])[requirements] == "PASS"
    assert check([{"InstanceRequirements": req} for _ in range(5)])[requirements] == "FAIL"
    assert check([{"InstanceType": f"m6i.{i}"} for i in range(40)] +
                 [{"InstanceType": {"$state": "UNRESOLVED"}}])[types] == "NEEDS_REVIEW"
    assert check([{"InstanceRequirements": req} for _ in range(5)] +
                 [{"InstanceRequirements": {"$state": "UNRESOLVED"}}])[requirements] == "FAIL"
    assert check([{"InstanceRequirements": req}, {"$state": "UNRESOLVED"}])[requirements] == "PASS"

    resource = group(MinSize=1, MaxSize=3,
                     MixedInstancesPolicy={"LaunchTemplate": {
                         "LaunchTemplateSpecification": {"LaunchTemplateId": "lt-123", "Version": "1"},
                         "Overrides": [{"InstanceType": f"m6i.{i}"} for i in range(41)]}})
    checked = Checker(ROOT / "schemas", ROOT / "profiles/vpc-subnet.json").check(design(resource))
    assert any(row["rule_id"] == "AUTOSCALING_GROUP_INSTANCE_TYPE_LIMIT" and row["verdict"] == "FAIL"
               for row in checked["results"])
