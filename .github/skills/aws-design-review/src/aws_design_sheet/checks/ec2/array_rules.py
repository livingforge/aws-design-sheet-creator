"""EC2 conditions that compare items across nested property arrays."""
from __future__ import annotations

from ...models import ValueState
from ..registry import resource_check


SOURCES = {
    "EC2_FLEET_OVERRIDE_AGGREGATE_LIMIT": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-ec2-ec2fleet-fleetlaunchtemplateconfigrequest.html"],
    "EC2_IPAM_RESOLVER_RULE_CONDITIONS": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-ec2-ipamprefixlistresolver-ipamprefixlistresolverrulecondition.html"],
    "EC2_SPOT_FLEET_PRIMARY_PRIVATE_IP_UNIQUE": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-ec2-spotfleet-instancenetworkinterfacespecification.html"],
    "EC2_SPOT_FLEET_SECONDARY_IP_COUNT_EXCLUSIVE": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-ec2-spotfleet-instancenetworkinterfacespecification.html"],
}


def _result(resource: Resource, rule_id: str, path: str, verdict: str,
            reason: str, evidence: list[str], dependencies: list[str]) -> dict[str, Any]:
    return {"rule_id": rule_id, "resource_id": resource.id, "path": path,
            "verdict": verdict, "reason": reason,
            "dependencies": dependencies, "evidence_ids": list(dict.fromkeys(evidence))}


def _known(resource: Resource, path: str) -> tuple[Any, list[str], bool]:
    field = resource.field(path)
    if field is None or field.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        return None, [], True
    evidence = [*field.intent_evidence_ids,
                *(id for candidate in field.candidates for id in candidate.evidence_ids)]
    if field.state != ValueState.KNOWN:
        return None, evidence, False
    return field.selected().value, evidence, True


@resource_check('AWS::EC2::EC2Fleet')
def evaluate_ec2_fleet_override_limit(resource: Resource) -> dict[str, Any]:
    rule = "EC2_FLEET_OVERRIDE_AGGREGATE_LIMIT"
    path = "/properties/LaunchTemplateConfigs"
    fleet_type, type_evidence, type_known = _known(resource, "/properties/Type")
    configs, evidence, configs_known = _known(resource, path)
    evidence += type_evidence
    if not type_known or (fleet_type is not None and fleet_type not in ("request", "maintain", "instant")):
        return _result(resource, rule, path, "NEEDS_REVIEW", "fleet type is unresolved",
                       evidence, ["/properties/Type"])
    if fleet_type == "instant":
        return _result(resource, rule, path, "NOT_APPLICABLE", "limit applies to request and maintain fleets",
                       evidence, [])
    if not configs_known or not isinstance(configs, list):
        return _result(resource, rule, path, "NEEDS_REVIEW", "launch template configurations are unresolved",
                       evidence, [path])
    total = 0
    for index, config in enumerate(configs):
        if not isinstance(config, dict):
            return _result(resource, rule, path, "NEEDS_REVIEW", "a launch template configuration is unresolved",
                           evidence, [f"{path}/{index}"])
        overrides = config.get("Overrides", [])
        if not isinstance(overrides, list):
            return _result(resource, rule, path, "NEEDS_REVIEW", "an overrides array is unresolved",
                           evidence, [f"{path}/{index}/Overrides"])
        total += len(overrides)
    verdict = "FAIL" if total > 300 else "PASS"
    return _result(resource, rule, path, verdict, f"{total} overrides across launch templates (maximum 300)",
                   evidence, [])


@resource_check('AWS::EC2::IPAMPrefixListResolver')
def evaluate_ipam_resolver_rule_conditions(resource: Resource) -> dict[str, Any]:
    rule = "EC2_IPAM_RESOLVER_RULE_CONDITIONS"
    path = "/properties/Rules"
    rules, evidence, known = _known(resource, path)
    if rules is None and known:
        return _result(resource, rule, path, "NOT_APPLICABLE", "no selection rules are configured",
                       evidence, [])
    if not known or not isinstance(rules, list):
        return _result(resource, rule, path, "NEEDS_REVIEW", "selection rules are unresolved",
                       evidence, [path])
    for index, item in enumerate(rules):
        if not isinstance(item, dict) or not isinstance(item.get("RuleType"), str):
            return _result(resource, rule, path, "NEEDS_REVIEW", "a rule type is unresolved",
                           evidence, [f"{path}/{index}/RuleType"])
        kind = item["RuleType"]
        conditions = item.get("Conditions", [])
        if not isinstance(conditions, list):
            return _result(resource, rule, path, "NEEDS_REVIEW", "rule conditions are unresolved",
                           evidence, [f"{path}/{index}/Conditions"])
        if kind == "static-cidr" and conditions:
            return _result(resource, rule, path, "FAIL", "static CIDR rules cannot have conditions",
                           evidence, [])
        if kind not in ("static-cidr", "ipam-pool-cidr", "ipam-resource-cidr"):
            return _result(resource, rule, path, "NEEDS_REVIEW", "rule type is not recognized",
                           evidence, [f"{path}/{index}/RuleType"])
        for condition in conditions:
            if not isinstance(condition, dict):
                return _result(resource, rule, path, "NEEDS_REVIEW", "a condition is unresolved",
                               evidence, [f"{path}/{index}/Conditions"])
            if kind == "ipam-pool-cidr" and any(key in condition for key in (
                    "ResourceId", "ResourceOwner", "ResourceRegion", "ResourceTag")):
                return _result(resource, rule, path, "FAIL", "resource conditions require ipam-resource-cidr",
                               evidence, [])
            if kind == "ipam-resource-cidr" and "IpamPoolId" in condition:
                return _result(resource, rule, path, "FAIL", "IpamPoolId requires ipam-pool-cidr",
                               evidence, [])
    return _result(resource, rule, path, "PASS", "rule conditions match their rule types",
                   evidence, [])


@resource_check('AWS::EC2::SpotFleet')
def evaluate_spot_fleet_private_ips(resource: Resource) -> list[dict[str, Any]]:
    base = "/properties/SpotFleetRequestConfigData"
    config, evidence, known = _known(resource, base)
    rules = ("EC2_SPOT_FLEET_PRIMARY_PRIVATE_IP_UNIQUE",
             "EC2_SPOT_FLEET_SECONDARY_IP_COUNT_EXCLUSIVE")
    if not known or not isinstance(config, dict):
        return [_result(resource, rule, base, "NEEDS_REVIEW", "Spot Fleet configuration is unresolved",
                        evidence, [base]) for rule in rules]
    specifications = config.get("LaunchSpecifications")
    if specifications is None:
        return [_result(resource, rule, base, "NOT_APPLICABLE", "no launch specifications are configured",
                        evidence, []) for rule in rules]
    if not isinstance(specifications, list):
        return [_result(resource, rule, base, "NEEDS_REVIEW", "launch specifications are unresolved",
                        evidence, [f"{base}/LaunchSpecifications"]) for rule in rules]
    violations: dict[str, str] = {}
    uncertain = False
    for specification in specifications:
        if not isinstance(specification, dict):
            uncertain = True
            continue
        interfaces = specification.get("NetworkInterfaces", [])
        if not isinstance(interfaces, list):
            uncertain = True
            continue
        for interface in interfaces:
            if not isinstance(interface, dict):
                uncertain = True
                continue
            addresses = interface.get("PrivateIpAddresses", [])
            if not isinstance(addresses, list) or any(not isinstance(item, dict) for item in addresses):
                uncertain = True
                continue
            if sum(item.get("Primary") is True for item in addresses) > 1:
                violations[rules[0]] = "more than one private IP address is marked primary"
            if "SecondaryPrivateIpAddressCount" in interface and any(
                    item.get("Primary") is False for item in addresses):
                violations[rules[1]] = "secondary address count is combined with a specified secondary IP"
    return [_result(resource, rule, base, "FAIL" if rule in violations else
                    "NEEDS_REVIEW" if uncertain else "PASS",
                    violations.get(rule, "a launch specification is unresolved" if uncertain else
                                   "private IP address settings are consistent"),
                    evidence, [base] if uncertain and rule not in violations else []) for rule in rules]
