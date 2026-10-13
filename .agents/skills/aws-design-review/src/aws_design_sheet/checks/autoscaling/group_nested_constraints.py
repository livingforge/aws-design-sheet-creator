"""Auto Scaling group conditions involving nested or sibling values."""
from __future__ import annotations

from ...models import ValueState
from ..registry import resource_check
from ..common.context import Context


SOURCES = {
    "AUTOSCALING_GROUP_MAINTENANCE_PERCENTAGES": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-autoscaling-autoscalinggroup-instancemaintenancepolicy.html"],
    "AUTOSCALING_GROUP_WEIGHTED_CAPACITY_ALL": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-autoscaling-autoscalinggroup-launchtemplateoverrides.html"],
    "AUTOSCALING_GROUP_INSTANCE_TYPE_LIMIT": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-autoscaling-autoscalinggroup-launchtemplateoverrides.html"],
    "AUTOSCALING_GROUP_INSTANCE_REQUIREMENTS_LIMIT": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-autoscaling-autoscalinggroup-launchtemplateoverrides.html"],
    "AUTOSCALING_GROUP_INSTANCE_REQUIREMENTS_STRATEGY": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-autoscaling-autoscalinggroup-instancesdistribution.html"],
}


class _Context(Context):
    def finding(self, rule_id: str, path: str, verdict: str, reason: str) -> dict:
        return {**super().finding(rule_id, path, verdict, reason),
                "source_checked_at": "2026-10-01"}


def _nested(ctx: _Context, resource: Resource, root: str, *keys: str):
    """Return (value, unresolved); an absent nested member has value None."""
    path = "/properties/" + root
    field = resource.field(path)
    if field is None or field.state in (ValueState.MISSING, ValueState.NOT_APPLICABLE):
        return None, False
    value = ctx.value(resource, path)
    if field.state != ValueState.KNOWN or not isinstance(value, dict):
        return None, True
    for key in keys:
        if not isinstance(value, dict):
            ctx.dependencies.append(resource.id + path)
            return None, True
        value = value.get(key)
    if isinstance(value, dict) and value.get("$state") == "UNRESOLVED":
        ctx.dependencies.append(resource.id + path)
        return None, True
    return value, False


@resource_check('AWS::AutoScaling::AutoScalingGroup')
def evaluate_group_nested_constraints(design: Design, resource: Resource) -> list[dict]:
    ctx = _Context(design, resource)
    results = []
    maintenance_path = "/properties/InstanceMaintenancePolicy"
    policy, unknown = _nested(ctx, resource, "InstanceMaintenancePolicy")
    if unknown:
        results.append(ctx.finding("AUTOSCALING_GROUP_MAINTENANCE_PERCENTAGES", maintenance_path,
                                   "NEEDS_REVIEW", "instance maintenance policy is unresolved"))
    elif isinstance(policy, dict):
        minimum, maximum = policy.get("MinHealthyPercentage"), policy.get("MaxHealthyPercentage")
        if minimum is None and maximum is None:
            verdict, reason = "NOT_APPLICABLE", "neither healthy percentage is specified"
        elif minimum is None or maximum is None:
            verdict, reason = "FAIL", "both healthy percentages must be specified together"
        elif isinstance(minimum, bool) or isinstance(maximum, bool) or not isinstance(minimum, int) or not isinstance(maximum, int):
            verdict, reason = "NEEDS_REVIEW", "both healthy percentages must be known integers"
            ctx.dependencies.append(resource.id + maintenance_path)
        elif maximum - minimum > 100:
            verdict, reason = "FAIL", "healthy percentage difference exceeds 100"
        else:
            verdict, reason = "PASS", "healthy percentage difference is at most 100"
        results.append(ctx.finding("AUTOSCALING_GROUP_MAINTENANCE_PERCENTAGES", maintenance_path,
                                   verdict, reason))

    overrides_path = "/properties/MixedInstancesPolicy/LaunchTemplate/Overrides"
    mixed, unknown = _nested(ctx, resource, "MixedInstancesPolicy")
    if unknown:
        for rule in ("AUTOSCALING_GROUP_WEIGHTED_CAPACITY_ALL",
                     "AUTOSCALING_GROUP_INSTANCE_REQUIREMENTS_STRATEGY",
                     "AUTOSCALING_GROUP_INSTANCE_TYPE_LIMIT",
                     "AUTOSCALING_GROUP_INSTANCE_REQUIREMENTS_LIMIT"):
            results.append(ctx.finding(rule, overrides_path, "NEEDS_REVIEW",
                                       "mixed instances policy is unresolved"))
        return results
    if not isinstance(mixed, dict):
        return results
    launch = mixed.get("LaunchTemplate")
    overrides = launch.get("Overrides") if isinstance(launch, dict) else None
    if isinstance(launch, dict) and launch.get("$state") == "UNRESOLVED":
        overrides = launch
    if overrides is not None:
        if not isinstance(overrides, list) or any(not isinstance(item, dict) for item in overrides):
            ctx.dependencies.append(resource.id + overrides_path)
            results.append(ctx.finding("AUTOSCALING_GROUP_WEIGHTED_CAPACITY_ALL", overrides_path,
                                       "NEEDS_REVIEW", "launch template overrides are unresolved"))
        else:
            typed = [item for item in overrides if item.get("InstanceType") is not None]
            weighted = [item for item in typed if item.get("WeightedCapacity") is not None]
            if any(isinstance(item.get("InstanceType"), dict) or
                   isinstance(item.get("WeightedCapacity"), dict) for item in overrides):
                verdict, reason = "NEEDS_REVIEW", "instance type or weight is unresolved"
                ctx.dependencies.append(resource.id + overrides_path)
            elif weighted and len(weighted) != len(typed):
                verdict, reason = "FAIL", "every instance type override needs a weight when one has a weight"
            else:
                verdict, reason = "PASS", "instance type override weights are consistent"
            results.append(ctx.finding("AUTOSCALING_GROUP_WEIGHTED_CAPACITY_ALL", overrides_path,
                                       verdict, reason))

    # These limits apply to the group as a whole, rather than to each override.
    # An unresolved override can contribute at most one to either count.
    for rule, key, limit in (
        ("AUTOSCALING_GROUP_INSTANCE_TYPE_LIMIT", "InstanceType", 40),
        ("AUTOSCALING_GROUP_INSTANCE_REQUIREMENTS_LIMIT", "InstanceRequirements", 4),
    ):
        if overrides is None:
            continue
        if not isinstance(overrides, list):
            verdict, reason = "NEEDS_REVIEW", "launch template overrides are unresolved"
        else:
            present = 0
            uncertain = 0
            for item in overrides:
                if not isinstance(item, dict) or item.get("$state") == "UNRESOLVED":
                    uncertain += 1
                    continue
                value = item.get(key)
                if value is None:
                    continue
                if isinstance(value, dict) and value.get("$state") == "UNRESOLVED":
                    uncertain += 1
                else:
                    present += 1
            if present > limit:
                verdict, reason = "FAIL", f"more than {limit} {key} overrides are specified"
            elif present + uncertain > limit:
                verdict, reason = "NEEDS_REVIEW", f"unresolved overrides may exceed the {limit} {key} limit"
            else:
                verdict, reason = "PASS", f"at most {limit} {key} overrides are specified"
        if verdict == "NEEDS_REVIEW":
            ctx.dependencies.append(resource.id + overrides_path)
        results.append(ctx.finding(rule, overrides_path, verdict, reason))

    distribution = mixed.get("InstancesDistribution")
    if not isinstance(distribution, dict):
        return results
    strategies = (("OnDemandAllocationStrategy", "prioritized"),
                  ("SpotAllocationStrategy", "capacity-optimized-prioritized"))
    for property_name, prohibited in strategies:
        strategy = distribution.get(property_name)
        if strategy != prohibited and not isinstance(strategy, dict):
            continue
        path = "/properties/MixedInstancesPolicy/InstancesDistribution/" + property_name
        if isinstance(strategy, dict) or not isinstance(overrides, list) or any(not isinstance(item, dict) for item in overrides):
            verdict, reason = "NEEDS_REVIEW", "strategy or instance requirements are unresolved"
            ctx.dependencies.append(resource.id + path)
        elif any(isinstance(item.get("InstanceRequirements"), dict) and
                 item["InstanceRequirements"].get("$state") == "UNRESOLVED" for item in overrides):
            verdict, reason = "NEEDS_REVIEW", "instance requirements are unresolved"
            ctx.dependencies.append(resource.id + overrides_path)
        elif any(item.get("InstanceRequirements") is not None for item in overrides):
            verdict, reason = "FAIL", "priority strategy cannot be used with instance requirements"
        else:
            verdict, reason = "PASS", "priority strategy has no instance requirements"
        results.append(ctx.finding("AUTOSCALING_GROUP_INSTANCE_REQUIREMENTS_STRATEGY", path,
                                   verdict, reason))
    return results
