"""Checks for AWS::AutoScaling::ScalingPolicy, AWS::AutoScaling::AutoScalingGroup."""
from __future__ import annotations

import re
from decimal import Decimal
from ..registry import resource_check
from .group_nested_constraints import _Context
from ..common.field_reads import ABSENT, UNKNOWN, linked, read


SOURCES = {
    "AUTOSCALING_POLICY_QUERY_IDS": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-autoscaling-scalingpolicy-metricdataquery.html#cfn-autoscaling-scalingpolicy-metricdataquery-id",
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-autoscaling-scalingpolicy-targettrackingmetricdataquery.html#cfn-autoscaling-scalingpolicy-targettrackingmetricdataquery-id"],
    "AUTOSCALING_POLICY_QUERY_RETURN_DATA": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-autoscaling-scalingpolicy-metricdataquery.html#cfn-autoscaling-scalingpolicy-metricdataquery-returndata",
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-autoscaling-scalingpolicy-targettrackingmetricdataquery.html#cfn-autoscaling-scalingpolicy-targettrackingmetricdataquery-returndata"],
    "AUTOSCALING_GROUP_LAUNCH_TEMPLATE_LIMIT": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-autoscaling-autoscalinggroup-launchtemplateoverrides.html"],
    "AUTOSCALING_GROUP_SUBNET_AVAILABILITY_ZONES": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-autoscaling-autoscalinggroup.html#cfn-autoscaling-autoscalinggroup-vpczoneidentifier"],
    "AUTOSCALING_GROUP_CLUSTER_PLACEMENT_SINGLE_AZ": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-autoscaling-autoscalinggroup.html#cfn-autoscaling-autoscalinggroup-placementgroup"],
    "AUTOSCALING_GROUP_LAUNCH_CONFIGURATION_SUBNET": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-autoscaling-launchconfiguration.html"],
    "AUTOSCALING_GROUP_TRAFFIC_SOURCE_KIND": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-autoscaling-autoscalinggroup-trafficsourceidentifier.html"],
    "AUTOSCALING_POLICY_STEP_INTERVALS": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-autoscaling-scalingpolicy-stepadjustment.html"],
    "AUTOSCALING_POLICY_STEP_EXACT_CAPACITY": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-autoscaling-scalingpolicy-stepadjustment.html#cfn-autoscaling-scalingpolicy-stepadjustment-scalingadjustment"],
}


def launch_template_limit(design: Design, resource: Resource) -> dict:
    ctx = _Context(design, resource)
    base = '/properties/MixedInstancesPolicy/LaunchTemplate'
    paths = ['/properties/LaunchTemplate', base + '/LaunchTemplateSpecification']
    overrides = read(ctx, resource, base + '/Overrides')
    uncertain = 0
    if isinstance(overrides, list):
        paths.extend(base + f'/Overrides/{i}/LaunchTemplateSpecification'
                     for i in range(len(overrides)))
    elif overrides is not ABSENT:
        # Unknown length cannot give a finite upper bound.
        uncertain = 21
    identities: list[set[tuple[str, str]]] = []
    for path in paths:
        spec = read(ctx, resource, path)
        if spec is ABSENT and not any(r.source_resource_id == resource.id and
                                     r.source_path.startswith(path + '/') for r in design.relations):
            continue  # An override without a specification inherits the base template.
        tokens = set()
        for key, kind in (('LaunchTemplateId', 'id'), ('LaunchTemplateName', 'name')):
            target = linked(ctx, resource, path + '/' + key, 'AWS::EC2::LaunchTemplate')
            value = read(ctx, resource, path + '/' + key)
            if target is not None:
                tokens.add(('resource', target.id))
                # Only explicit physical aliases; Resource.name is a design label.
                for alias, alias_kind in (('LaunchTemplateId', 'id'), ('LaunchTemplateName', 'name')):
                    known = read(ctx, target, '/properties/' + alias)
                    if isinstance(known, str):
                        tokens.add((alias_kind, known))
                if isinstance(value, str):
                    tokens.add((kind, value))
            elif isinstance(value, str) and value and not any(
                    r.source_resource_id == resource.id and r.source_path == path + '/' + key
                    for r in design.relations):
                tokens.add((kind, value))
        if not tokens:
            uncertain += 1
            ctx.dependencies.append(resource.id + path)
            continue
        # Merge repeated IDs, names and proven aliases, including transitive aliases.
        again = True
        while again:
            again = False
            for existing in identities[:]:
                if existing & tokens:
                    tokens |= existing
                    identities.remove(existing)
                    again = True
        identities.append(tokens)
    lower = max((sum(any(k == kind for k, _ in tokens) for tokens in identities)
                 for kind in ('id', 'name', 'resource')), default=0)
    upper = len(identities) + uncertain
    if lower > 20:
        verdict, reason = 'FAIL', 'more than 20 distinct launch templates are specified'
    elif upper <= 20:
        verdict, reason = 'PASS', 'at most 20 distinct launch templates are specified'
    else:
        verdict, reason = 'NEEDS_REVIEW', 'unresolved identities may exceed the 20 launch template limit'
        ctx.dependencies.append(resource.id + base)
    if not identities and not uncertain:
        verdict, reason = 'NOT_APPLICABLE', 'no launch templates are specified'
    return ctx.finding('AUTOSCALING_GROUP_LAUNCH_TEMPLATE_LIMIT', base, verdict, reason)


def group_links(design: Design, resource: Resource) -> list[dict]:
    ctx = _Context(design, resource)
    results = []
    az_path = '/properties/AvailabilityZones'
    subnet_path = '/properties/VPCZoneIdentifier'
    azs = read(ctx, resource, az_path)
    subnets = read(ctx, resource, subnet_path)
    known_azs = {v for v in azs if isinstance(v, str)} if isinstance(azs, list) else set()
    az_unknown = azs is not ABSENT and (not isinstance(azs, list) or
                                      any(not isinstance(v, str) for v in azs))
    subnet_azs = set()
    subnet_unknown = subnets is UNKNOWN
    mismatch = False
    if isinstance(subnets, list):
        for i in range(len(subnets)):
            subnet = linked(ctx, resource, subnet_path + f'/{i}', 'AWS::EC2::Subnet')
            zone = read(ctx, subnet, '/properties/AvailabilityZone') if subnet else UNKNOWN
            if isinstance(zone, str):
                subnet_azs.add(zone)
                if isinstance(azs, list) and zone not in known_azs and not az_unknown:
                    mismatch = True
            else:
                subnet_unknown = True
                ctx.dependencies.append(resource.id + subnet_path + f'/{i}')
    elif subnets is not ABSENT:
        subnet_unknown = True
    if subnets is not ABSENT and azs is not ABSENT:
        verdict = 'FAIL' if mismatch else 'NEEDS_REVIEW' if subnet_unknown or az_unknown else 'PASS'
        results.append(ctx.finding('AUTOSCALING_GROUP_SUBNET_AVAILABILITY_ZONES', subnet_path,
                                  verdict, 'subnet Availability Zones must be among the group Availability Zones'))
    placement_path = '/properties/PlacementGroup'
    placement = read(ctx, resource, placement_path)
    if placement is not ABSENT:
        target = linked(ctx, resource, placement_path, 'AWS::EC2::PlacementGroup')
        strategy = read(ctx, target, '/properties/Strategy') if target else UNKNOWN
        if strategy in ('spread', 'partition'):
            verdict = 'NOT_APPLICABLE'
        elif strategy != 'cluster':
            verdict = 'NEEDS_REVIEW'
        elif len(known_azs | subnet_azs) > 1:
            verdict = 'FAIL'
        elif az_unknown or subnet_unknown or not (known_azs | subnet_azs):
            verdict = 'NEEDS_REVIEW'
        else:
            verdict = 'PASS'
        results.append(ctx.finding('AUTOSCALING_GROUP_CLUSTER_PLACEMENT_SINGLE_AZ', placement_path,
                                  verdict, 'cluster placement groups require a single Availability Zone'))
    config_path = '/properties/LaunchConfigurationName'
    if read(ctx, resource, config_path) is not ABSENT:
        config = linked(ctx, resource, config_path, 'AWS::AutoScaling::LaunchConfiguration')
        public = read(ctx, config, '/properties/AssociatePublicIpAddress') if config else UNKNOWN
        tenancy = read(ctx, config, '/properties/PlacementTenancy') if config else UNKNOWN
        required = (isinstance(public, bool) or isinstance(tenancy, str))
        # Both conditions are explicit in the launch configuration documentation.
        if required:
            verdict = ('FAIL' if subnets is ABSENT or subnets == [] else
                       'NEEDS_REVIEW' if not isinstance(subnets, list) else 'PASS')
        elif public is UNKNOWN or tenancy is UNKNOWN:
            verdict = 'NEEDS_REVIEW'
        else:
            verdict = 'NOT_APPLICABLE'
        results.append(ctx.finding('AUTOSCALING_GROUP_LAUNCH_CONFIGURATION_SUBNET', subnet_path,
                                  verdict, 'explicit public IP or tenancy launch configuration requires subnets'))
    return results


def traffic_sources(design: Design, resource: Resource) -> list[dict]:
    ctx = _Context(design, resource)
    path = '/properties/TrafficSources'
    values = read(ctx, resource, path)
    if values is ABSENT:
        return []
    if not isinstance(values, list):
        return [ctx.finding('AUTOSCALING_GROUP_TRAFFIC_SOURCE_KIND', path, 'NEEDS_REVIEW',
                            'traffic sources are unresolved')]
    results = []
    types = {'elb': 'AWS::ElasticLoadBalancing::LoadBalancer',
             'elbv2': 'AWS::ElasticLoadBalancingV2::TargetGroup',
             'vpc-lattice': 'AWS::VpcLattice::TargetGroup'}
    for i in range(len(values)):
        item_path = path + f'/{i}'
        kind = read(ctx, resource, item_path + '/Type')
        identifier = read(ctx, resource, item_path + '/Identifier')
        if not isinstance(kind, str) or kind not in types:
            verdict, reason = 'NEEDS_REVIEW', 'traffic source type is unresolved or unsupported'
        else:
            refs = [r for r in design.relations if r.source_resource_id == resource.id
                    and r.source_path == item_path + '/Identifier']
            if len(refs) == 1:
                target = ctx.by_id.get(refs[0].target_resource_id)
                ctx.evidence.extend(refs[0].evidence_ids)
                if target is None:
                    verdict, reason = 'NEEDS_REVIEW', 'traffic source reference is unresolved'
                else:
                    verdict = 'PASS' if target.type == types[kind] and target.scope == resource.scope else 'FAIL'
                    reason = 'traffic source must match its type, account and Region'
            elif refs or not isinstance(identifier, str):
                verdict, reason = 'NEEDS_REVIEW', 'traffic source identifier is unresolved'
            elif kind == 'elb':
                verdict = 'FAIL' if identifier.startswith('arn:') else 'PASS'
                reason = 'Classic Load Balancer identifiers must be names'
            else:
                match = re.fullmatch(r'arn:([^:]+):([^:]+):([^:]+):(\d{12}):(.+)', identifier)
                service = 'elasticloadbalancing' if kind == 'elbv2' else 'vpc-lattice'
                verdict = ('PASS' if match and match[2] == service and
                           match[3] == resource.scope.region and match[4] == resource.scope.account and
                           match[5].startswith('targetgroup/') else 'FAIL')
                reason = 'target group ARN must match its service, account and Region'
        if verdict == 'NEEDS_REVIEW':
            ctx.dependencies.append(resource.id + item_path)
        results.append(ctx.finding('AUTOSCALING_GROUP_TRAFFIC_SOURCE_KIND', item_path, verdict, reason))
    return results


@resource_check('AWS::AutoScaling::ScalingPolicy')
def step_ranges(design: Design, resource: Resource) -> list[dict]:
    ctx = _Context(design, resource)
    path = '/properties/StepAdjustments'
    steps = read(ctx, resource, path)
    if steps is ABSENT:
        return []
    verdict, reason = 'PASS', 'step intervals are contiguous, nonoverlapping and unbounded where required'
    intervals = []
    uncertain = False
    if not isinstance(steps, list) or not steps:
        uncertain = True
    else:
        for i in range(len(steps)):
            lower = read(ctx, resource, path + f'/{i}/MetricIntervalLowerBound')
            upper = read(ctx, resource, path + f'/{i}/MetricIntervalUpperBound')
            if lower is ABSENT or lower is None:
                lower = Decimal('-Infinity')
            if upper is ABSENT or upper is None:
                upper = Decimal('Infinity')
            if any(v is UNKNOWN or isinstance(v, bool) or not isinstance(v, (int, float, Decimal))
                   for v in (lower, upper)):
                uncertain = True
                continue
            lower, upper = Decimal(str(lower)), Decimal(str(upper))
            if lower.is_nan() or upper.is_nan():
                uncertain = True
                continue
            if lower >= upper or (lower.is_infinite() and upper.is_infinite()):
                verdict, reason = 'FAIL', 'step bounds must increase and cannot both be null'
            intervals.append((lower, upper))
        intervals.sort()
        if sum(lo == Decimal('-Infinity') for lo, _ in intervals) > 1 or sum(
                hi == Decimal('Infinity') for _, hi in intervals) > 1:
            verdict, reason = 'FAIL', 'at most one null lower and one null upper bound are allowed'
        for (_, hi), (lo, _) in zip(intervals, intervals[1:]):
            if hi > lo:
                verdict, reason = 'FAIL', 'step intervals overlap'
            elif hi < lo and not uncertain:
                verdict, reason = 'FAIL', 'step intervals have a gap'
        if not uncertain and intervals and (
                any(lo < 0 for lo, _ in intervals) and intervals[0][0] != Decimal('-Infinity') or
                any(hi > 0 for _, hi in intervals) and intervals[-1][1] != Decimal('Infinity')):
            verdict, reason = 'FAIL', 'negative lower or positive upper bounds require an unbounded step'
    if uncertain and verdict != 'FAIL':
        verdict, reason = 'NEEDS_REVIEW', 'unresolved step intervals may overlap or have gaps'
        ctx.dependencies.append(resource.id + path)
    results = [ctx.finding('AUTOSCALING_POLICY_STEP_INTERVALS', path, verdict, reason)]
    adjustment = read(ctx, resource, '/properties/AdjustmentType')
    if adjustment == 'ExactCapacity' or adjustment is UNKNOWN:
        for i in range(len(steps) if isinstance(steps, list) else 0):
            item_path = path + f'/{i}/ScalingAdjustment'
            value = read(ctx, resource, item_path)
            verdict = ('NEEDS_REVIEW' if adjustment is UNKNOWN or type(value) is not int else
                       'FAIL' if value < 0 else 'PASS')
            if verdict == 'NEEDS_REVIEW':
                ctx.dependencies.append(resource.id + item_path)
            results.append(ctx.finding('AUTOSCALING_POLICY_STEP_EXACT_CAPACITY', item_path, verdict,
                                      'exact capacity step adjustments must be non-negative'))
    return results


@resource_check('AWS::AutoScaling::AutoScalingGroup')
def evaluate_group_pending(design: Design, resource: Resource) -> list[dict]:
    return [launch_template_limit(design, resource), *group_links(design, resource),
            *traffic_sources(design, resource)]


@resource_check('AWS::AutoScaling::ScalingPolicy')
def metric_queries(design: Design, resource: Resource) -> list[dict]:
    """Validate query sets independently; their ordering does not select the final expression."""
    ctx = _Context(design, resource)
    paths = ['/properties/TargetTrackingConfiguration/CustomizedMetricSpecification/Metrics']
    base = '/properties/PredictiveScalingConfiguration/MetricSpecifications'
    specifications = read(ctx, resource, base)
    if isinstance(specifications, list):
        paths.extend(base + f'/{i}/{kind}/MetricDataQueries'
                     for i in range(len(specifications)) for kind in (
                         'CustomizedScalingMetricSpecification', 'CustomizedLoadMetricSpecification',
                         'CustomizedCapacityMetricSpecification'))
    elif specifications is not ABSENT:
        paths.append(base)
    results = []
    for path in paths:
        queries = read(ctx, resource, path)
        if queries is ABSENT:
            continue
        if not isinstance(queries, list) or not queries:
            for rule in ('AUTOSCALING_POLICY_QUERY_IDS', 'AUTOSCALING_POLICY_QUERY_RETURN_DATA'):
                ctx.dependencies.append(resource.id + path)
                results.append(ctx.finding(rule, path, 'NEEDS_REVIEW', 'metric queries are unresolved'))
            continue
        ids = [read(ctx, resource, path + f'/{i}/Id') for i in range(len(queries))]
        known_ids = [v for v in ids if isinstance(v, str)]
        verdict = ('FAIL' if len(known_ids) != len(set(known_ids)) else
                   'NEEDS_REVIEW' if len(known_ids) != len(ids) else 'PASS')
        if verdict == 'NEEDS_REVIEW':
            ctx.dependencies.append(resource.id + path)
        results.append(ctx.finding('AUTOSCALING_POLICY_QUERY_IDS', path, verdict,
                                  'metric query IDs must be unique within each metric specification'))
        expressions = [read(ctx, resource, path + f'/{i}/Expression') for i in range(len(queries))]
        returns = [read(ctx, resource, path + f'/{i}/ReturnData') for i in range(len(queries))]
        has_math = any(isinstance(v, str) for v in expressions)
        if not has_math and any(v is UNKNOWN for v in expressions):
            verdict, reason = 'NEEDS_REVIEW', 'whether the metric specification uses math is unresolved'
        elif not has_math:
            verdict, reason = 'NOT_APPLICABLE', 'no math expression is specified'
        elif sum(v is True for v in returns) > 1 or any(
                v is True and expression is ABSENT for v, expression in zip(returns, expressions)):
            verdict, reason = 'FAIL', 'only the final math expression may return data'
        elif any(type(v) is not bool for v in returns) or any(v is UNKNOWN for v in expressions):
            verdict, reason = 'NEEDS_REVIEW', 'math query expressions or ReturnData flags are unresolved'
        elif sum(v is True for v in returns) != 1:
            verdict, reason = 'FAIL', 'exactly one final math expression must return data'
        else:
            verdict, reason = 'PASS', 'one math expression returns data and all other queries do not'
        if verdict == 'NEEDS_REVIEW':
            ctx.dependencies.append(resource.id + path)
        results.append(ctx.finding('AUTOSCALING_POLICY_QUERY_RETURN_DATA', path, verdict, reason))
    return results
