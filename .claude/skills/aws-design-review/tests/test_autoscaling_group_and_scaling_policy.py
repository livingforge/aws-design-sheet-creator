"""Pending Auto Scaling checks: boundaries, aliases, uncertainty and integration."""
from pathlib import Path

import pytest

from aws_design_sheet.checks.autoscaling.group_and_scaling_policy import evaluate_group_pending, launch_template_limit, step_ranges, metric_queries
from aws_design_sheet.checker import Checker
from aws_design_sheet.models import Relation, ValueState
from test_autoscaling_group_nested_constraints import group, design

ROOT = Path(__file__).resolve().parents[1]
UNKNOWN = {'$state': 'UNRESOLVED'}


def linked_design(main, targets=(), links=()):
    data = design(main)
    data.resources.extend(targets)
    data.relations.extend(Relation(id=str(i), source_resource_id=main.id,
                                   source_path='/properties/' + path,
                                   target_resource_id=target, evidence_ids=['e1'])
                          for i, (path, target) in enumerate(links))
    return data


def target(id, type, **properties):
    resource = group(**properties)
    resource.id = id
    resource.name = id
    resource.type = type
    return resource


def templates(count, key='LaunchTemplateId'):
    return group(MixedInstancesPolicy={'LaunchTemplate': {
        'LaunchTemplateSpecification': {key: 'template-0'},
        'Overrides': [{'LaunchTemplateSpecification': {key: f'template-{i}'}}
                      for i in range(count)]}})


@pytest.mark.parametrize('count,expected', [(0, 'PASS'), (20, 'PASS'), (21, 'FAIL')])
def test_launch_template_count(count, expected):
    resource = templates(count)
    assert launch_template_limit(design(resource), resource)['verdict'] == expected


def test_template_aliases_and_versions():
    resource = templates(20)
    overrides = resource.fields[0].selected().value['LaunchTemplate']['Overrides']
    overrides.append({'LaunchTemplateSpecification': {'LaunchTemplateName': 'friendly', 'Version': '2'}})
    template = target('template', 'AWS::EC2::LaunchTemplate', LaunchTemplateName='friendly')
    root = 'MixedInstancesPolicy/LaunchTemplate/'
    links = [(root + 'Overrides/0/LaunchTemplateSpecification/LaunchTemplateId', 'template'),
             (root + 'Overrides/20/LaunchTemplateSpecification/LaunchTemplateName', 'template')]
    assert launch_template_limit(linked_design(resource, [template], links), resource)['verdict'] == 'PASS'
    # Without a proven alias, a name may describe an existing ID or a new template.
    assert launch_template_limit(design(resource), resource)['verdict'] == 'NEEDS_REVIEW'
    overrides.append({'LaunchTemplateSpecification': {'LaunchTemplateId': 'template-1', 'Version': '99'}})
    assert launch_template_limit(linked_design(resource, [template], links), resource)['verdict'] == 'PASS'


def test_template_unknowns_and_missing_overrides():
    resource = templates(20)
    overrides = resource.fields[0].selected().value['LaunchTemplate']['Overrides']
    overrides.extend([{}, {'InstanceType': 'm6i.large'}])
    assert launch_template_limit(design(resource), resource)['verdict'] == 'PASS'
    overrides.append({'LaunchTemplateSpecification': UNKNOWN})
    assert launch_template_limit(design(resource), resource)['verdict'] == 'NEEDS_REVIEW'
    overrides.append({'LaunchTemplateSpecification': {'LaunchTemplateId': 'new'}})
    assert launch_template_limit(design(resource), resource)['verdict'] == 'FAIL'
    assert launch_template_limit(design(group()), group())['verdict'] == 'NOT_APPLICABLE'
    resource = group(MixedInstancesPolicy=UNKNOWN)
    assert launch_template_limit(design(resource), resource)['verdict'] == 'NEEDS_REVIEW'


def test_template_child_fields_and_reference_only():
    resource = group(**{'MixedInstancesPolicy/LaunchTemplate/LaunchTemplateSpecification/LaunchTemplateId': 'lt-1'})
    assert launch_template_limit(design(resource), resource)['verdict'] == 'PASS'
    resource = group(LaunchTemplate={})
    template = target('template', 'AWS::EC2::LaunchTemplate')
    data = linked_design(resource, [template], [('LaunchTemplate/LaunchTemplateId', 'template')])
    assert launch_template_limit(data, resource)['verdict'] == 'PASS'


def findings(data, resource):
    return {r['rule_id']: r for r in evaluate_group_pending(data, resource)}


@pytest.mark.parametrize('zone,expected', [('ap-northeast-1a', 'PASS'), ('ap-northeast-1c', 'FAIL'),
                                          (UNKNOWN, 'NEEDS_REVIEW')])
def test_subnet_zone(zone, expected):
    resource = group(AvailabilityZones=['ap-northeast-1a'], VPCZoneIdentifier=['subnet'])
    subnet = target('subnet', 'AWS::EC2::Subnet', AvailabilityZone=zone)
    data = linked_design(resource, [subnet], [('VPCZoneIdentifier/0', 'subnet')])
    row = findings(data, resource)['AUTOSCALING_GROUP_SUBNET_AVAILABILITY_ZONES']
    assert row['verdict'] == expected
    assert row['evidence_ids'] == ['e1']
    if expected == 'NEEDS_REVIEW':
        assert row['dependencies']


def test_subnet_unknown_zone_list_and_scope():
    resource = group(AvailabilityZones=['ap-northeast-1a', UNKNOWN], VPCZoneIdentifier=['subnet'])
    subnet = target('subnet', 'AWS::EC2::Subnet', AvailabilityZone='ap-northeast-1c')
    data = linked_design(resource, [subnet], [('VPCZoneIdentifier/0', 'subnet')])
    assert findings(data, resource)['AUTOSCALING_GROUP_SUBNET_AVAILABILITY_ZONES']['verdict'] == 'NEEDS_REVIEW'
    resource.fields[0].selected().value = ['ap-northeast-1c']
    subnet.scope = subnet.scope.model_copy(update={'region': 'us-east-1'})
    assert findings(data, resource)['AUTOSCALING_GROUP_SUBNET_AVAILABILITY_ZONES']['verdict'] == 'NEEDS_REVIEW'


@pytest.mark.parametrize('strategy,zones,expected', [
    ('cluster', ['ap-northeast-1a'], 'PASS'),
    ('cluster', ['ap-northeast-1a', 'ap-northeast-1c'], 'FAIL'),
    ('cluster', ['ap-northeast-1a', UNKNOWN], 'NEEDS_REVIEW'),
    ('spread', ['ap-northeast-1a', 'ap-northeast-1c'], 'NOT_APPLICABLE'),
])
def test_cluster_placement(strategy, zones, expected):
    resource = group(PlacementGroup='placement', AvailabilityZones=zones)
    placement = target('placement', 'AWS::EC2::PlacementGroup', Strategy=strategy)
    data = linked_design(resource, [placement], [('PlacementGroup', 'placement')])
    assert findings(data, resource)['AUTOSCALING_GROUP_CLUSTER_PLACEMENT_SINGLE_AZ']['verdict'] == expected


@pytest.mark.parametrize('properties', [{'AssociatePublicIpAddress': True},
                                       {'AssociatePublicIpAddress': False},
                                       {'PlacementTenancy': 'dedicated'}, {'PlacementTenancy': 'default'}])
def test_launch_configuration_requires_subnets(properties):
    resource = group(LaunchConfigurationName='config')
    config = target('config', 'AWS::AutoScaling::LaunchConfiguration', **properties)
    data = linked_design(resource, [config], [('LaunchConfigurationName', 'config')])
    key = 'AUTOSCALING_GROUP_LAUNCH_CONFIGURATION_SUBNET'
    assert findings(data, resource)[key]['verdict'] == 'FAIL'
    resource.fields.extend(group(VPCZoneIdentifier=['subnet']).fields)
    assert findings(data, resource)[key]['verdict'] == 'PASS'


@pytest.mark.parametrize('kind,identifier,expected', [
    ('elb', 'classic', 'PASS'), ('elb', 'arn:aws:elasticloadbalancing:ap-northeast-1:111111111111:targetgroup/t/1', 'FAIL'),
    ('elbv2', 'arn:aws:elasticloadbalancing:ap-northeast-1:111111111111:targetgroup/t/1', 'PASS'),
    ('vpc-lattice', 'arn:aws:vpc-lattice:ap-northeast-1:111111111111:targetgroup/tg-1', 'PASS'),
    ('elbv2', 'arn:aws:elasticloadbalancing:us-east-1:111111111111:targetgroup/t/1', 'FAIL'),
    ('elbv2', 'arn:aws:elasticloadbalancing:ap-northeast-1:222222222222:targetgroup/t/1', 'FAIL'),
    ('vpc-lattice', 'arn:aws:elasticloadbalancing:ap-northeast-1:111111111111:targetgroup/t/1', 'FAIL'),
    ('elbv2', UNKNOWN, 'NEEDS_REVIEW'),
])
def test_traffic_source_literals(kind, identifier, expected):
    resource = group(TrafficSources=[{'Type': kind, 'Identifier': identifier}])
    assert findings(design(resource), resource)['AUTOSCALING_GROUP_TRAFFIC_SOURCE_KIND']['verdict'] == expected


def test_traffic_source_relation_and_unknown_parent():
    resource = group(TrafficSources=[{'Type': 'elbv2', 'Identifier': 'target'}])
    tg = target('target', 'AWS::ElasticLoadBalancingV2::TargetGroup')
    data = linked_design(resource, [tg], [('TrafficSources/0/Identifier', 'target')])
    assert findings(data, resource)['AUTOSCALING_GROUP_TRAFFIC_SOURCE_KIND']['verdict'] == 'PASS'
    tg.type = 'AWS::VpcLattice::TargetGroup'
    assert findings(data, resource)['AUTOSCALING_GROUP_TRAFFIC_SOURCE_KIND']['verdict'] == 'FAIL'
    resource.fields[0].state = ValueState.UNRESOLVED
    resource.fields[0].selected_candidate_id = None
    assert findings(data, resource)['AUTOSCALING_GROUP_TRAFFIC_SOURCE_KIND']['verdict'] == 'NEEDS_REVIEW'


def step(lower=None, upper=None):
    value = {'ScalingAdjustment': 1}
    if lower is not None:
        value['MetricIntervalLowerBound'] = lower
    if upper is not None:
        value['MetricIntervalUpperBound'] = upper
    return value


@pytest.mark.parametrize('steps,expected', [
    ([step(0, 10), step(10)], 'PASS'), ([step(-10, 0), step(None, -10)], 'PASS'),
    ([step(10), step(0, 10)], 'PASS'),
    ([step(0, 10), step(5)], 'FAIL'), ([step(0, 10), step(11)], 'FAIL'),
    ([step(0, 10)], 'FAIL'), ([step(-10, 0)], 'FAIL'),
    ([step()], 'FAIL'), ([step(10, 0)], 'FAIL'),
    ([step(0, 10), {'MetricIntervalLowerBound': UNKNOWN, 'ScalingAdjustment': 1}], 'NEEDS_REVIEW'),
    ([step(0, 10), step(11), UNKNOWN], 'NEEDS_REVIEW'),
    ([step(0, 10), step(5), UNKNOWN], 'FAIL'),
])
def test_step_intervals(steps, expected):
    resource = target('policy', 'AWS::AutoScaling::ScalingPolicy', StepAdjustments=steps)
    assert step_ranges(design(resource), resource)[0]['verdict'] == expected


def test_exact_capacity_and_checker_connection():
    resource = target('policy', 'AWS::AutoScaling::ScalingPolicy', PolicyType='StepScaling',
                      AdjustmentType='ExactCapacity', AutoScalingGroupName='group',
                      StepAdjustments=[{**step(0), 'ScalingAdjustment': -1}])
    data = design(resource)
    rows = step_ranges(data, resource)
    assert rows[1]['verdict'] == 'FAIL'
    checked = Checker(ROOT / 'schemas', ROOT / 'profiles/vpc-subnet.json').check(data)
    row = next(r for r in checked['results'] if r['rule_id'] == 'AUTOSCALING_POLICY_STEP_EXACT_CAPACITY')
    assert row['verdict'] == 'FAIL' and row['source_urls'] and row['evidence_ids']
    resource = templates(21)
    checked = Checker(ROOT / 'schemas', ROOT / 'profiles/vpc-subnet.json').check(design(resource))
    assert any(r['rule_id'] == 'AUTOSCALING_GROUP_LAUNCH_TEMPLATE_LIMIT' and r['verdict'] == 'FAIL'
               for r in checked['results'])


@pytest.mark.parametrize('queries,ids_verdict,return_verdict', [
    ([{'Id': 'result', 'Expression': 'm1', 'ReturnData': True},
      {'Id': 'm1', 'MetricStat': {}, 'ReturnData': False}], 'PASS', 'PASS'),
    ([{'Id': 'm1', 'MetricStat': {}}, {'Id': 'm1', 'MetricStat': {}}], 'FAIL', 'NOT_APPLICABLE'),
    ([{'Id': UNKNOWN, 'Expression': 'm1', 'ReturnData': True},
      {'Id': 'm1', 'MetricStat': {}, 'ReturnData': False}], 'NEEDS_REVIEW', 'PASS'),
    ([{'Id': 'e1', 'Expression': 'm1', 'ReturnData': True},
      {'Id': 'm1', 'MetricStat': {}, 'ReturnData': True}], 'PASS', 'FAIL'),
    ([{'Id': 'e1', 'Expression': 'm1', 'ReturnData': False},
      {'Id': 'm1', 'MetricStat': {}, 'ReturnData': False}], 'PASS', 'FAIL'),
    ([{'Id': 'e1', 'Expression': 'm1', 'ReturnData': True},
      {'Id': 'm1', 'MetricStat': {}}], 'PASS', 'NEEDS_REVIEW'),
])
@pytest.mark.parametrize('predictive', [True, False])
def test_metric_queries(queries, ids_verdict, return_verdict, predictive):
    props = ({'PredictiveScalingConfiguration': {'MetricSpecifications': [
        {'CustomizedScalingMetricSpecification': {'MetricDataQueries': queries}}]}} if predictive else
        {'TargetTrackingConfiguration': {'CustomizedMetricSpecification': {'Metrics': queries}}})
    resource = target('policy', 'AWS::AutoScaling::ScalingPolicy', **props)
    rows = metric_queries(design(resource), resource)
    assert [row['verdict'] for row in rows] == [ids_verdict, return_verdict]
