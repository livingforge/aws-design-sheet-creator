import pytest

from aws_design_sheet.models import Relation
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN

PREFIX = 'AWS::ElasticLoadBalancingV2::'


def fixture(code='200', variant='direct', family=None, lb_family='dualstack'):
    group = target('group', PREFIX + 'TargetGroup', Matcher={'HttpCode': code},
                   **({'IpAddressType': family} if family else {}))
    lb = target('lb', PREFIX + 'LoadBalancer', Type='application', IpAddressType=lb_family)
    listener = target('listener', PREFIX + 'Listener')
    owner = target('owner', PREFIX + ('ListenerRule' if variant == 'rule' else 'Listener'),
                   **{('Actions' if variant == 'rule' else 'DefaultActions'): [
                       {'Type': 'forward', **({'ForwardConfig': {'TargetGroups': [{'TargetGroupArn': 'group'}]}}
                                             if variant == 'weighted' else {'TargetGroupArn': 'group'})}]})
    design = linked_design(group, [lb, listener, owner])
    base = 'Actions' if variant == 'rule' else 'DefaultActions'
    paths = [(owner.id, base + '/0/' + ('ForwardConfig/TargetGroups/0/' if variant == 'weighted' else '') + 'TargetGroupArn', 'group'),
             (owner.id, 'ListenerArn' if variant == 'rule' else 'LoadBalancerArn', 'listener' if variant == 'rule' else 'lb')]
    if variant == 'rule': paths.append(('listener', 'LoadBalancerArn', 'lb'))
    design.relations.extend(Relation(id=str(i), source_resource_id=source, source_path='/properties/' + path,
                                    target_resource_id=dest, evidence_ids=['e1']) for i, (source, path, dest) in enumerate(paths))
    return design, group, lb


def verdict(design, group, rule='ELBV2_ALB_MATCHER_RANGE'):
    return next(f['verdict'] for f in run_resource_checks(design, group) if f['rule_id'] == rule)


@pytest.mark.parametrize('variant', ['direct', 'weighted', 'rule'])
@pytest.mark.parametrize('code,expected', [('200,202-499', 'PASS'), ('500', 'FAIL'), ('199', 'FAIL'),
                                        ('499-200', 'FAIL'), ('200, 202', 'NEEDS_REVIEW'), (UNKNOWN, 'NEEDS_REVIEW')])
def test_alb_matcher(variant, code, expected):
    design, group, _ = fixture(code, variant)
    assert verdict(design, group) == expected


@pytest.mark.parametrize('change', ['conditional_target', 'conditional_lb', 'missing_target', 'network',
                                  'unknown_type', 'scope', 'non_forward', 'conditional_listener'])
def test_no_unproven_alb_inference(change):
    design, group, lb = fixture('500', 'rule')
    if change == 'conditional_target': design.relations[0].condition = 'conditional'
    if change == 'conditional_listener': design.relations[1].condition = 'conditional'
    if change == 'conditional_lb': design.relations[2].condition = 'conditional'
    if change == 'missing_target': design.relations.pop(0)
    if change == 'scope': lb.scope.account = '999999999999'
    if change in ('network', 'unknown_type'):
        lb.fields[0].selected().value = 'network' if change == 'network' else UNKNOWN
    if change == 'non_forward': design.resources[-1].fields[0].selected().value[0]['Type'] = 'redirect'
    assert verdict(design, group) == 'NEEDS_REVIEW'


@pytest.mark.parametrize('lb_family,expected', [('ipv4', 'FAIL'), ('dualstack', 'PASS'),
    ('dualstack-without-public-ipv4', 'PASS'), (UNKNOWN, 'NEEDS_REVIEW'), ('future', 'NEEDS_REVIEW')])
def test_ipv6_target_family(lb_family, expected):
    design, group, _ = fixture(family='ipv6', lb_family=lb_family)
    assert verdict(design, group, 'ELBV2_ALB_IPV6_TARGET') == expected


def test_application_default_and_missing_family():
    design, group, lb = fixture('499', family='ipv6')
    lb.fields.clear()
    assert verdict(design, group) == 'PASS'
    assert verdict(design, group, 'ELBV2_ALB_IPV6_TARGET') == 'NEEDS_REVIEW'


@pytest.mark.parametrize('family,address,expected', [
    ('ipv4', '10.0.0.1', 'PASS'), ('ipv4', '2001:db8::1', 'FAIL'),
    ('ipv6', '2001:db8::1', 'PASS'), ('ipv6', '10.0.0.1', 'FAIL'),
    ('ipv6', 'fe80::1%eth0', 'NEEDS_REVIEW'), ('ipv4', UNKNOWN, 'NEEDS_REVIEW'),
    ('ipv4', 'not-an-address', 'NEEDS_REVIEW'), (None, '10.0.0.1', 'NEEDS_REVIEW'),
])
def test_target_address_family(family, address, expected):
    design, group, _ = fixture(family=family)
    extra = target('extra', PREFIX + 'TargetGroup', TargetType='ip', Targets=[{'Id': address}])
    group.fields.extend(extra.fields)
    assert verdict(design, group, 'ELBV2_TARGET_ADDRESS_FAMILY') == expected
