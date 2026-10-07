import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


def check(attrs):
    resource=target('group','AWS::ElasticLoadBalancingV2::TargetGroup',TargetGroupAttributes=attrs)
    return {r['rule_id']:r['verdict'] for r in run_resource_checks(linked_design(resource),resource)}


@pytest.mark.parametrize('algorithm,enabled,expected',[
    ('weighted_random','on','PASS'),('round_robin','on','FAIL'),
    ('least_outstanding_requests','on','FAIL'),('round_robin','off','PASS'),
    (UNKNOWN,'on','NEEDS_REVIEW'),('future','on','NEEDS_REVIEW'),
])
def test_anomaly_algorithm(algorithm,enabled,expected):
    attrs=[{'Key':'load_balancing.algorithm.type','Value':algorithm},{'Key':'load_balancing.algorithm.anomaly_mitigation','Value':enabled}]
    assert check(attrs)['ELBV2_ANOMALY_WEIGHTED_RANDOM']==expected


@pytest.mark.parametrize('flag,expected',[('true','FAIL'),('false','PASS'),(UNKNOWN,'NEEDS_REVIEW'),(None,'NEEDS_REVIEW')])
def test_draining_interval(flag,expected):
    attrs=[{'Key':'target_health_state.unhealthy.draining_interval_seconds','Value':'0'}]
    if flag is not None:
        attrs.append({'Key':'target_health_state.unhealthy.connection_termination.enabled','Value':flag})
    assert check(attrs)['ELBV2_UNHEALTHY_DRAINING_FLAG']==expected


@pytest.mark.parametrize('other,expected',[('rebalance','PASS'),('no_rebalance','FAIL'),(UNKNOWN,'NEEDS_REVIEW'),(None,'NEEDS_REVIEW')])
def test_failover_values(other,expected):
    attrs=[{'Key':'target_failover.on_deregistration','Value':'rebalance'}]
    if other is not None:
        attrs.append({'Key':'target_failover.on_unhealthy','Value':other})
    assert check(attrs)['ELBV2_FAILOVER_ATTRIBUTES_MATCH']==expected


def test_duplicate_unknown_and_missing_attribute_values():
    attrs=[{'Key':'load_balancing.algorithm.type','Value':'round_robin'},
           {'Key':'load_balancing.algorithm.type','Value':'weighted_random'},
           {'Key':'load_balancing.algorithm.anomaly_mitigation','Value':'on'}]
    assert check(attrs)['ELBV2_ANOMALY_WEIGHTED_RANDOM']=='NEEDS_REVIEW'
    assert check([{'Key':UNKNOWN,'Value':'on'}])['ELBV2_ANOMALY_WEIGHTED_RANDOM']=='NEEDS_REVIEW'
    assert check([{'Key':'load_balancing.algorithm.anomaly_mitigation'}])['ELBV2_ANOMALY_WEIGHTED_RANDOM']=='NEEDS_REVIEW'
    assert check(UNKNOWN)['ELBV2_FAILOVER_ATTRIBUTES_MATCH']=='NEEDS_REVIEW'
