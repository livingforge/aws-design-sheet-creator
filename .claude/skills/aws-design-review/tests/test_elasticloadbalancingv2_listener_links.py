import pytest
from aws_design_sheet.models import Relation
from aws_design_sheet.checks.elasticloadbalancingv2.listener_links import evaluate_listener_links
from aws_design_sheet.checks.registry import combine
from aws_design_sheet.checks.apigateway.rest_mapping_sources import rest_mapping_sources
from aws_design_sheet.checks.cloudwatch.alarm_rule import alarm_rule
from aws_design_sheet.checks.secretsmanager.tags import secret_tags
from aws_design_sheet.checks.route53.healthcheck_addresses import healthcheck_address
from aws_design_sheet.checks.logs.links import integration_singleton, transformed_input_declaration, transformer_class
from aws_design_sheet.checks.autoscaling.scaling_labels import scaling_labels
from aws_design_sheet.checks.autoscaling.metric_math import math_references
from aws_design_sheet.checks.apigateway.mapping_order import private_mapping_order
from aws_design_sheet.checks.multi_service.domain_certificates import domain_certificates
from aws_design_sheet.checks.autoscaling.scheduled_timezone import scheduled_timezone
from aws_design_sheet.checks.cloudwatch.anomaly_timezone import anomaly_timezone
from aws_design_sheet.checks.logs.subscription_count import subscription_count
from aws_design_sheet.checks.logs.scheduled_query import scheduled_query
from aws_design_sheet.checks.elasticloadbalancingv2.listener_links import listener_forward_protocol
from aws_design_sheet.checks.apigatewayv2.targets import integration_targets, managed_payload_target
from aws_design_sheet.checks.elasticloadbalancingv2.attributes_and_rules import lb_attributes, target_group_checks, listener_local
from aws_design_sheet.checks.cloudfront.tenant_forwarding import tenant_forwarding
from aws_design_sheet.checks.ssm.parameters_and_windows import ssm_local, ssm_target_keys, ssm_window_tags, ssm_automation_rate_target
from aws_design_sheet.checks.cloudwatch.alarm_source import alarm_source
from aws_design_sheet.checks.dynamodb.keys_and_regions import dynamodb_keys
from aws_design_sheet.checks.events.partner_bus_name import event_bus
from aws_design_sheet.checks.cloudfront.policies_keys_and_tenants import tenant_parameters, public_key_material, staging_distributions
from aws_design_sheet.checks.ssm.parameter_policies import parameter_policies
from aws_design_sheet.checks.ssm.patch_filters import patch_filters
from aws_design_sheet.checks.ssm.schedule import window_task_target, window_schedule, association_schedule
from aws_design_sheet.checks.ecs.task_definition import evaluate_ecs_local
from aws_design_sheet.checks.ecs.daemon import daemon_references
from aws_design_sheet.checks.ecs.service_links import service_links
from aws_design_sheet.checks.ecs.taskset_links import taskset_links
from aws_design_sheet.checks.ecs.cluster_links import cluster_links
from aws_design_sheet.checks.ecs.cluster_capacity import capacity_declarations
from aws_design_sheet.checks.ecs.provider_links import primary_controller, provider_protection
from aws_design_sheet.checks.eks.links import eks_links
from aws_design_sheet.checks.eks.capability_role import capability_role
from aws_design_sheet.checks.eks.private_subnets import fargate_private_subnets
from aws_design_sheet.checks.sns.endpoints import sns_endpoints
from aws_design_sheet.checks.events.rule import event_targets
from aws_design_sheet.checks.elasticloadbalancing.policy_names import classic_policy_names
from aws_design_sheet.checks.cloudwatch.dashboard_and_metric_stream import dashboard, stream_strings
from aws_design_sheet.checks.cloudwatch.insight_rule import insight_rule
from aws_design_sheet.checks.logs.policy import logs_account_policy
from aws_design_sheet.checks.kms.key_policy_and_replica import kms_local
from aws_design_sheet.checks.route53.alias import route53_alias
from aws_design_sheet.checks.secretsmanager.rotation_schedule import rotation_schedule
from aws_design_sheet.checks.multi_service.named_resource_collisions import finite_ledger_checks
from aws_design_sheet.checks.route53.query_log_scope import route53_query_log_scope
from aws_design_sheet.checks.ecr.cache_role_scope import ecr_cache_role_scope
from aws_design_sheet.checks.cloudwatch.suppressor_declaration import metric_stream_scope, composite_alarm_suppressor
from aws_design_sheet.checks.kms.alias_target_scope import kms_alias_target_scope
from aws_design_sheet.checks.eks.cluster_scope import eks_cluster_scope
from aws_design_sheet.checks.sns.encryption_key_type import sns_encryption_key_type
continuation_checks = combine(rest_mapping_sources, alarm_rule, secret_tags, healthcheck_address, integration_singleton, transformed_input_declaration, transformer_class, scaling_labels, math_references, private_mapping_order, domain_certificates, scheduled_timezone, anomaly_timezone, subscription_count, scheduled_query, listener_forward_protocol, integration_targets, managed_payload_target, lb_attributes, tenant_forwarding, ssm_local, ssm_target_keys, ssm_window_tags, ssm_automation_rate_target, alarm_source, dynamodb_keys, target_group_checks, event_bus, listener_local, tenant_parameters, public_key_material, staging_distributions, parameter_policies, patch_filters, window_task_target, window_schedule, association_schedule, evaluate_ecs_local, daemon_references, service_links, taskset_links, cluster_links, capacity_declarations, primary_controller, provider_protection, eks_links, capability_role, fargate_private_subnets, sns_endpoints, event_targets, classic_policy_names, dashboard, stream_strings, insight_rule, logs_account_policy, kms_local, route53_alias, rotation_schedule, finite_ledger_checks, route53_query_log_scope, ecr_cache_role_scope, metric_stream_scope, kms_alias_target_scope, eks_cluster_scope, composite_alarm_suppressor, sns_encryption_key_type)
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN

RULE = 'AWS::ElasticLoadBalancingV2::ListenerRule'
LISTENER = 'AWS::ElasticLoadBalancingV2::Listener'
ARN = 'arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/my-alb/123/456'


@pytest.mark.parametrize('protocol,target_protocol,expected',[
    ('TCP','TCP','PASS'),('TCP','TCP_UDP','PASS'),('TCP','TCP_QUIC','PASS'),
    ('TLS','TLS','PASS'),('TLS','TCP','PASS'),('TLS','UDP','FAIL'),
    ('UDP','TCP_UDP','PASS'),('UDP','TCP','FAIL'),
    ('TCP_UDP','TCP_UDP','PASS'),('TCP_UDP','UDP','FAIL'),
    ('TCP_QUIC','TCP_QUIC','PASS'),('TCP_QUIC','QUIC','FAIL'),
    ('QUIC','TCP_QUIC','PASS'),('QUIC','QUIC','PASS'),
    ('TCP','HTTP','FAIL'),('TCP','FUTURE','NEEDS_REVIEW'),('TCP',UNKNOWN,'NEEDS_REVIEW'),
])
@pytest.mark.parametrize('weighted',[False,True])
def test_network_listener_target_protocol(protocol,target_protocol,expected,weighted):
    action={'Type':'forward'}
    field='DefaultActions/0/'
    if weighted:
        action['ForwardConfig']={'TargetGroups':[{'TargetGroupArn':{'Ref':'group'}}]}
        field+='ForwardConfig/TargetGroups/0/TargetGroupArn'
    else:
        action['TargetGroupArn']={'Ref':'group'}
        field+='TargetGroupArn'
    main=target('listener',LISTENER,Protocol=protocol,DefaultActions=[action])
    group=target('group','AWS::ElasticLoadBalancingV2::TargetGroup',Protocol=target_protocol)
    data=linked_design(main,[group],[(field,'group')])
    rows=continuation_checks(data,main)
    assert next(r['verdict'] for r in rows if r['rule_id']=='ELBV2_NLB_FORWARD_PROTOCOL')==expected
    data.relations[0].condition='optional'
    assert continuation_checks(data,main)[0]['verdict']=='NEEDS_REVIEW'


def test_external_target_protocol_is_not_inferred_from_arn():
    main=target('listener',LISTENER,Protocol='TCP_UDP',DefaultActions=[{'Type':'forward','TargetGroupArn':'arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tcp/123'}])
    assert continuation_checks(linked_design(main),main)[0]['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('port,conditional,region,override,expected',[
    (80,False,'ap-northeast-1',80,'PASS'),
    (443,False,'ap-northeast-1',80,'NEEDS_REVIEW'),
    (80,True,'ap-northeast-1',80,'NEEDS_REVIEW'),
    (80,False,'us-west-2',80,'NEEDS_REVIEW'),
    (UNKNOWN,False,'ap-northeast-1',80,'NEEDS_REVIEW'),
    (80,False,'ap-northeast-1',443,'NEEDS_REVIEW'),
])
def test_alb_target_listener_port(port,conditional,region,override,expected):
    main=target('group','AWS::ElasticLoadBalancingV2::TargetGroup',TargetType='alb',Port=80,Targets=[{'Id':{'Ref':'lb'},'Port':override}])
    lb=target('lb','AWS::ElasticLoadBalancingV2::LoadBalancer')
    listener=target('listener',LISTENER,LoadBalancerArn={'Ref':'lb'},Port=port)
    listener.scope.region=region
    data=linked_design(main,[lb,listener],[('Targets/0/Id','lb')])
    data.relations.append(Relation(id='listener-lb',source_resource_id='listener',source_path='/properties/LoadBalancerArn',target_resource_id='lb',evidence_ids=['e1'],condition='optional' if conditional else None))
    assert continuation_checks(data,main)[0]['verdict']==expected


def verdicts(data, resource):
    return {r['rule_id']: r['verdict'] for r in evaluate_listener_links(data, resource)}


@pytest.mark.parametrize('other_arn,priority,expected', [
    (ARN, 10, 'FAIL'), (ARN, 11, 'NEEDS_REVIEW'),
    (ARN + 'a', 10, 'NEEDS_REVIEW'), (UNKNOWN, 10, 'NEEDS_REVIEW'),
    (ARN, UNKNOWN, 'NEEDS_REVIEW'),
])
def test_literal_priority_collisions(other_arn, priority, expected):
    main = target('one', RULE, ListenerArn=ARN, Priority=10)
    other = target('two', RULE, ListenerArn=other_arn, Priority=priority)
    assert verdicts(linked_design(main, [other]), main)['ELBV2_RULE_PRIORITY_DUPLICATE'] == expected


@pytest.mark.parametrize('kind,expected', [('app', 'PASS'), ('net', 'FAIL'), ('gwy', 'FAIL')])
def test_literal_listener_kind(kind, expected):
    main = target('one', RULE, ListenerArn=ARN.replace('/app/', '/' + kind + '/'), Priority=10)
    assert verdicts(linked_design(main), main)['ELBV2_RULE_APPLICATION_LISTENER'] == expected


def test_linked_listener_collision_and_default_lb_type():
    main = target('one', RULE, ListenerArn={'Ref': 'listener'}, Priority=10)
    other = target('two', RULE, ListenerArn={'Ref': 'listener'}, Priority=10)
    listener = target('listener', LISTENER, LoadBalancerArn={'Ref': 'lb'})
    lb = target('lb', 'AWS::ElasticLoadBalancingV2::LoadBalancer')
    data = linked_design(main, [other, listener, lb], [('ListenerArn', 'listener')])
    data.relations.extend([
        Relation(id='other', source_resource_id='two', source_path='/properties/ListenerArn', target_resource_id='listener', evidence_ids=['e1']),
        Relation(id='lb', source_resource_id='listener', source_path='/properties/LoadBalancerArn', target_resource_id='lb', evidence_ids=['e1']),
    ])
    result = verdicts(data, main)
    assert result['ELBV2_RULE_PRIORITY_DUPLICATE'] == 'FAIL'
    assert result['ELBV2_RULE_APPLICATION_LISTENER'] == 'PASS'
    listener.scope.region = 'us-west-2'
    result = verdicts(data, main)
    assert result['ELBV2_RULE_PRIORITY_DUPLICATE'] == 'NEEDS_REVIEW'
    assert result['ELBV2_RULE_APPLICATION_LISTENER'] == 'NEEDS_REVIEW'


def test_unresolved_listener_is_not_assumed_application():
    main = target('one', RULE, ListenerArn=UNKNOWN, Priority=10)
    assert set(verdicts(linked_design(main), main).values()) == {'NEEDS_REVIEW'}
