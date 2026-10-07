import pytest
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


@pytest.mark.parametrize('inline',[False,True])
@pytest.mark.parametrize('protocol,endpoint,expected',[
    ('http','http://example.com/path','PASS'), ('https','https://example.com','PASS'),
    ('https','HTTPS://example.com','PASS'), ('http','https://example.com','FAIL'),
    ('https','https://','FAIL'), ('https','https://example.com:bad','FAIL'),
    ('https','https://[invalid','FAIL'), ('https','https://example.com/a b','FAIL'),
    ('sqs','arn:aws:sqs:ap-northeast-1:123456789012:queue.fifo','PASS'),
    ('lambda','arn:aws:lambda:ap-northeast-1:123456789012:function:app:alias','PASS'),
    ('firehose','arn:aws:firehose:ap-northeast-1:123456789012:deliverystream/app','PASS'),
    ('application','arn:aws:sns:ap-northeast-1:123456789012:endpoint/GCM/app/id','PASS'),
    ('lambda','arn:aws:sqs:ap-northeast-1:123456789012:queue','FAIL'),
    ('application','arn:aws:sns:ap-northeast-1:123456789012:topic','FAIL'),
    ('sqs','https://sqs.ap-northeast-1.amazonaws.com/123456789012/queue','FAIL'),
    ('email','user@example.com','NEEDS_REVIEW'), ('sms','+12025550123','NEEDS_REVIEW'),
    ('future','value','NEEDS_REVIEW'), ('https',UNKNOWN,'NEEDS_REVIEW'),
    (UNKNOWN,'https://example.com','NEEDS_REVIEW'),
])
def test_endpoint_representation(inline,protocol,endpoint,expected):
    props={'Protocol':protocol,'Endpoint':endpoint}
    resource=target('main','AWS::SNS::Topic' if inline else 'AWS::SNS::Subscription', **({'Subscription':[props]} if inline else props))
    findings={r['rule_id']:r['verdict'] for r in continuation_checks(linked_design(resource),resource)}
    assert findings['SNS_ENDPOINT_PROTOCOL_FORMAT']==expected


def test_absent_and_unknown_subscriptions():
    for resource in [target('main','AWS::SNS::Subscription',Protocol='https'),target('main','AWS::SNS::Topic')]:
        assert not continuation_checks(linked_design(resource),resource)
    resource=target('main','AWS::SNS::Topic',Subscription=UNKNOWN)
    assert continuation_checks(linked_design(resource),resource)[0]['verdict']=='NEEDS_REVIEW'
