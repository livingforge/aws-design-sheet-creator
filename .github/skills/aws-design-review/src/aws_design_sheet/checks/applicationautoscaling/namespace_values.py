"""Checks for AWS::ApplicationAutoScaling::ScalableTarget, AWS::ApplicationAutoScaling::ScalingPolicy."""
import math
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'APP_AUTOSCALING_TARGET_NAMESPACE': [CF+'aws-resource-applicationautoscaling-scalabletarget.html'],
    'APP_AUTOSCALING_NAMESPACE_VALUES': [CF+'aws-resource-applicationautoscaling-scalabletarget.html'],
    'APP_AUTOSCALING_POLICY_NAMESPACE': [CF+'aws-resource-applicationautoscaling-scalingpolicy.html'],
    'APP_AUTOSCALING_TARGET_VALUE_RANGE': [CF+'aws-properties-applicationautoscaling-scalingpolicy-targettrackingscalingpolicyconfiguration.html'],
}
NAMESPACES = ('ecs','elasticmapreduce','ec2','appstream','dynamodb','rds','sagemaker',
              'custom-resource','comprehend','lambda','cassandra','kafka','elasticache','neptune','workspaces')


@resource_check('AWS::ApplicationAutoScaling::ScalableTarget', 'AWS::ApplicationAutoScaling::ScalingPolicy')
def evaluate_applicationautoscaling_namespace_values(design, resource):
    ctx = _Context(design, resource)
    results = []
    def get(path): return value(ctx, resource, path)
    def emit(rule, path, verdict, reason):
        results.append(ctx.finding(rule, path, verdict, reason))
    def enum(rule, path, choices):
        raw = get(path)
        if raw is not ABSENT:
            emit(rule, path, 'NEEDS_REVIEW' if not literal(raw) else 'PASS' if raw in choices else 'FAIL',
                 'explicit value compared with current documented allowed values; omitted and unresolved values are not inferred')
    def maximum(rule, path, limit):
        raw = get(path)
        if raw is not ABSENT:
            emit(rule, path, 'NEEDS_REVIEW' if not isinstance(raw, list) else 'PASS' if len(raw) <= limit else 'FAIL',
                 'explicit array length compared with documented maximum; member validity is separate')
    def required(rule, path, active):
        raw = get(path)
        verdict = 'NEEDS_REVIEW'
        if active:
            verdict = 'FAIL' if raw is ABSENT else 'PASS' if literal(raw) else 'NEEDS_REVIEW'
        emit(rule, path, verdict, 'checks presence only for an explicitly established triggering condition; credentials and resource existence remain external')

    if resource.type in ('AWS::ApplicationAutoScaling::ScalableTarget','AWS::ApplicationAutoScaling::ScalingPolicy'):
        is_target = resource.type.endswith('::ScalableTarget')
        rule = 'APP_AUTOSCALING_TARGET_NAMESPACE' if is_target else 'APP_AUTOSCALING_POLICY_NAMESPACE'
        ns = get('/properties/ServiceNamespace')
        dimension = get('/properties/ScalableDimension')
        if is_target or ns is not ABSENT or dimension is not ABSENT:
            known = literal(ns) and literal(dimension) and bool(re.fullmatch(r'[a-z-]+:[A-Za-z0-9_-]+:[A-Za-z0-9_-]+',dimension))
            emit(rule,'/properties/ScalableDimension','NEEDS_REVIEW' if not known else 'PASS' if dimension.split(':')[0] == ns else 'FAIL',
                 'checks only namespace prefix consistency; resource ID formats, actual target and dimension availability remain separate')
        if is_target: enum('APP_AUTOSCALING_NAMESPACE_VALUES','/properties/ServiceNamespace',NAMESPACES)
        else:
            path = '/properties/TargetTrackingScalingPolicyConfiguration/TargetValue'
            raw = get(path)
            if raw is not ABSENT:
                numeric = type(raw) is int or type(raw) is float and math.isfinite(raw)
                emit('APP_AUTOSCALING_TARGET_VALUE_RANGE',path,'NEEDS_REVIEW' if not numeric else 'PASS' if -(2**360) <= raw <= 2**360 else 'FAIL',
                     'checks the documented finite numeric range only; suitability for the chosen metric is external')
    return results
