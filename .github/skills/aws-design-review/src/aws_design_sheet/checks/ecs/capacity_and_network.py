"""Checks for AWS::ECS::Service, AWS::ECS::TaskSet."""
from __future__ import annotations

from ..registry import resource_check
from ..common.design_uniqueness import _Context
from ..common.field_reads import ABSENT, UNKNOWN, linked, read


SOURCES = {
    "ECS_CAPACITY_PROVIDER_BASE": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-ecs-service-capacityproviderstrategyitem.html"],
    "ECS_CAPACITY_PROVIDER_WEIGHT": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-ecs-service-capacityproviderstrategyitem.html"],
    "ECS_SERVICE_NETWORK_MODE": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ecs-service.html#cfn-ecs-service-networkconfiguration"],
}


@resource_check('AWS::ECS::Service', 'AWS::ECS::TaskSet')
def ecs_capacity(design, resource):
    ctx = _Context(design, resource)
    path = '/properties/CapacityProviderStrategy'
    items = read(ctx, resource, path)
    if items is ABSENT:
        return []
    if not isinstance(items, list):
        return [ctx.finding('ECS_CAPACITY_PROVIDER_BASE', path, 'NEEDS_REVIEW', 'strategy is unresolved'),
                ctx.finding('ECS_CAPACITY_PROVIDER_WEIGHT', path, 'NEEDS_REVIEW', 'strategy is unresolved')]
    bases = [read(ctx, resource, path + f'/{i}/Base') for i in range(len(items))]
    weights = [read(ctx, resource, path + f'/{i}/Weight') for i in range(len(items))]
    base_count = sum(type(v) is int for v in bases)
    unknown = any(v is UNKNOWN or (v is not ABSENT and type(v) is not int) for v in bases)
    base_verdict = 'FAIL' if base_count > 1 else 'NEEDS_REVIEW' if unknown else 'PASS'
    if len(items) < 2:
        weight_verdict = 'NOT_APPLICABLE'
    elif any(type(v) is int and v > 0 for v in weights):
        weight_verdict = 'PASS'
    elif any(v is UNKNOWN or (v is not ABSENT and type(v) is not int) for v in weights):
        weight_verdict = 'NEEDS_REVIEW'
    else:
        weight_verdict = 'FAIL'
    return [ctx.finding('ECS_CAPACITY_PROVIDER_BASE', path, base_verdict,
                        'only one capacity provider may define Base'),
            ctx.finding('ECS_CAPACITY_PROVIDER_WEIGHT', path, weight_verdict,
                        'multiple capacity providers require at least one positive weight')]


@resource_check('AWS::ECS::Service')
def ecs_network(design, resource):
    ctx = _Context(design, resource)
    path = '/properties/NetworkConfiguration'
    task = linked(ctx, resource, '/properties/TaskDefinition', 'AWS::ECS::TaskDefinition')
    mode = read(ctx, task, '/properties/NetworkMode') if task else UNKNOWN
    config = read(ctx, resource, path)
    if mode == 'awsvpc':
        verdict = 'FAIL' if config is ABSENT else 'NEEDS_REVIEW' if config is UNKNOWN else 'PASS'
    elif mode in ('bridge', 'host', 'none'):
        verdict = 'PASS' if config is ABSENT else 'NEEDS_REVIEW' if config is UNKNOWN else 'FAIL'
    else:
        verdict = 'NEEDS_REVIEW'
    return ctx.finding('ECS_SERVICE_NETWORK_MODE', path, verdict,
                       'network configuration is required only for awsvpc task definitions')
