"""Task-set checks using explicitly linked task definitions and registries."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, UNKNOWN
from ..common.vpc_membership import vpc_membership
from .service_links import container_port, service_registries

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {rule: [CF + 'aws-properties-ecs-taskset-serviceregistry.html'] for rule in (
    'ECS_TASKSET_REGISTRY_CONFIGURATION', 'ECS_TASKSET_REGISTRY_CONTAINER_PORT')}
SOURCES.update({rule: [CF + 'aws-properties-ecs-taskset-loadbalancer.html'] for rule in (
    'ECS_TASKSET_CONTAINER_PORT', 'ECS_TASKSET_AWSVPC_TARGET_TYPE')})
SOURCES['ECS_TASKSET_VPC_MEMBERSHIP'] = [CF + 'aws-properties-ecs-taskset-awsvpcconfiguration.html']
SOURCES['ECS_TASKSET_PLATFORM_CAPACITY'] = [CF + 'aws-resource-ecs-taskset.html', CF + 'aws-properties-ecs-taskset-capacityproviderstrategyitem.html', CF + 'aws-properties-ecs-capacityprovider-autoscalinggroupprovider.html']
SOURCES['ECS_TASKSET_EXTERNAL_CONTROLLER'] = [CF + 'aws-resource-ecs-taskset.html']


@resource_check('AWS::ECS::TaskSet')
def taskset_links(design, resource):
    # Import here because provider VPC helpers share the service/target modules.
    from .provider_links import primary_controller
    ctx = _Context(design, resource)
    task = linked(ctx, resource, '/properties/TaskDefinition', 'AWS::ECS::TaskDefinition')
    mode = value(ctx, task, '/properties/NetworkMode') if task else UNKNOWN
    results = service_registries(ctx, resource, task, mode, 'ECS_TASKSET')
    results.extend(primary_controller(design, resource, 'ECS_TASKSET_EXTERNAL_CONTROLLER'))
    results.extend(platform_capacity(ctx, resource))
    results.extend(vpc_membership(ctx, resource, '/properties/NetworkConfiguration/AwsVpcConfiguration', 'ECS_TASKSET_VPC_MEMBERSHIP'))
    groups = value(ctx, resource, '/properties/LoadBalancers')
    if groups is ABSENT:
        return results
    if not isinstance(groups, list):
        return results + [ctx.finding('ECS_TASKSET_CONTAINER_PORT', '/properties/LoadBalancers', 'NEEDS_REVIEW', 'load balancers are unresolved')]
    for i in range(len(groups)):
        base = f'/properties/LoadBalancers/{i}'
        results.append(container_port(ctx, resource, task, base, 'ECS_TASKSET_CONTAINER_PORT'))
        if mode in ('bridge', 'host', 'none'):
            continue
        group = linked(ctx, resource, base + '/TargetGroupArn', 'AWS::ElasticLoadBalancingV2::TargetGroup')
        kind = value(ctx, group, '/properties/TargetType') if group else UNKNOWN
        verdict = 'NEEDS_REVIEW'
        if mode == 'awsvpc':
            verdict = 'PASS' if kind == 'ip' else 'FAIL' if kind in ('instance', 'lambda', 'alb') else 'NEEDS_REVIEW'
        results.append(ctx.finding('ECS_TASKSET_AWSVPC_TARGET_TYPE', base + '/TargetGroupArn', verdict,
            'awsvpc task sets require target groups with explicit ip target type; unknown defaults and references need review'))
    return results


def platform_capacity(ctx, resource):
    path = '/properties/PlatformVersion'
    if value(ctx, resource, path) is ABSENT or value(ctx, resource, '/properties/LaunchType') is not ABSENT:
        return []
    base = '/properties/CapacityProviderStrategy'
    strategy = value(ctx, resource, base)
    kinds = []
    for i in range(len(strategy) if isinstance(strategy, list) else 0):
        member_path = base + f'/{i}/CapacityProvider'
        name = value(ctx, resource, member_path)
        if name in ('FARGATE', 'FARGATE_SPOT'):
            kinds.append('fargate')
            continue
        provider = linked(ctx, resource, member_path, 'AWS::ECS::CapacityProvider')
        asg = value(ctx, provider, '/properties/AutoScalingGroupProvider') if provider else UNKNOWN
        managed = value(ctx, provider, '/properties/ManagedInstancesProvider') if provider else UNKNOWN
        kinds.append('ec2' if isinstance(asg, dict) and managed is ABSENT else 'unknown')
    verdict = ('PASS' if kinds and all(k == 'fargate' for k in kinds) else
               'FAIL' if kinds and all(k == 'ec2' for k in kinds) else 'NEEDS_REVIEW')
    return [ctx.finding('ECS_TASKSET_PLATFORM_CAPACITY', path, verdict,
        'PlatformVersion applies only to Fargate; this checks built-in providers or explicitly linked ASG-backed providers, not version validity or runtime state')]
