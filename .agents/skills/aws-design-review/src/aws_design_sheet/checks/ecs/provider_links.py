"""Declared ECS provider and primary-task-set prerequisites."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, UNKNOWN
from ..common.vpc_membership import vpc_membership

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'ECS_PRIMARY_EXTERNAL_CONTROLLER': [CF + 'aws-resource-ecs-primarytaskset.html'],
    'ECS_PROVIDER_ASG_PROTECTION': [CF + 'aws-properties-ecs-capacityprovider-autoscalinggroupprovider.html'],
    'ECS_PROVIDER_SUBNET_VPC': [CF + 'aws-properties-ecs-capacityprovider-managedinstancesnetworkconfiguration.html'],
}


@resource_check('AWS::ECS::PrimaryTaskSet')
def primary_controller(design, resource, rule='ECS_PRIMARY_EXTERNAL_CONTROLLER'):
    ctx = _Context(design, resource)
    path = '/properties/Service'
    service = linked(ctx, resource, path, 'AWS::ECS::Service')
    controller = value(ctx, service, '/properties/DeploymentController/Type') if service else UNKNOWN
    verdict = ('PASS' if controller == 'EXTERNAL' else
               'FAIL' if controller in ('ECS', 'CODE_DEPLOY') else 'NEEDS_REVIEW')
    return [ctx.finding(rule, path, verdict,
        'task-set management requires an EXTERNAL service controller; only the explicitly linked declaration is checked')]


@resource_check('AWS::ECS::CapacityProvider')
def provider_protection(design, resource):
    ctx = _Context(design, resource)
    results = vpc_membership(ctx, resource,
        '/properties/ManagedInstancesProvider/InstanceLaunchTemplate/NetworkConfiguration',
        'ECS_PROVIDER_SUBNET_VPC', include_security_groups=False)
    base = '/properties/AutoScalingGroupProvider'
    protection = value(ctx, resource, base + '/ManagedTerminationProtection')
    if protection is ABSENT or protection == 'DISABLED':
        return results
    group = linked(ctx, resource, base + '/AutoScalingGroupArn', 'AWS::AutoScaling::AutoScalingGroup')
    declared = value(ctx, group, '/properties/NewInstancesProtectedFromScaleIn') if group else UNKNOWN
    verdict = 'NEEDS_REVIEW'
    if protection == 'ENABLED':
        verdict = 'PASS' if declared is True else 'FAIL' if declared is False else 'NEEDS_REVIEW'
    return results + [ctx.finding('ECS_PROVIDER_ASG_PROTECTION', base + '/ManagedTerminationProtection', verdict,
        'managed termination protection requires group scale-in protection; this checks the explicit group setting only, not protection of existing instances')]
