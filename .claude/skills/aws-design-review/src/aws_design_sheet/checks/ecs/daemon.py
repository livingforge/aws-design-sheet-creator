"""Daemon container references; runtime behavior is deliberately not inferred."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from .task_definition import container_references

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-ecs-daemontaskdefinition-'
SOURCES = {
    'ECS_DAEMON_DEPENDENCY_TARGET': [CF + 'containerdependency.html', CF + 'daemoncontainerdefinition.html'],
    'ECS_DAEMON_MOUNT_VOLUME': [CF + 'mountpoint.html'],
    'ECS_DAEMON_AWSLOGS_OPTIONS': [CF + 'logconfiguration.html'],
}


@resource_check('AWS::ECS::DaemonTaskDefinition')
def daemon_references(design, resource):
    ctx = _Context(design, resource)
    containers = value(ctx, resource, '/properties/ContainerDefinitions')
    volumes = value(ctx, resource, '/properties/Volumes')
    names = set()
    pending = volumes is not ABSENT and not isinstance(volumes, list)
    for i in range(len(volumes) if isinstance(volumes, list) else 0):
        name = value(ctx, resource, f'/properties/Volumes/{i}/Name')
        if isinstance(name, str):
            names.add(name)
        else:
            pending = True
    # The daemon-specific page does not document the omitted Essential default.
    results = container_references(ctx, resource, containers, names, pending,
        'ECS_DAEMON_DEPENDENCY_TARGET', 'ECS_DAEMON_MOUNT_VOLUME', default_essential=False)
    for i in range(len(containers) if isinstance(containers, list) else 0):
        base = f'/properties/ContainerDefinitions/{i}/LogConfiguration'
        driver = value(ctx, resource, base + '/LogDriver')
        if driver is ABSENT or isinstance(driver, str) and driver != 'awslogs':
            continue
        options = [value(ctx, resource, base + '/Options/' + key)
                   for key in ('awslogs-region', 'awslogs-group')]
        secrets = value(ctx, resource, base + '/SecretOptions')
        verdict = 'NEEDS_REVIEW'
        if driver == 'awslogs':
            if all(isinstance(option, str) and option for option in options):
                verdict = 'PASS'
            elif (secrets is ABSENT or secrets == []) and any(option is ABSENT or option == '' for option in options):
                verdict = 'FAIL'
        results.append(ctx.finding('ECS_DAEMON_AWSLOGS_OPTIONS', base + '/Options', verdict,
            'awslogs requires region and group options; SecretOptions substitutions, permissions and log-group existence need separate review'))
    return results
