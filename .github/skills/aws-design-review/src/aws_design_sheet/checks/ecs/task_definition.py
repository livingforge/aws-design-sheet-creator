"""ECS task-internal constraints, independent of live cluster capabilities."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from .references import evaluate_task_references
from .size import evaluate_task_size

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-ecs-taskdefinition-'
SOURCES = {
    'ECS_TASK_ESSENTIAL_CONTAINER': [CF + 'containerdefinition.html'],
    'ECS_TASK_LAUNCH_VOLUME_COUNT': [CF + 'volume.html'],
    'ECS_TASK_DEPENDENCY_TARGET': [CF + 'containerdependency.html'],
    'ECS_TASK_MOUNT_VOLUME': [CF + 'volume.html'],
    'ECS_TASK_PORT_RANGES': ['https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_PortMapping.html'],
}


@resource_check('AWS::ECS::TaskDefinition')
def evaluate_ecs_local(design, resource):
    if resource.type != 'AWS::ECS::TaskDefinition':
        return []
    ctx = _Context(design, resource)
    root = '/properties/ContainerDefinitions'
    containers = value(ctx, resource, root)
    results = evaluate_task_references(ctx, resource, containers) + evaluate_task_size(design, resource)
    volumes = value(ctx, resource, '/properties/Volumes')
    volume_names, unknown_volumes = set(), volumes is not ABSENT and not isinstance(volumes, list)
    if isinstance(volumes, list):
        flags = []
        for i in range(len(volumes)):
            path = f'/properties/Volumes/{i}'
            flags.append(value(ctx, resource, path + '/ConfiguredAtLaunch'))
            name = value(ctx, resource, path + '/Name')
            if isinstance(name, str):
                volume_names.add(name)
            else:
                unknown_volumes = True
        count = sum(f is True for f in flags)
        pending = any(f is not ABSENT and type(f) is not bool for f in flags)
        results.append(ctx.finding('ECS_TASK_LAUNCH_VOLUME_COUNT', '/properties/Volumes',
            'FAIL' if count > 1 else 'NEEDS_REVIEW' if pending else 'PASS',
            'at most one volume may be configured at launch'))
    elif volumes is not ABSENT:
        results.append(ctx.finding('ECS_TASK_LAUNCH_VOLUME_COUNT', '/properties/Volumes', 'NEEDS_REVIEW',
            'volume configuration is unresolved'))
    if not isinstance(containers, list):
        results.append(ctx.finding('ECS_TASK_ESSENTIAL_CONTAINER', root, 'NEEDS_REVIEW', 'containers are unresolved'))
        return results
    flags = [value(ctx, resource, root + f'/{i}/Essential') for i in range(len(containers))]
    verdict = ('PASS' if any(f is True or f is ABSENT for f in flags) else
               'NEEDS_REVIEW' if any(type(f) is not bool for f in flags) else 'FAIL')
    results.append(ctx.finding('ECS_TASK_ESSENTIAL_CONTAINER', root, verdict,
        'at least one essential container is required; omitted Essential defaults to true'))
    for i in range(len(containers)):
        results.extend(port_ranges(ctx, resource, root + f'/{i}'))
    return results + container_references(ctx, resource, containers, volume_names, unknown_volumes,
        'ECS_TASK_DEPENDENCY_TARGET', 'ECS_TASK_MOUNT_VOLUME', default_essential=True)


def container_references(ctx, resource, containers, volume_names, unknown_volumes,
                         dependency_rule, mount_rule, *, default_essential):
    root = '/properties/ContainerDefinitions'
    results = []
    if not isinstance(containers, list):
        return [ctx.finding(rule, root, 'NEEDS_REVIEW', 'containers are unresolved')
                for rule in (dependency_rule, mount_rule)]
    names, unknown_names = {}, False
    for i in range(len(containers)):
        name = value(ctx, resource, root + f'/{i}/Name')
        if isinstance(name, str):
            names.setdefault(name, []).append(i)
        else:
            unknown_names = True
    for i in range(len(containers)):
        base = root + f'/{i}'
        mounts = value(ctx, resource, base + '/MountPoints')
        if mounts is not ABSENT:
            for j in range(len(mounts) if isinstance(mounts, list) else 1):
                path = base + f'/MountPoints/{j}/SourceVolume'
                name = value(ctx, resource, path)
                verdict = ('PASS' if isinstance(name, str) and name in volume_names else
                           'NEEDS_REVIEW' if unknown_volumes or not isinstance(name, str) else 'FAIL')
                results.append(ctx.finding(mount_rule, path, verdict,
                    'mount SourceVolume must name a volume in this task definition'))
        dependencies = value(ctx, resource, base + '/DependsOn')
        if dependencies is ABSENT:
            continue
        if not isinstance(dependencies, list):
            results.append(ctx.finding(dependency_rule, base + '/DependsOn', 'NEEDS_REVIEW',
                'container dependencies are unresolved'))
            continue
        for j in range(len(dependencies)):
            path = base + f'/DependsOn/{j}'
            name = value(ctx, resource, path + '/ContainerName')
            condition = value(ctx, resource, path + '/Condition')
            matches = names.get(name, []) if isinstance(name, str) else []
            verdict = 'NEEDS_REVIEW'
            if not matches and isinstance(name, str) and not unknown_names:
                verdict = 'FAIL'
            elif len(matches) == 1 and not unknown_names:
                target = root + f'/{matches[0]}'
                if condition in ('COMPLETE', 'SUCCESS'):
                    essential = value(ctx, resource, target + '/Essential')
                    verdict = ('FAIL' if essential is True or essential is ABSENT and default_essential else
                               'PASS' if essential is False else 'NEEDS_REVIEW')
                elif condition == 'HEALTHY':
                    health = value(ctx, resource, target + '/HealthCheck')
                    verdict = 'FAIL' if health is ABSENT else 'PASS' if isinstance(health, dict) else 'NEEDS_REVIEW'
                elif condition == 'START':
                    verdict = 'PASS'
            results.append(ctx.finding(dependency_rule, path, verdict,
                'dependency target must exist; COMPLETE/SUCCESS require nonessential targets and HEALTHY requires HealthCheck'))
    return results


def port_ranges(ctx, resource, base):
    path = base + '/PortMappings'
    mappings = value(ctx, resource, path)
    if mappings is ABSENT:
        return []
    intervals, ranges = [], 0
    pending, bad = not isinstance(mappings, list), False
    for j in range(len(mappings) if isinstance(mappings, list) else 0):
        item_path = path + f'/{j}'
        port_range = value(ctx, resource, item_path + '/ContainerPortRange')
        port = value(ctx, resource, item_path + '/ContainerPort')
        if port_range is not ABSENT:
            if isinstance(port_range, str) and '{{' not in port_range:
                ranges += 1
                match = re.fullmatch(r'([0-9]{1,5})-([0-9]{1,5})', port_range)
                if match and 1 <= int(match[1]) < int(match[2]) <= 65535:
                    intervals.append((int(match[1]), int(match[2])))
                else:
                    bad = True
            else:
                pending = True
        if type(port) is int and port_range is ABSENT:
            intervals.append((port, port))
        elif port is not ABSENT:
            pending = True
    intervals.sort()
    overlap = any(left[1] >= right[0] for left, right in zip(intervals, intervals[1:]))
    verdict = 'FAIL' if bad or overlap or ranges > 100 else 'NEEDS_REVIEW' if pending else 'PASS'
    return [ctx.finding('ECS_TASK_PORT_RANGES', path, verdict,
        'ranges must ascend within 1..65535, at most 100 ranges per container, and no port may appear in two mappings')]
