"""ECS service relationships proven by same-scope task/target-group links."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, UNKNOWN
from ..common.vpc_membership import vpc_membership
from .deployment_time import deployment_time
from .references import splunk_options

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {rule: [CF + 'aws-resource-ecs-service.html'] for rule in (
    'ECS_SERVICE_TASK_NETWORK', 'ECS_SERVICE_ROLE_NETWORK', 'ECS_SERVICE_COMBINED_CONSTRAINTS')}
SOURCES.update({rule: [CF + 'aws-properties-ecs-service-loadbalancer.html'] for rule in (
    'ECS_SERVICE_CONTAINER_PORT', 'ECS_SERVICE_AWSVPC_TARGET_TYPE')})
SOURCES['ECS_SERVICE_SPLUNK_OPTIONS'] = [CF + 'aws-properties-ecs-service-logconfiguration.html']
SOURCES['ECS_SERVICE_LINKED_ROLE_REQUIRED'] = [CF + 'aws-resource-ecs-service.html',
    'https://docs.aws.amazon.com/AmazonECS/latest/developerguide/register-multiple-targetgroups.html']
SOURCES['ECS_SERVICE_CONNECT_PORT_REFERENCE'] = [CF + 'aws-properties-ecs-taskdefinition-portmapping.html', CF + 'aws-properties-ecs-service-serviceconnectservice.html']
SOURCES['ECS_SERVICE_CONNECT_REQUEST_TIMEOUT'] = [CF + 'aws-properties-ecs-service-timeoutconfiguration.html', CF + 'aws-properties-ecs-taskdefinition-portmapping.html']
SOURCES['ECS_SERVICE_FARGATE_CAPACITY'] = [CF + 'aws-resource-ecs-service.html',
    CF + 'aws-properties-ecs-service-capacityproviderstrategyitem.html',
    CF + 'aws-properties-ecs-service-placementconstraint.html',
    CF + 'aws-properties-ecs-service-servicemanagedebsvolumeconfiguration.html']
SOURCES['ECS_SERVICE_DEFAULT_CONTROLLER_TASK'] = ['https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_CreateService.html']
SOURCES['ECS_SERVICE_VOLUME_REFERENCE'] = [CF + 'aws-properties-ecs-service-servicevolumeconfiguration.html']
SOURCES['ECS_SERVICE_VPC_MEMBERSHIP'] = [CF + 'aws-properties-ecs-service-awsvpcconfiguration.html']
SOURCES.update({rule: [CF + 'aws-properties-ecs-service-serviceregistry.html'] for rule in (
    'ECS_SERVICE_REGISTRY_CONFIGURATION', 'ECS_SERVICE_REGISTRY_CONTAINER_PORT')})


@resource_check('AWS::ECS::Service')
def service_links(design, resource):
    ctx = _Context(design, resource)
    task = linked(ctx, resource, '/properties/TaskDefinition', 'AWS::ECS::TaskDefinition')
    mode = value(ctx, task, '/properties/NetworkMode') if task else UNKNOWN
    network = value(ctx, resource, '/properties/NetworkConfiguration')
    verdict = 'NEEDS_REVIEW'
    if mode == 'awsvpc':
        verdict = 'FAIL' if network is ABSENT else 'PASS' if isinstance(network, dict) else 'NEEDS_REVIEW'
    elif mode in ('bridge', 'host', 'none'):
        verdict = 'PASS' if network is ABSENT else 'FAIL' if isinstance(network, dict) else 'NEEDS_REVIEW'
    results = [ctx.finding('ECS_SERVICE_TASK_NETWORK', '/properties/NetworkConfiguration', verdict,
        'network configuration is required for linked awsvpc tasks and unsupported for explicit other network modes')]
    if value(ctx, resource, '/properties/DeploymentController') is ABSENT:
        definition = value(ctx, resource, '/properties/TaskDefinition')
        verdict = ('FAIL' if definition is ABSENT else 'PASS' if task or
                   isinstance(definition, str) and definition and '{{' not in definition and '${' not in definition else 'NEEDS_REVIEW')
        results.append(ctx.finding('ECS_SERVICE_DEFAULT_CONTROLLER_TASK', '/properties/TaskDefinition', verdict,
            'an omitted deployment controller defaults to ECS on creation and requires TaskDefinition; this does not validate an external task definition or existing service update state'))
    results.extend(splunk_options(ctx, resource, '/properties/ServiceConnectConfiguration', 'ECS_SERVICE_SPLUNK_OPTIONS'))
    results.extend(service_connect(ctx, resource, task))
    results.extend(fargate_capacity(ctx, resource))
    results.extend(deployment_time(ctx, resource))
    results.extend(service_registries(ctx, resource, task, mode))
    results.extend(volume_references(ctx, resource, task))
    results.extend(vpc_membership(ctx, resource, '/properties/NetworkConfiguration/AwsvpcConfiguration', 'ECS_SERVICE_VPC_MEMBERSHIP'))
    role = value(ctx, resource, '/properties/Role')
    if role is not ABSENT:
        verdict = ('FAIL' if mode == 'awsvpc' and isinstance(role, str) else
                   'PASS' if mode in ('bridge', 'host', 'none') else 'NEEDS_REVIEW')
        results.append(ctx.finding('ECS_SERVICE_ROLE_NETWORK', '/properties/Role', verdict,
            'a service using an awsvpc task cannot specify Role; service-linked-role requirements beyond network mode are separate'))
        registry = value(ctx, resource, '/properties/ServiceRegistries')
        controller = value(ctx, resource, '/properties/DeploymentController/Type')
        accelerators = value(ctx, task, '/properties/InferenceAccelerators') if task else UNKNOWN
        registry_known = isinstance(registry, list) and any(isinstance(value(ctx, resource, f'/properties/ServiceRegistries/{i}'), dict) for i in range(len(registry)))
        accelerator_known = task and isinstance(accelerators, list) and any(isinstance(value(ctx, task, f'/properties/InferenceAccelerators/{i}'), dict) for i in range(len(accelerators)))
        multiple = multiple_target_groups(ctx, resource)
        required = controller == 'EXTERNAL' or registry_known or accelerator_known or multiple is True
        if required or multiple is None:
            results.append(ctx.finding('ECS_SERVICE_LINKED_ROLE_REQUIRED', '/properties/Role',
                'FAIL' if required and isinstance(role, str) and '{{' not in role else 'NEEDS_REVIEW',
                'service discovery, EXTERNAL controller, inference accelerators and multiple target groups require the service-linked role instead of explicit Role'))
    count, pending = 0, False
    for obj in (value(ctx, resource, '/properties/PlacementConstraints'),
                value(ctx, task, '/properties/PlacementConstraints') if task else UNKNOWN):
        if isinstance(obj, list):
            count += len(obj)
        elif obj is not ABSENT:
            pending = True
    results.append(ctx.finding('ECS_SERVICE_COMBINED_CONSTRAINTS', '/properties/PlacementConstraints',
        'FAIL' if count > 10 else 'NEEDS_REVIEW' if pending else 'PASS',
        'service and task-definition placement constraints together cannot exceed ten'))
    lbs = value(ctx, resource, '/properties/LoadBalancers')
    if lbs is ABSENT:
        return results
    if not isinstance(lbs, list):
        return results + [ctx.finding('ECS_SERVICE_CONTAINER_PORT', '/properties/LoadBalancers', 'NEEDS_REVIEW', 'load balancers are unresolved')]
    for i in range(len(lbs)):
        base = f'/properties/LoadBalancers/{i}'
        results.append(container_port(ctx, resource, task, base))
        if mode == 'awsvpc':
            classic = value(ctx, resource, base + '/LoadBalancerName')
            group = linked(ctx, resource, base + '/TargetGroupArn', 'AWS::ElasticLoadBalancingV2::TargetGroup')
            kind = value(ctx, group, '/properties/TargetType') if group else UNKNOWN
            verdict = ('FAIL' if isinstance(classic, str) and '{{' not in classic else
                       'PASS' if kind == 'ip' else 'FAIL' if kind in ('instance', 'lambda', 'alb') else 'NEEDS_REVIEW')
            results.append(ctx.finding('ECS_SERVICE_AWSVPC_TARGET_TYPE', base, verdict,
                'awsvpc tasks cannot use Classic Load Balancers and require linked target groups of type ip'))
    return results


def multiple_target_groups(ctx, resource):
    groups = value(ctx, resource, '/properties/LoadBalancers')
    if groups is ABSENT:
        return False
    if not isinstance(groups, list):
        return None
    arns, ids, pending = set(), set(), False
    for i in range(len(groups)):
        path = f'/properties/LoadBalancers/{i}/TargetGroupArn'
        raw = value(ctx, resource, path)
        if raw is ABSENT:
            continue
        group = linked(ctx, resource, path, 'AWS::ElasticLoadBalancingV2::TargetGroup')
        if group:
            ids.add(group.id)
        elif isinstance(raw, str) and re.fullmatch(r'arn:[a-z0-9-]+:elasticloadbalancing:[a-z0-9-]+:\d{12}:targetgroup/[A-Za-z0-9-]+/[a-fA-F0-9]{16}', raw):
            arns.add(raw)
        else:
            pending = True
    if len(arns) > 1 or len(ids) > 1:
        return True
    # A literal ARN and a linked logical resource may identify the same group.
    return None if pending or (arns and ids) else False


def volume_references(ctx, resource, task):
    root = '/properties/VolumeConfigurations'
    configs = value(ctx, resource, root)
    if configs is ABSENT:
        return []
    if not isinstance(configs, list):
        return [ctx.finding('ECS_SERVICE_VOLUME_REFERENCE', root, 'NEEDS_REVIEW', 'volume configurations are unresolved')]
    volumes = value(ctx, task, '/properties/Volumes') if task else UNKNOWN
    names, pending = [], volumes is not ABSENT and not isinstance(volumes, list)
    for i in range(len(volumes) if isinstance(volumes, list) else 0):
        name = value(ctx, task, f'/properties/Volumes/{i}/Name')
        if isinstance(name, str) and '{{' not in name:
            names.append(name)
        else:
            pending = True
    results = []
    for i in range(len(configs)):
        path = root + f'/{i}/Name'
        name = value(ctx, resource, path)
        verdict = 'NEEDS_REVIEW'
        if isinstance(name, str) and '{{' not in name and not pending:
            count = names.count(name)
            verdict = 'PASS' if count == 1 else 'FAIL' if count == 0 else 'NEEDS_REVIEW'
        results.append(ctx.finding('ECS_SERVICE_VOLUME_REFERENCE', path, verdict,
            'service volume names must match a unique volume in the linked task definition'))
    return results


def container_port(ctx, resource, task, base, rule='ECS_SERVICE_CONTAINER_PORT'):
    containers = value(ctx, task, '/properties/ContainerDefinitions') if task else UNKNOWN
    name = value(ctx, resource, base + '/ContainerName')
    port = value(ctx, resource, base + '/ContainerPort')
    matches, pending, verdict = [], not isinstance(containers, list), 'NEEDS_REVIEW'
    for i in range(len(containers) if isinstance(containers, list) else 0):
        path = f'/properties/ContainerDefinitions/{i}'
        candidate = value(ctx, task, path + '/Name')
        if not isinstance(candidate, str) or '{{' in candidate:
            pending = True
        elif candidate == name:
            matches.append(path)
    if isinstance(name, str) and '{{' not in name and type(port) is int and not pending:
        if not matches:
            verdict = 'FAIL'
        elif len(matches) == 1:
            path = matches[0] + '/PortMappings'
            mappings = value(ctx, task, path)
            pending = mappings is not ABSENT and not isinstance(mappings, list)
            ports = []
            for i in range(len(mappings) if isinstance(mappings, list) else 0):
                raw = value(ctx, task, path + f'/{i}/ContainerPort')
                pending |= type(raw) is not int
                if type(raw) is int:
                    ports.append(raw)
            verdict = 'PASS' if port in ports else 'NEEDS_REVIEW' if pending else 'FAIL'
    return ctx.finding(rule, base + '/ContainerPort', verdict,
        'service container name and port must match a linked task definition; duplicate/unknown names or range-only mappings require review')


def service_connect(ctx, resource, task):
    root = '/properties/ServiceConnectConfiguration'
    if value(ctx, resource, root + '/Enabled') is False:
        return []
    path = root + '/Services'
    services = value(ctx, resource, path)
    if services is ABSENT:
        return []
    if not isinstance(services, list):
        return [ctx.finding('ECS_SERVICE_CONNECT_PORT_REFERENCE', path, 'NEEDS_REVIEW', 'Service Connect services are unresolved')]
    containers = value(ctx, task, '/properties/ContainerDefinitions') if task else UNKNOWN
    names, pending = {}, not isinstance(containers, list)
    for i in range(len(containers) if isinstance(containers, list) else 0):
        base = f'/properties/ContainerDefinitions/{i}/PortMappings'
        mappings = value(ctx, task, base)
        if mappings is ABSENT:
            continue
        if not isinstance(mappings, list):
            pending = True
            continue
        for j in range(len(mappings)):
            mapping = base + f'/{j}'
            name = value(ctx, task, mapping + '/Name')
            if name is ABSENT:
                continue
            if not isinstance(name, str) or '{{' in name:
                pending = True
            else:
                names.setdefault(name, []).append(mapping)
    results = []
    for i in range(len(services)):
        base = path + f'/{i}'
        name = value(ctx, resource, base + '/PortName')
        matches = names.get(name, []) if isinstance(name, str) else []
        verdict = 'NEEDS_REVIEW'
        if isinstance(name, str) and '{{' not in name and not pending:
            verdict = 'PASS' if len(matches) == 1 else 'FAIL' if not matches else 'NEEDS_REVIEW'
        results.append(ctx.finding('ECS_SERVICE_CONNECT_PORT_REFERENCE', base + '/PortName', verdict,
            'Service Connect PortName must identify a unique named port mapping in the linked task definition'))
        timeout = value(ctx, resource, base + '/Timeout/PerRequestTimeoutSeconds')
        if timeout is ABSENT:
            continue
        timeout_verdict = 'NEEDS_REVIEW'
        if verdict == 'PASS' and type(timeout) is int:
            protocol = value(ctx, task, matches[0] + '/AppProtocol')
            timeout_verdict = ('FAIL' if protocol is ABSENT or protocol == 'tcp' else
                               'PASS' if protocol in ('http', 'http2', 'grpc') else 'NEEDS_REVIEW')
        results.append(ctx.finding('ECS_SERVICE_CONNECT_REQUEST_TIMEOUT', base + '/Timeout/PerRequestTimeoutSeconds', timeout_verdict,
            'PerRequestTimeoutSeconds is not allowed for TCP, including the default when AppProtocol is omitted'))
    return results


def fargate_capacity(ctx, resource):
    if value(ctx, resource, '/properties/LaunchType') is not ABSENT:
        return []  # Existing declared rules cover explicit launch types.
    base = '/properties/CapacityProviderStrategy'
    strategy = value(ctx, resource, base)
    if strategy is ABSENT or strategy == []:
        return []  # The cluster default cannot be inferred.
    known_fargate = isinstance(strategy, list) and all(
        value(ctx, resource, base + f'/{i}/CapacityProvider') in ('FARGATE', 'FARGATE_SPOT')
        for i in range(len(strategy)))
    results = []
    scheduling = value(ctx, resource, '/properties/SchedulingStrategy')
    if scheduling == 'DAEMON':
        results.append(ctx.finding('ECS_SERVICE_FARGATE_CAPACITY', '/properties/SchedulingStrategy',
            'FAIL' if known_fargate else 'NEEDS_REVIEW',
            'DAEMON is unsupported when every explicit capacity provider is FARGATE/FARGATE_SPOT'))
    constraints = value(ctx, resource, '/properties/PlacementConstraints')
    if constraints is not ABSENT and constraints != []:
        definite = isinstance(constraints, list) and any(
            isinstance(value(ctx, resource, f'/properties/PlacementConstraints/{i}'), dict)
            for i in range(len(constraints)))
        results.append(ctx.finding('ECS_SERVICE_FARGATE_CAPACITY', '/properties/PlacementConstraints',
            'FAIL' if known_fargate and definite else 'NEEDS_REVIEW',
            'task placement constraints are unsupported with a proven Fargate-only strategy'))
    volumes = value(ctx, resource, '/properties/VolumeConfigurations')
    for i in range(len(volumes) if isinstance(volumes, list) else 0):
        path = f'/properties/VolumeConfigurations/{i}/ManagedEBSVolume/VolumeType'
        if value(ctx, resource, path) == 'standard':
            results.append(ctx.finding('ECS_SERVICE_FARGATE_CAPACITY', path,
                'FAIL' if known_fargate else 'NEEDS_REVIEW',
                'magnetic EBS volumes are unsupported with a proven Fargate-only strategy'))
    return results


def service_registries(ctx, resource, task, mode, prefix='ECS_SERVICE'):
    root = '/properties/ServiceRegistries'
    registries = value(ctx, resource, root)
    if registries is ABSENT:
        return []
    if not isinstance(registries, list):
        return [ctx.finding(prefix + '_REGISTRY_CONFIGURATION', root, 'NEEDS_REVIEW', 'service registries are unresolved')]
    results = []
    for i in range(len(registries)):
        base = root + f'/{i}'
        name = value(ctx, resource, base + '/ContainerName')
        port = value(ctx, resource, base + '/ContainerPort')
        direct = value(ctx, resource, base + '/Port')
        pair = False if name is ABSENT or port is ABSENT else True if isinstance(name, str) and '{{' not in name and type(port) is int else None
        direct_present = False if direct is ABSENT else True if type(direct) is int else None
        verdict = 'NEEDS_REVIEW'
        if mode in ('bridge', 'host'):
            verdict = 'PASS' if pair is True else 'FAIL' if pair is False else 'NEEDS_REVIEW'
        elif mode == 'awsvpc':
            registry = linked(ctx, resource, base + '/RegistryArn', 'AWS::ServiceDiscovery::Service')
            records = value(ctx, registry, '/properties/DnsConfig/DnsRecords') if registry else UNKNOWN
            types = [value(ctx, registry, f'/properties/DnsConfig/DnsRecords/{j}/Type') for j in range(len(records))] if isinstance(records, list) else []
            if 'SRV' in types:
                if pair is not None and direct_present is not None:
                    verdict = 'PASS' if pair != direct_present else 'FAIL'
            elif types and all(kind in ('A', 'AAAA', 'CNAME') for kind in types):
                continue  # This conditional requirement applies to SRV only.
        results.append(ctx.finding(prefix + '_REGISTRY_CONFIGURATION', base, verdict,
            'bridge/host need a container name/port pair; awsvpc with a linked SRV registry needs either that pair or Port, but not both'))
        if pair is True:
            results.append(container_port(ctx, resource, task, base, prefix + '_REGISTRY_CONTAINER_PORT'))
    return results
