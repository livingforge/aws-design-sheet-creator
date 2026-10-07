"""Task-local ECS references and option maps; no cluster lookups."""
from ..common.context_values import value
from ..common.field_reads import ABSENT
from .proxy import proxy_properties

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-ecs-taskdefinition-'
API = 'https://docs.aws.amazon.com/AmazonECS/latest/APIReference/'
SOURCES = {
    'ECS_TASK_CONTAINER_REFERENCE': [CF + 'volumefrom.html', CF + 'proxyconfiguration.html', API + 'ContainerDefinition.html'],
    'ECS_TASK_INFERENCE_REFERENCE': [API + 'ResourceRequirement.html'],
    'ECS_TASK_NEURON_CONTAINER_COUNT': [API + 'ResourceRequirement.html'],
    'ECS_TASK_FIRELENS_OPTIONS': [CF + 'firelensconfiguration.html'],
    'ECS_TASK_SPLUNK_OPTIONS': [CF + 'logconfiguration.html'],
}


def literal(item):
    return isinstance(item, str) and '{{' not in item


def name_index(ctx, resource, path, field):
    items = value(ctx, resource, path)
    names, pending = {}, items is not ABSENT and not isinstance(items, list)
    for i in range(len(items) if isinstance(items, list) else 0):
        name = value(ctx, resource, f'{path}/{i}/{field}')
        if literal(name):
            names.setdefault(name, []).append(i)
        else:
            pending = True
    return names, pending


def reference_verdict(name, names, pending, other_than=None):
    if not literal(name) or pending:
        return 'NEEDS_REVIEW'
    matches = names.get(name, [])
    if len(matches) > 1:
        return 'NEEDS_REVIEW'
    return 'PASS' if matches and matches[0] != other_than else 'FAIL'


def evaluate_task_references(ctx, resource, containers):
    root = '/properties/ContainerDefinitions'
    names, pending = name_index(ctx, resource, root, 'Name')
    accelerators, accelerator_pending = name_index(ctx, resource, '/properties/InferenceAccelerators', 'DeviceName')
    results = proxy_properties(ctx, resource)
    proxy = value(ctx, resource, '/properties/ProxyConfiguration')
    if proxy is not ABSENT:
        path = '/properties/ProxyConfiguration/ContainerName'
        name = value(ctx, resource, path)
        results.append(ctx.finding('ECS_TASK_CONTAINER_REFERENCE', path,
            reference_verdict(name, names, pending), 'proxy must name a container in this task'))
    neuron_containers, neuron_pending, has_requirements = 0, False, False
    if not isinstance(containers, list):
        return results
    for i in range(len(containers)):
        base = root + f'/{i}'
        for field, child in [('VolumesFrom', 'SourceContainer'), ('Links', None)]:
            items = value(ctx, resource, base + '/' + field)
            if items is ABSENT:
                continue
            if not isinstance(items, list):
                results.append(ctx.finding('ECS_TASK_CONTAINER_REFERENCE', base + '/' + field,
                    'NEEDS_REVIEW', 'container references are unresolved'))
                continue
            for j in range(len(items)):
                path = base + f'/{field}/{j}' + ('/' + child if child else '')
                name = value(ctx, resource, path)
                if field == 'Links' and literal(name):
                    name = name.split(':', 1)[0]
                verdict = reference_verdict(name, names, pending, other_than=i)
                results.append(ctx.finding('ECS_TASK_CONTAINER_REFERENCE', path, verdict,
                    'reference must identify another container in this task; duplicate names require review'))
        results.extend(firelens_options(ctx, resource, base))
        results.extend(splunk_options(ctx, resource, base))
        requirements = value(ctx, resource, base + '/ResourceRequirements')
        if requirements is ABSENT:
            continue
        has_requirements = True
        if not isinstance(requirements, list):
            neuron_pending = True
            continue
        has_neuron = False
        for j in range(len(requirements)):
            path = base + f'/ResourceRequirements/{j}'
            kind = value(ctx, resource, path + '/Type')
            if kind == 'NeuronDevice':
                has_neuron = True
            elif not literal(kind):
                neuron_pending = True
            if kind == 'InferenceAccelerator':
                name = value(ctx, resource, path + '/Value')
                results.append(ctx.finding('ECS_TASK_INFERENCE_REFERENCE', path + '/Value',
                    reference_verdict(name, accelerators, accelerator_pending),
                    'InferenceAccelerator value must match a task DeviceName'))
        neuron_containers += has_neuron
    if has_requirements:
        results.append(ctx.finding('ECS_TASK_NEURON_CONTAINER_COUNT', root,
            'FAIL' if neuron_containers > 1 else 'NEEDS_REVIEW' if neuron_pending else 'PASS',
            'only one container in a task may request NeuronDevice resources'))
    return results


def firelens_options(ctx, resource, base):
    path = base + '/FirelensConfiguration/Options'
    options = value(ctx, resource, path)
    if options is ABSENT:
        return []
    allowed = {'enable-ecs-log-metadata', 'config-file-type', 'config-file-value'}
    if not isinstance(options, dict):
        verdict = 'NEEDS_REVIEW'
    elif set(options) - allowed:
        verdict = 'FAIL'
    else:
        pending, bad = False, False
        for key, choices in [('enable-ecs-log-metadata', {'true', 'false'}),
                             ('config-file-type', {'s3', 'file'})]:
            item = value(ctx, resource, path + '/' + key)
            if item is ABSENT:
                continue
            if not literal(item):
                pending = True
            elif item not in choices:
                bad = True
        verdict = 'FAIL' if bad else 'NEEDS_REVIEW' if pending else 'PASS'
    return [ctx.finding('ECS_TASK_FIRELENS_OPTIONS', path, verdict,
        'FireLens permits three documented option keys and fixed metadata/config-file-type values')]


def splunk_options(ctx, resource, base, rule='ECS_TASK_SPLUNK_OPTIONS'):
    path = base + '/LogConfiguration'
    driver = value(ctx, resource, path + '/LogDriver')
    if driver is ABSENT or isinstance(driver, str) and driver != 'splunk':
        return []
    if driver != 'splunk':
        return [ctx.finding(rule, path, 'NEEDS_REVIEW', 'log driver is unresolved')]
    secrets = value(ctx, resource, path + '/SecretOptions')
    names = set()
    unknown_names = secrets is not ABSENT and not isinstance(secrets, list)
    for i in range(len(secrets) if isinstance(secrets, list) else 0):
        name = value(ctx, resource, path + f'/SecretOptions/{i}/Name')
        if literal(name):
            names.add(name)
        else:
            unknown_names = True
    missing, pending = False, False
    for key in ('splunk-token', 'splunk-url'):
        option = value(ctx, resource, path + '/Options/' + key)
        if key in names or literal(option) and option:
            continue
        if option is ABSENT and not unknown_names:
            missing = True
        else:
            pending = True
    return [ctx.finding(rule, path,
        'FAIL' if missing else 'NEEDS_REVIEW' if pending else 'PASS',
        'splunk-token and splunk-url must be supplied through Options or named SecretOptions; secret contents and access remain unverified')]
