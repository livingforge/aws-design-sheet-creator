"""Checks for AWS::Events::Rule."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, UNKNOWN
from ..common.vpc_membership import vpc_membership
from .input import event_input

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'EVENTS_REDSHIFT_SECRET_REPRESENTATION': [CF + 'aws-properties-events-rule-redshiftdataparameters.html', 'https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_RedshiftDataParameters.html'],
    'EVENTS_TARGET_INVOCATION_ROLE': ['https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-events-iam-roles.html', CF + 'aws-resource-events-rule.html'],
    'EVENTS_ENCRYPTED_BUS_DISCOVERY': ['https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-events-eventbus.html', 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-eventschemas-discoverer.html'],
    'EVENTS_CROSS_ACCOUNT_BUS_INPUT': [CF + 'aws-resource-events-rule.html'],
    'EVENTS_CAPACITY_PROVIDER_BASE_COUNT': [CF + 'aws-properties-events-rule-capacityproviderstrategyitem.html'],
    'EVENTS_ECS_TASK_COMPATIBILITY': [CF + 'aws-properties-events-rule-ecsparameters.html'],
    'EVENTS_ECS_VPC_MEMBERSHIP': [CF + 'aws-properties-events-rule-awsvpcconfiguration.html'],
    'EVENTS_PARTNER_BUS_MANAGEMENT_EVENTS': [CF + 'aws-resource-events-rule.html', CF + 'aws-resource-events-eventbus.html'],
    'EVENTS_FIFO_TARGET_DEDUPLICATION': [CF + 'aws-properties-events-rule-target.html'],
    'EVENTS_ECS_COMBINED_CONSTRAINTS': [CF + 'aws-properties-events-rule-ecsparameters.html'],
    'EVENTS_INPUT_PATHS_MAP': [CF + 'aws-properties-events-rule-inputtransformer.html'],
}


def encrypted_bus_discovery(design, resource):
    ctx = _Context(design, resource)
    path = '/properties/KmsKeyIdentifier'
    key = value(ctx, resource, path)
    if key is ABSENT:
        return []
    key_known = bool(linked(ctx, resource, path, 'AWS::KMS::Key')) or (isinstance(key, str) and bool(key) and re.fullmatch(r'[a-zA-Z0-9_\-/:]+', key) is not None)
    collision = False
    for discoverer in design.resources:
        if discoverer.type != 'AWS::EventSchemas::Discoverer':
            continue
        other_ctx = _Context(design, discoverer)
        bus = linked(other_ctx, discoverer, '/properties/SourceArn', resource.type)
        if bus and bus.id == resource.id:
            ctx.evidence.extend(other_ctx.evidence)
            collision = True
    return [ctx.finding('EVENTS_ENCRYPTED_BUS_DISCOVERY', path,
        'FAIL' if key_known and collision else 'NEEDS_REVIEW',
        'customer-key encryption cannot be combined with the explicitly linked schema discoverer' if key_known and collision else
        'unresolved encryption keys, unlinked discoverers and existing discovery state remain unverified')]


@resource_check('AWS::Events::Rule')
def event_targets(design, resource):
    ctx = _Context(design, resource)
    results = partner_bus_state(ctx, resource)
    targets = value(ctx, resource, '/properties/Targets')
    if targets is ABSENT:
        return results
    if not isinstance(targets, list):
        return results + [ctx.finding(rule, '/properties/Targets', 'NEEDS_REVIEW', 'targets are unresolved')
                for rule in ('EVENTS_CROSS_ACCOUNT_BUS_INPUT', 'EVENTS_CAPACITY_PROVIDER_BASE_COUNT')]
    for i in range(len(targets)):
        path = f'/properties/Targets/{i}'
        results.extend(event_input(ctx, resource, path))
        results.extend(target_invocation_role(ctx, resource, path))
        results.extend(redshift_secret(ctx, resource, path))
        map_path = path + '/InputTransformer/InputPathsMap'
        mappings = value(ctx, resource, map_path)
        if mappings is not ABSENT:
            verdict = 'NEEDS_REVIEW'
            if isinstance(mappings, dict):
                if any(k == 'Ref' or isinstance(k, str) and k.startswith(('Fn::', '$')) for k in mappings):
                    verdict = 'NEEDS_REVIEW'
                else:
                    verdict = 'FAIL' if len(mappings) > 100 or any(isinstance(k, str) and k.startswith('AWS.') for k in mappings) else 'PASS'
            results.append(ctx.finding('EVENTS_INPUT_PATHS_MAP', map_path, verdict,
                'input path maps allow at most 100 entries and keys cannot begin AWS.; JSON path grammar is a separate check'))
        results.extend(ecs_target_links(ctx, resource, path))
        queue = linked(ctx, resource, path + '/Arn', 'AWS::SQS::Queue')
        if queue:
            fifo = value(ctx, queue, '/properties/FifoQueue')
            if fifo is True:
                dedup = value(ctx, queue, '/properties/ContentBasedDeduplication')
                results.append(ctx.finding('EVENTS_FIFO_TARGET_DEDUPLICATION', path + '/Arn',
                    'PASS' if dedup is True else 'FAIL' if dedup is False or dedup is ABSENT else 'NEEDS_REVIEW',
                    'linked FIFO queue targets require content-based deduplication; standard/fair queue semantics are not inferred'))
            elif fifo is not ABSENT and type(fifo) is not bool:
                results.append(ctx.finding('EVENTS_FIFO_TARGET_DEDUPLICATION', path + '/Arn', 'NEEDS_REVIEW',
                    'linked queue FIFO mode is unresolved'))
        arn = value(ctx, resource, path + '/Arn')
        inputs = [value(ctx, resource, path + '/' + name) for name in ('Input', 'InputPath', 'InputTransformer')]
        if any(v is not ABSENT for v in inputs):
            match = re.fullmatch(r'arn:[a-z0-9-]+:events:[a-z0-9-]+:(\d{12}):event-bus/[^{}\s]+', arn) if isinstance(arn, str) else None
            verdict = 'NEEDS_REVIEW'
            if match and re.fullmatch(r'\d{12}', resource.scope.account):
                verdict = ('PASS' if match[1] == resource.scope.account else
                           'FAIL' if any(v is not ABSENT and v is not UNKNOWN for v in inputs) else 'NEEDS_REVIEW')
            elif isinstance(arn, str) and re.fullmatch(r'arn:[a-z0-9-]+:(?!events:)[a-z0-9-]+:[^{}\s]+', arn):
                continue
            results.append(ctx.finding('EVENTS_CROSS_ACCOUNT_BUS_INPUT', path, verdict,
                'input overrides cannot be supplied to a literal event-bus ARN in another account; unresolved target accounts require review'))
        base_path = path + '/EcsParameters/CapacityProviderStrategy'
        strategies = value(ctx, resource, base_path)
        if strategies is ABSENT:
            continue
        count, pending = 0, not isinstance(strategies, list)
        for j in range(len(strategies) if isinstance(strategies, list) else 0):
            base = value(ctx, resource, base_path + f'/{j}/Base')
            if type(base) is int:
                count += 1
            elif base is not ABSENT:
                pending = True
        results.append(ctx.finding('EVENTS_CAPACITY_PROVIDER_BASE_COUNT', base_path,
            'FAIL' if count > 1 else 'NEEDS_REVIEW' if pending else 'PASS',
            'at most one strategy entry may define Base; an explicit zero still defines the field'))
    return results


def redshift_secret(ctx, resource, path):
    path += '/RedshiftDataParameters/SecretManagerArn'
    raw = value(ctx, resource, path)
    if raw is ABSENT:
        return []
    verdict = 'NEEDS_REVIEW'
    if linked(ctx, resource, path, 'AWS::SecretsManager::Secret'):
        verdict = 'PASS'
    elif isinstance(raw, str) and '{' not in raw:
        if raw.startswith('arn:'):
            verdict = 'PASS' if re.fullmatch(r'arn:aws[a-z-]*:secretsmanager:[a-z0-9.-]+:\d{12}:secret:[^\s:]+', raw) else 'FAIL'
        elif raw.startswith('$'):
            verdict = 'PASS' if re.fullmatch(r'\$(\.[\w_-]+(\[(\d+|\*)\])*)*', raw) else 'FAIL'
    return [ctx.finding('EVENTS_REDSHIFT_SECRET_REPRESENTATION', path, verdict,
        'checks a Secrets Manager ARN or documented JSON-path representation; plain names conflict with the published pattern and runtime identity/permissions remain unverified')]


def target_invocation_role(ctx, resource, path):
    arn = value(ctx, resource, path + '/Arn')
    known = any(linked(ctx, resource, path + '/Arn', kind) for kind in (
        'AWS::Kinesis::Stream','AWS::StepFunctions::StateMachine'))
    if isinstance(arn, str):
        known |= re.fullmatch(r'arn:[a-z0-9-]+:(?:kinesis:[a-z0-9-]+:\d{12}:stream/[^{}\s]+|states:[a-z0-9-]+:\d{12}:stateMachine:[^{}\s]+)', arn) is not None
    if not known:
        return []
    role_path = path + '/RoleArn'
    role = value(ctx, resource, role_path)
    if role is ABSENT:
        role_path = '/properties/RoleArn'
        role = value(ctx, resource, role_path)
    verdict = 'NEEDS_REVIEW'
    if role is ABSENT:
        verdict = 'FAIL'
    elif linked(ctx, resource, role_path, 'AWS::IAM::Role') or isinstance(role, str) and re.fullmatch(r'arn:[a-z0-9-]+:iam::\d{12}:role/[^{}\s]+', role):
        verdict = 'PASS'
    return [ctx.finding('EVENTS_TARGET_INVOCATION_ROLE', path + '/RoleArn', verdict,
        'a proven Kinesis stream or Step Functions target requires an invocation role; checks presence only, not role permissions or trust')]


def partner_bus_state(ctx, resource):
    state = value(ctx, resource, '/properties/State')
    if state != 'ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS':
        return []
    name = value(ctx, resource, '/properties/EventBusName')
    bus = linked(ctx, resource, '/properties/EventBusName', 'AWS::Events::EventBus')
    verdict = 'NEEDS_REVIEW'
    if bus:
        source = value(ctx, bus, '/properties/EventSourceName')
        verdict = 'PASS' if source is ABSENT else 'FAIL' if isinstance(source, str) and '{{' not in source else 'NEEDS_REVIEW'
    elif name is ABSENT or name == 'default':
        verdict = 'PASS'
    return [ctx.finding('EVENTS_PARTNER_BUS_MANAGEMENT_EVENTS', '/properties/State', verdict,
        'management-event mode is allowed on default/custom buses, not linked partner-source buses; bus names alone do not establish kind')]


def ecs_target_links(ctx, resource, path):
    base = path + '/EcsParameters'
    if value(ctx, resource, base) is ABSENT:
        return []
    results = []
    launch = value(ctx, resource, base + '/LaunchType')
    network = value(ctx, resource, base + '/NetworkConfiguration')
    task = linked(ctx, resource, base + '/TaskDefinitionArn', 'AWS::ECS::TaskDefinition')
    runtime_constraints = value(ctx, resource, base + '/PlacementConstraints')
    task_constraints = value(ctx, task, '/properties/PlacementConstraints') if task else UNKNOWN
    if runtime_constraints is not ABSENT or task_constraints is not ABSENT:
        count, pending = 0, False
        for constraints in (runtime_constraints, task_constraints):
            if isinstance(constraints, list):
                count += len(constraints)
            elif constraints is not ABSENT:
                pending = True
        results.append(ctx.finding('EVENTS_ECS_COMBINED_CONSTRAINTS', base + '/PlacementConstraints',
            'FAIL' if count > 10 else 'NEEDS_REVIEW' if pending else 'PASS',
            'the task definition and runtime placement constraints together cannot exceed ten; unresolved task definitions require review'))
    if launch is not ABSENT or network is not ABSENT:
        pending, bad = task is None, False
        if task:
            if launch is not ABSENT:
                compat = value(ctx, task, '/properties/RequiresCompatibilities')
                if not isinstance(launch, str) or '{{' in launch or not isinstance(compat, list):
                    pending = True
                elif launch not in compat:
                    if any(not isinstance(c, str) or '{{' in c for c in compat):
                        pending = True
                    else:
                        bad = True
            if network is not ABSENT:
                mode = value(ctx, task, '/properties/NetworkMode')
                if isinstance(mode, str) and '{{' not in mode and network is not UNKNOWN:
                    bad |= mode != 'awsvpc'
                else:
                    pending = True
        results.append(ctx.finding('EVENTS_ECS_TASK_COMPATIBILITY', base,
            'FAIL' if bad else 'NEEDS_REVIEW' if pending else 'PASS',
            'explicit launch type must match linked task compatibility; network configuration requires task awsvpc mode'))
    vpc_base = base + '/NetworkConfiguration/AwsVpcConfiguration'
    results.extend(vpc_membership(ctx, resource, vpc_base, 'EVENTS_ECS_VPC_MEMBERSHIP'))
    return results
