"""Checks for these resource types:

- AWS::SSM::Parameter
- AWS::SSM::MaintenanceWindowTarget
- AWS::SSM::MaintenanceWindowTask
- AWS::SSM::MaintenanceWindow
- AWS::SSM::Association
"""
import json
import re
import unicodedata
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, UNKNOWN
from ..common.json_constants import reject_constant

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'SSM_AUTOMATION_RATE_TARGET': [CF + 'aws-resource-ssm-association.html'],
    'SSM_WINDOW_TAG_CHARACTERS': [CF + 'aws-properties-ssm-maintenancewindow-tag.html'],
    'SSM_TARGET_KEY_CHARACTERS': [CF + 'aws-properties-ssm-maintenancewindowtarget-targets.html', CF + 'aws-properties-ssm-maintenancewindowtask-target.html'],
    'SSM_PARAMETER_ARN_LENGTH': ['https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_PutParameter.html'],
    'SSM_PARAMETER_HIERARCHY_DEPTH': ['https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_PutParameter.html'],
    'SSM_PARAMETER_POLICY_ARRAY': ['https://docs.aws.amazon.com/systems-manager/latest/userguide/parameter-store-policies.html'],
}


@resource_check('AWS::SSM::Parameter')
def ssm_local(design, resource):
    ctx = _Context(design, resource)
    results = []
    name = value(ctx, resource, '/properties/Name')
    if name is not ABSENT:
        depth_verdict = 'NEEDS_REVIEW'
        if isinstance(name, str) and re.fullmatch(r'/?[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*', name):
            depth_verdict = 'FAIL' if len(name.lstrip('/').split('/')) > 15 else 'PASS'
        results.append(ctx.finding('SSM_PARAMETER_HIERARCHY_DEPTH', '/properties/Name', depth_verdict,
            'parameter hierarchies allow at most 15 levels; this checks recognized literal names only, separately from reserved prefixes and complete name syntax'))
        region, account = resource.scope.region, resource.scope.account
        # Scope has no partition field. Infer only established public partitions.
        partition = ('aws-cn' if region.startswith('cn-') else 'aws-us-gov' if region.startswith('us-gov-')
                     else 'aws' if re.fullmatch(r'(?:af|ap|ca|eu|il|me|mx|sa|us)-(?!iso)[a-z]+-\d+', region) else None)
        verdict = 'NEEDS_REVIEW'
        if isinstance(name, str) and '{{' not in name and partition and re.fullmatch(r'\d{12}', account):
            arn = f'arn:{partition}:ssm:{region}:{account}:parameter/' + name.removeprefix('/')
            verdict = 'PASS' if len(arn) <= 1011 else 'FAIL'
        results.append(ctx.finding('SSM_PARAMETER_ARN_LENGTH', '/properties/Name', verdict,
            'the user-specified parameter name limit includes its ARN prefix (1011 characters)'))
    policies = value(ctx, resource, '/properties/Policies')
    if policies is not ABSENT:
        verdict = 'NEEDS_REVIEW'
        if isinstance(policies, str) and '{{' not in policies:
            try:
                parsed = json.loads(policies, parse_constant=reject_constant)
            except (ValueError, RecursionError):
                verdict = 'FAIL'
            else:
                verdict = 'PASS' if isinstance(parsed, list) and len(parsed) <= 10 else 'FAIL'
        results.append(ctx.finding('SSM_PARAMETER_POLICY_ARRAY', '/properties/Policies', verdict,
            'policies must be a JSON array with at most 10 entries; individual policy semantics require separate review'))
    return results


@resource_check('AWS::SSM::MaintenanceWindowTarget', 'AWS::SSM::MaintenanceWindowTask')
def ssm_target_keys(design, resource):
    ctx = _Context(design, resource)
    base = '/properties/Targets'
    targets = value(ctx, resource, base)
    if targets is ABSENT:
        return []
    if not isinstance(targets, list):
        return [ctx.finding('SSM_TARGET_KEY_CHARACTERS', base, 'NEEDS_REVIEW', 'targets are unresolved')]
    results = []
    for index in range(len(targets)):
        path = base + f'/{index}/Key'
        key = value(ctx, resource, path)
        valid = isinstance(key, str) and all(
            c in '_.:/=-@' or unicodedata.category(c)[0] in 'LZN' for c in key)
        verdict = 'PASS' if valid else 'FAIL' if isinstance(key, str) else 'NEEDS_REVIEW'
        results.append(ctx.finding('SSM_TARGET_KEY_CHARACTERS', path, verdict,
            'target keys allow Unicode letters, separators, numbers and documented punctuation; length is checked separately'))
    return results


@resource_check('AWS::SSM::MaintenanceWindow')
def ssm_window_tags(design, resource):
    ctx = _Context(design, resource)
    base = '/properties/Tags'
    tags = value(ctx, resource, base)
    if tags is ABSENT:
        return []
    if not isinstance(tags, list):
        return [ctx.finding('SSM_WINDOW_TAG_CHARACTERS', base, 'NEEDS_REVIEW', 'tags are unresolved')]
    results = []
    for i in range(len(tags)):
        for field in ('Key', 'Value'):
            path = base + f'/{i}/' + field
            raw = value(ctx, resource, path)
            if raw is ABSENT:
                continue
            valid = isinstance(raw, str) and all(c in '_.:/=+-@' or unicodedata.category(c)[0] in 'LZN' for c in raw)
            verdict = 'PASS' if valid else 'FAIL' if isinstance(raw, str) else 'NEEDS_REVIEW'
            results.append(ctx.finding('SSM_WINDOW_TAG_CHARACTERS', path, verdict,
                'tag text allows Unicode letters, separators, numbers and documented punctuation; lengths are checked separately'))
    return results


@resource_check('AWS::SSM::Association')
def ssm_automation_rate_target(design, resource):
    ctx = _Context(design, resource)
    controls = [value(ctx, resource, '/properties/' + k) for k in ('MaxConcurrency', 'MaxErrors')]
    if all(v is ABSENT for v in controls):
        return []
    path = '/properties/AutomationTargetParameterName'
    parameter = value(ctx, resource, path)
    targets = value(ctx, resource, '/properties/Targets')
    document = linked(ctx, resource, '/properties/Name', 'AWS::SSM::Document')
    kind = value(ctx, document, '/properties/DocumentType') if document else UNKNOWN
    if kind == 'Command':
        return []
    verdict = 'NEEDS_REVIEW'
    if isinstance(parameter, str) and parameter and '{{' not in parameter:
        verdict = 'PASS'
    elif kind == 'Automation' and isinstance(targets, list) and targets and any(isinstance(v, str) for v in controls) and parameter is ABSENT:
        verdict = 'FAIL'
    return [ctx.finding('SSM_AUTOMATION_RATE_TARGET', path, verdict,
        'a linked Automation runbook with explicit rate controls and resource targets requires a target parameter; document ownership and implicit rate-control behavior remain separate')]
