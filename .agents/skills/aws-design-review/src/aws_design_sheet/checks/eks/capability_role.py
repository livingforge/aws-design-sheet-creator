"""Declared EKS capability trust only; does not simulate effective IAM access."""
import json
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.partitions import public_partition
from ..common.trust_documents import unique_object, unresolved

SOURCES = {'EKS_CAPABILITY_DECLARED_TRUST': [
    'https://docs.aws.amazon.com/eks/latest/userguide/capability-role.html']}
REQUIRED = {'sts:AssumeRole', 'sts:TagSession'}


def capability_trust_verdict(document):
    if isinstance(document, str):
        try:
            document = json.loads(document, object_pairs_hook=unique_object) if len(document) <= 65536 else None
        except (ValueError, RecursionError):
            return 'NEEDS_REVIEW'
    if not isinstance(document, dict):
        return 'NEEDS_REVIEW'
    try:
        if unresolved(document):
            return 'NEEDS_REVIEW'
    except RecursionError:
        return 'NEEDS_REVIEW'
    if (set(document) - {'Version', 'Id', 'Statement'}
            or document.get('Version', '2012-10-17') != '2012-10-17'):
        return 'NEEDS_REVIEW'
    statements = document.get('Statement')
    statements = [statements] if isinstance(statements, dict) else statements
    if not isinstance(statements, list) or not statements:
        return 'NEEDS_REVIEW'
    allowed, pending = set(), False
    for statement in statements:
        if not isinstance(statement, dict) or set(statement) - {'Sid', 'Effect', 'Principal', 'Action'}:
            pending = True
            continue
        principal, actions, effect = statement.get('Principal'), statement.get('Action'), statement.get('Effect')
        actions = [actions] if isinstance(actions, str) else actions
        if (effect not in ('Allow', 'Deny') or not isinstance(principal, dict)
                or set(principal) != {'Service'} or not isinstance(actions, list) or not actions):
            pending = True
            continue
        services = principal['Service']
        services = [services] if isinstance(services, str) else services
        if (not isinstance(services, list) or not services
                or not all(isinstance(s, str) and re.fullmatch(r'[a-z0-9.-]+', s) for s in services)
                or not all(isinstance(a, str) and re.fullmatch(r'[A-Za-z0-9]+:[A-Za-z0-9]+', a) for a in actions)):
            pending = True
            continue
        # Only the exact documented action spelling is recognized here.
        # Case variants and wildcard actions remain unverified, not denied.
        if any(a.lower() in {r.lower() for r in REQUIRED} and a not in REQUIRED for a in actions):
            pending = True
            continue
        matches = REQUIRED.intersection(actions) if 'capabilities.eks.amazonaws.com' in services else set()
        if matches and effect == 'Deny':
            return 'FAIL'
        if effect == 'Allow':
            allowed.update(matches)
    return 'NEEDS_REVIEW' if pending else 'PASS' if allowed == REQUIRED else 'FAIL'


@resource_check('AWS::EKS::Capability')
def capability_role(design, resource):
    ctx = _Context(design, resource)
    path, policy_path = '/properties/RoleArn', '/properties/AssumeRolePolicyDocument'
    role = linked(ctx, resource, path, 'AWS::IAM::Role')
    verdict = 'NEEDS_REVIEW'
    if (role and public_partition(resource.scope.region) == 'aws'
            and re.fullmatch(r'[0-9]{12}', resource.scope.account)):
        nested_refs = any(r.source_resource_id == role.id and r.source_path.startswith(policy_path + '/')
                          for r in design.relations)
        if not nested_refs:
            verdict = capability_trust_verdict(value(ctx, role, policy_path))
    return [ctx.finding('EKS_CAPABILITY_DECLARED_TRUST', path, verdict,
        'checks declared unconditional capabilities.eks.amazonaws.com trust for both sts:AssumeRole and sts:TagSession on an explicitly linked same-scope role; conditions, unsupported syntax/partitions and external or effective permissions remain unverified')]
