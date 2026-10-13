"""Narrow, explicit SNS service trust checks; not an IAM authorization simulator."""
import json
import re
from ..common.context_values import _Context, linked, value
from ..common.trust_documents import unique_object, unresolved

SOURCES = {'SNS_FIREHOSE_ROLE_TRUST': [
    'https://docs.aws.amazon.com/sns/latest/dg/prereqs-kinesis-data-firehose.html',
    'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html']}
SOURCES['SNS_FIREHOSE_DECLARED_WRITE'] = SOURCES['SNS_FIREHOSE_ROLE_TRUST']


def sns_trust_verdict(document):
    if isinstance(document, str):
        if len(document) > 65536:
            return 'NEEDS_REVIEW'
        try:
            document = json.loads(document, object_pairs_hook=unique_object)
        except (ValueError, TypeError, RecursionError):
            return 'NEEDS_REVIEW'
    if not isinstance(document, dict):
        return 'NEEDS_REVIEW'
    try:
        if unresolved(document):
            return 'NEEDS_REVIEW'
    except RecursionError:
        return 'NEEDS_REVIEW'
    statements = document.get('Statement')
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or not statements:
        return 'NEEDS_REVIEW'
    allowed, pending = False, False
    for statement in statements:
        if not isinstance(statement, dict) or any(k in statement for k in ('NotPrincipal','NotAction','Condition')):
            pending = True
            continue
        principal = statement.get('Principal')
        effect = statement.get('Effect')
        actions = statement.get('Action')
        actions = [actions] if isinstance(actions, str) else actions
        if effect not in ('Allow','Deny') or not isinstance(principal, dict) or set(principal) != {'Service'} or not isinstance(actions, list) or not actions:
            pending = True
            continue
        services = principal['Service']
        services = [services] if isinstance(services, str) else services
        if not isinstance(services, list) or not services or not all(isinstance(s, str) and '*' not in s and '?' not in s for s in services):
            pending = True
            continue
        if not all(isinstance(a, str) and (a.lower() in ('*','sts:*') or '*' not in a and '?' not in a) for a in actions):
            pending = True
            continue
        matches = 'sns.amazonaws.com' in services and any(a.lower() in ('sts:assumerole','sts:*','*') for a in actions)
        if matches and effect == 'Deny':
            return 'FAIL'
        allowed |= matches and effect == 'Allow'
    return 'NEEDS_REVIEW' if pending else 'PASS' if allowed else 'FAIL'


def sns_firehose_trust(design, resource):
    ctx = _Context(design, resource)
    if resource.type != 'AWS::SNS::Subscription' or value(ctx, resource, '/properties/Protocol') != 'firehose':
        return []
    path = '/properties/SubscriptionRoleArn'
    role = linked(ctx, resource, path, 'AWS::IAM::Role')
    verdict = 'NEEDS_REVIEW'
    policy_path = '/properties/AssumeRolePolicyDocument'
    if role and not resource.scope.region.startswith(('cn-','us-iso','eu-isoe')):
        nested_refs = any(r.source_resource_id == role.id and r.source_path.startswith(policy_path + '/') for r in design.relations)
        if not nested_refs:
            verdict = sns_trust_verdict(value(ctx, role, policy_path))
    return [ctx.finding('SNS_FIREHOSE_ROLE_TRUST', path, verdict,
        'checks unconditional explicit SNS sts:AssumeRole trust on a linked role; conditions, broad principals and partition-specific principals remain unverified'),
        ctx.finding('SNS_FIREHOSE_DECLARED_WRITE', path, declared_firehose_write(ctx, resource, role),
        'checks explicit inline PutRecord grants/denials for the literal endpoint; external policies, boundaries, SCPs and effective authorization remain unverified')]


def declared_firehose_write(ctx, resource, role):
    endpoint = value(ctx, resource, '/properties/Endpoint')
    if not role or not isinstance(endpoint, str) or not re.fullmatch(r'arn:[a-z0-9-]+:firehose:[a-z0-9-]+:\d{12}:deliverystream/[^{}\s]+', endpoint):
        return 'NEEDS_REVIEW'
    path = '/properties/Policies'
    policies = value(ctx, role, path)
    if not isinstance(policies, list):
        return 'NEEDS_REVIEW'
    allowed, pending = False, False
    for i in range(len(policies)):
        doc_path = path + '/' + str(i) + '/PolicyDocument'
        body = value(ctx, role, doc_path)
        if any(r.source_resource_id == role.id and r.source_path.startswith(doc_path + '/') for r in ctx.design.relations):
            pending = True
            continue
        try:
            if isinstance(body, str):
                body = json.loads(body, object_pairs_hook=unique_object) if len(body) <= 65536 else None
            if not isinstance(body, dict) or unresolved(body):
                pending = True
                continue
        except (ValueError, TypeError, RecursionError):
            pending = True
            continue
        statements = body.get('Statement')
        statements = [statements] if isinstance(statements, dict) else statements
        if not isinstance(statements, list):
            pending = True
            continue
        for statement in statements:
            if not isinstance(statement, dict) or any(k in statement for k in ('Condition','NotAction','NotResource','Principal','NotPrincipal')):
                pending = True
                continue
            actions, resources = statement.get('Action'), statement.get('Resource')
            actions = [actions] if isinstance(actions, str) else actions
            resources = [resources] if isinstance(resources, str) else resources
            effect = statement.get('Effect')
            if effect not in ('Allow','Deny') or not isinstance(actions, list) or not isinstance(resources, list) or not all(isinstance(x,str) for x in actions + resources):
                pending = True
                continue
            known_action = any(a.lower() in ('firehose:putrecord','firehose:*','*') for a in actions)
            known_resource = any(r in (endpoint,'*') for r in resources)
            if known_action and known_resource:
                if effect == 'Deny':
                    return 'FAIL'
                allowed = True
            elif any('*' in a or '?' in a for a in actions) or any('*' in r or '?' in r for r in resources):
                pending = True
    return 'PASS' if allowed and not pending else 'NEEDS_REVIEW'
