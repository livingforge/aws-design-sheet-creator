"""Syntax and locally decidable data-protection policy content."""
import json
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT, UNKNOWN
from ..common.json_constants import reject_constant
from .index_policy import index_policy
from .metric_policy import metric_policy_limits
from .policy_limits import account_policy_limits
from .processors import account_transformer_processors

URL = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-logs-accountpolicy.html'
SOURCES = {'LOGS_ACCOUNT_POLICY_JSON': [URL], 'LOGS_DATA_PROTECTION_BLOCKS': [URL]}


def protection_blocks(body):
    if not isinstance(body, dict) or not isinstance(body.get('Statement'), list):
        return 'FAIL'
    statements = body['Statement']
    actions = {'Audit': [], 'Deidentify': []}
    for statement in statements:
        if not isinstance(statement, dict) or not isinstance(statement.get('Operation'), dict):
            return 'FAIL'
        for action in actions:
            if action in statement['Operation']:
                actions[action].append(statement)
    if any(not group for group in actions.values()):
        return 'FAIL'
    if len(statements) != 2 or any(len(group) != 1 for group in actions.values()):
        return 'NEEDS_REVIEW'  # The two-block contract does not explain extra statements.
    audit, redact = actions['Audit'][0], actions['Deidentify'][0]
    if audit is redact:
        return 'FAIL'
    audit_config = audit['Operation']['Audit']
    redact_config = redact['Operation']['Deidentify']
    if not isinstance(audit_config, dict) or not isinstance(audit_config.get('FindingsDestination'), dict):
        return 'FAIL'
    if not isinstance(redact_config, dict) or redact_config.get('MaskConfig') != {}:
        return 'FAIL'
    left, right = audit.get('DataIdentifier'), redact.get('DataIdentifier')
    if not isinstance(left, list) or not isinstance(right, list):
        return 'FAIL'
    if not all(isinstance(v, str) for v in left + right):
        return 'NEEDS_REVIEW'
    if left == right:
        return 'PASS'
    return 'NEEDS_REVIEW' if sorted(left) == sorted(right) else 'FAIL'


@resource_check('AWS::Logs::AccountPolicy')
def logs_account_policy(design, resource):
    ctx = _Context(design, resource)
    limits = account_policy_limits(design, resource) + metric_policy_limits(design, resource)
    path = '/properties/PolicyDocument'
    raw = value(ctx, resource, path)
    if raw is ABSENT:
        return limits
    body = None
    duplicate_keys = False

    def policy_object(pairs):
        nonlocal duplicate_keys
        duplicate_keys |= len(pairs) != len(dict(pairs))
        return dict(pairs)

    verdict = 'NEEDS_REVIEW'
    if isinstance(raw, str) and '{{resolve:' not in raw:
        try:
            body = json.loads(raw, parse_constant=reject_constant, object_pairs_hook=policy_object)
            verdict = 'PASS'
        except (ValueError, RecursionError):
            verdict = 'FAIL'
    results = limits + [ctx.finding('LOGS_ACCOUNT_POLICY_JSON', path, verdict,
        'PolicyDocument must be valid JSON; unresolved substitutions require review')]
    if value(ctx, resource, '/properties/PolicyType') == 'TRANSFORMER_POLICY' and verdict == 'PASS':
        results.extend(account_transformer_processors(ctx, path, UNKNOWN if duplicate_keys else body))
    if value(ctx, resource, '/properties/PolicyType') == 'FIELD_INDEX_POLICY':
        results.extend(index_policy(ctx, path, body if verdict == 'PASS' and not duplicate_keys else UNKNOWN))
    if value(ctx, resource, '/properties/PolicyType') == 'DATA_PROTECTION_POLICY':
        verdict = protection_blocks(body) if verdict == 'PASS' else verdict
        results.append(ctx.finding('LOGS_DATA_PROTECTION_BLOCKS', path, verdict,
            'data protection requires Audit/FindingsDestination and Deidentify/empty MaskConfig with matching identifier arrays; destinations, identifiers and extra statements remain unverified'))
    return results
