"""Checks for AWS::IAM::Policy."""
import json
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT, UNKNOWN
from ..common.required_values import uncertain

SOURCES = {
    'IAM_IDENTITY_STATEMENT_STRUCTURE': ['https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html'],
}


@resource_check('AWS::IAM::Policy')
def evaluate_iam_identity_statement_structure(design, resource):
    ctx = _Context(design, resource)
    path = '/properties/PolicyDocument'
    policy = value(ctx, resource, path)
    if isinstance(policy, str) and not uncertain(policy):
        try:
            policy = json.loads(policy)
        except (ValueError, RecursionError):
            policy = UNKNOWN
    rule = 'IAM_IDENTITY_STATEMENT_STRUCTURE'
    reason = 'each identity statement needs Effect and exactly one Action/NotAction and Resource/NotResource; service action/resource/condition semantics remain outside this check'
    if not isinstance(policy, dict) or '$state' in policy or '$ref' in policy:
        return [ctx.finding(rule, path, 'NEEDS_REVIEW', reason)]
    statements = policy.get('Statement', ABSENT)
    if isinstance(statements, dict) and '$state' not in statements and '$ref' not in statements:
        statements = [statements]
    if not isinstance(statements, list):
        return [ctx.finding(rule, path + '/Statement', 'FAIL' if statements is ABSENT else 'NEEDS_REVIEW', reason)]
    if not statements:
        return [ctx.finding(rule, path + '/Statement', 'FAIL', reason)]
    rows = []
    for i, statement in enumerate(statements):
        if not isinstance(statement, dict) or '$state' in statement or '$ref' in statement:
            verdict = 'NEEDS_REVIEW'
        else:
            effect = statement.get('Effect', ABSENT)
            invalid = effect is ABSENT or (isinstance(effect, str) and not uncertain(effect) and effect not in ('Allow', 'Deny'))
            unknown = effect not in ('Allow', 'Deny') and not invalid
            for pair in (('Action', 'NotAction'), ('Resource', 'NotResource')):
                supplied = [key for key in pair if key in statement]
                invalid |= len(supplied) != 1
                if len(supplied) == 1:
                    v = statement[supplied[0]]
                    unknown |= not (isinstance(v, str) and bool(v) and not uncertain(v) or
                                    isinstance(v, list) and bool(v) and all(isinstance(s, str) and bool(s) and not uncertain(s) for s in v))
            verdict = 'FAIL' if invalid else 'NEEDS_REVIEW' if unknown else 'PASS'
        rows.append(ctx.finding(rule, path + f'/Statement/{i}', verdict, reason))
    return rows
