"""Checks for AWS::Lambda::LayerVersionPermission."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT, UNKNOWN

SOURCES = {
    'LAMBDA_LAYER_ORGANIZATION_PRINCIPAL': [
        'https://docs.aws.amazon.com/lambda/latest/api/API_AddLayerVersionPermission.html',
        'https://docs.aws.amazon.com/lambda/latest/dg/permissions-layer-cross-account.html'],
}


def _unresolved(v):
    return v is UNKNOWN or (isinstance(v, str) and '{{resolve:' in v)


@resource_check('AWS::Lambda::LayerVersionPermission')
def evaluate_lambda_layer_organization_principal(design, resource):
    ctx = _Context(design, resource)
    organization = value(ctx, resource, '/properties/OrganizationId')
    if organization is ABSENT:
        return []
    path = '/properties/Principal'
    principal = value(ctx, resource, path)
    if _unresolved(organization) or not isinstance(organization, str) or not organization:
        verdict = 'NEEDS_REVIEW'
    elif not isinstance(principal, str) or _unresolved(principal):
        verdict = 'NEEDS_REVIEW'
    else:
        verdict = 'PASS' if principal == '*' else 'FAIL'
    return [{**ctx.finding('LAMBDA_LAYER_ORGANIZATION_PRINCIPAL', path, verdict,
        'documented organization-wide sharing uses Principal=*; an account-specific principal is narrower, but API rejection of that combination is not established'),
        'severity': 'WARNING'}]
