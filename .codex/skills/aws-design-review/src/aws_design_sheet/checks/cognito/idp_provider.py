"""Checks for AWS::Cognito::UserPoolIdentityProvider."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'COGNITO_IDP_PROVIDER': [CF+'aws-resource-cognito-userpoolidentityprovider.html'],
}


@resource_check('AWS::Cognito::UserPoolIdentityProvider')
def evaluate_cognito_idp_provider(design, resource):
    ctx = _Context(design, resource)
    results = []

    def emit(rule, path, verdict, reason):
        f = ctx.finding(rule, path, verdict, reason)
        f['source_checked_at'] = '2026-10-04'
        results.append(f)

    def enum(rule, path, allowed):
        raw = value(ctx, resource, path)
        if raw is not ABSENT:
            emit(rule, path, 'NEEDS_REVIEW' if not literal(raw) else 'PASS' if raw in allowed else 'FAIL', 'checks documented literal enum; conditional applicability, defaults and external service state remain separate')

    if resource.type == 'AWS::Cognito::UserPoolIdentityProvider':
        enum('COGNITO_IDP_PROVIDER', '/properties/ProviderType', ('SAML', 'Facebook', 'Google', 'LoginWithAmazon', 'SignInWithApple', 'OIDC'))
    return results
