"""Checks for AWS::Cognito::LogDeliveryConfiguration, AWS::Cognito::UserPoolClient."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, UNKNOWN
from ..common.literals import expand, literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'COGNITO_AUTH_LOG_TIER': [CF+'aws-properties-cognito-logdeliveryconfiguration-logconfiguration.html'],
    'COGNITO_USER_AUTH_TIER': [CF+'aws-resource-cognito-userpoolclient.html'],
}


@resource_check('AWS::Cognito::LogDeliveryConfiguration', 'AWS::Cognito::UserPoolClient')
def evaluate_cognito_deployment_identity(design, resource):
    ctx = _Context(design, resource)
    results = []

    def get(path):
        return value(ctx, resource, path)

    def emit(rule, path, verdict, reason):
        f = ctx.finding(rule, path, verdict, reason)
        f['source_checked_at'] = '2026-10-04'
        results.append(f)

    def enum(rule, path, allowed):
        raw = get(path)
        if raw is not ABSENT:
            emit(rule, path, 'NEEDS_REVIEW' if not literal(raw) else 'PASS' if raw in allowed else 'FAIL', 'checks documented literal values; external availability and applicability remain separate')

    if resource.type in ('AWS::Cognito::LogDeliveryConfiguration', 'AWS::Cognito::UserPoolClient'):
        pool = linked(ctx, resource, '/properties/UserPoolId', 'AWS::Cognito::UserPool')
        tier = value(ctx, pool, '/properties/UserPoolTier') if pool else UNKNOWN

        def tier_check(rule, path, allowed):
            verdict = 'NEEDS_REVIEW' if tier not in ('LITE', 'ESSENTIALS', 'PLUS') else 'PASS' if tier in allowed else 'FAIL'
            emit(rule, path, verdict, 'checks explicitly declared tier of a unique same-scope linked pool; omitted tier and external/current service state remain held')

        if resource.type == 'AWS::Cognito::LogDeliveryConfiguration':
            for p in expand(ctx, resource, '/properties/LogConfigurations/*/EventSource'):
                event = get(p)
                if event == 'userAuthEvents':
                    tier_check('COGNITO_AUTH_LOG_TIER', p, ('PLUS',))
                elif event is not ABSENT and not literal(event):
                    emit('COGNITO_AUTH_LOG_TIER', p, 'NEEDS_REVIEW', 'event source unresolved')
        else:
            p = '/properties/ExplicitAuthFlows'
            raw = get(p)
            if isinstance(raw, list):
                values = [get(p+'/'+str(i)) for i in range(len(raw))]
                if 'ALLOW_USER_AUTH' in values:
                    tier_check('COGNITO_USER_AUTH_TIER', p, ('ESSENTIALS', 'PLUS'))
                elif any(not literal(v) for v in values):
                    emit('COGNITO_USER_AUTH_TIER', p, 'NEEDS_REVIEW', 'authentication flow selection unresolved')
            elif raw is not ABSENT:
                emit('COGNITO_USER_AUTH_TIER', p, 'NEEDS_REVIEW', 'authentication flows unresolved')
    return results
