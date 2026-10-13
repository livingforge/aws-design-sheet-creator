"""Checks for AWS::DataZone::Environment."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, UNKNOWN
from ..common.literals import literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'DATAZONE_BLUEPRINT_DOMAIN_VERSION': [CF+'aws-resource-datazone-environment.html', CF+'aws-resource-datazone-domain.html'],
}


@resource_check('AWS::DataZone::Environment')
def evaluate_datazone_blueprint_domain_version(design, resource):
    ctx = _Context(design, resource)
    results = []
    def get(p):
        return value(ctx, resource, p)
    def emit(rule, p, verdict, reason):
        f = ctx.finding(rule, p, verdict, reason)
        f['source_checked_at'] = '2026-10-04'
        results.append(f)
    if resource.type == 'AWS::DataZone::Environment':
        p = '/properties/EnvironmentBlueprintIdentifier'
        raw = get(p)
        if raw is not ABSENT:
            domain = linked(ctx,resource,'/properties/DomainIdentifier','AWS::DataZone::Domain')
            version = value(ctx,domain,'/properties/DomainVersion') if domain else UNKNOWN
            verdict = 'NEEDS_REVIEW' if not literal(raw) or version not in ('V1','V2') else 'PASS' if version=='V1' else 'FAIL'
            emit('DATAZONE_BLUEPRINT_DOMAIN_VERSION', p, verdict, 'explicit blueprint identifier requires linked V1 domain; unknown identifier/version, defaults and external domains remain held')
    return results
