"""Checks for AWS::AppRunner::Service."""
from urllib.parse import urlsplit
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'APPRUNNER_GITHUB_CONNECTION': [CF+'aws-properties-apprunner-service-authenticationconfiguration.html'],
    'APPRUNNER_OBSERVABILITY_REQUIRED': [CF+'aws-properties-apprunner-service-serviceobservabilityconfiguration.html'],
}


@resource_check('AWS::AppRunner::Service')
def evaluate_apprunner_service(design, resource):
    ctx = _Context(design, resource)
    results = []
    def get(path): return value(ctx, resource, path)
    def emit(rule, path, verdict, reason):
        results.append(ctx.finding(rule, path, verdict, reason))
    def enum(rule, path, choices):
        raw = get(path)
        if raw is not ABSENT:
            emit(rule, path, 'NEEDS_REVIEW' if not literal(raw) else 'PASS' if raw in choices else 'FAIL',
                 'explicit value compared with current documented allowed values; omitted and unresolved values are not inferred')
    def maximum(rule, path, limit):
        raw = get(path)
        if raw is not ABSENT:
            emit(rule, path, 'NEEDS_REVIEW' if not isinstance(raw, list) else 'PASS' if len(raw) <= limit else 'FAIL',
                 'explicit array length compared with documented maximum; member validity is separate')
    def required(rule, path, active):
        raw = get(path)
        verdict = 'NEEDS_REVIEW'
        if active:
            verdict = 'FAIL' if raw is ABSENT else 'PASS' if literal(raw) else 'NEEDS_REVIEW'
        emit(rule, path, verdict, 'checks presence only for an explicitly established triggering condition; credentials and resource existence remain external')

    if resource.type == 'AWS::AppRunner::Service':
        url = get('/properties/SourceConfiguration/CodeRepository/RepositoryUrl')
        if url is not ABSENT:
            github = False
            if literal(url):
                try:
                    parsed = urlsplit(url)
                    github = parsed.scheme == 'https' and parsed.hostname == 'github.com' and bool(parsed.path.strip('/')) and parsed.username is None and parsed.port in (None, 443)
                except ValueError: pass
            required('APPRUNNER_GITHUB_CONNECTION','/properties/SourceConfiguration/AuthenticationConfiguration/ConnectionArn',github)
        base = '/properties/ObservabilityConfiguration'
        if get(base) is not ABSENT:
            required('APPRUNNER_OBSERVABILITY_REQUIRED',base+'/ObservabilityConfigurationArn',get(base+'/ObservabilityEnabled') is True)
    return results
