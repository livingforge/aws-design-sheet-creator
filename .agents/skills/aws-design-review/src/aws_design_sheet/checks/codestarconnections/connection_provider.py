"""Checks for AWS::CodeStarConnections::Connection."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'CODESTAR_CONNECTION_PROVIDER': [CF+'aws-resource-codestarconnections-connection.html'],
}


@resource_check('AWS::CodeStarConnections::Connection')
def evaluate_codestarconnections_connection_provider(design, resource):
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

    if resource.type == 'AWS::CodeStarConnections::Connection':
        enum('CODESTAR_CONNECTION_PROVIDER', '/properties/ProviderType', ('Bitbucket', 'GitHub', 'GitHubEnterpriseServer', 'GitLab', 'GitLabSelfManaged'))
    return results
