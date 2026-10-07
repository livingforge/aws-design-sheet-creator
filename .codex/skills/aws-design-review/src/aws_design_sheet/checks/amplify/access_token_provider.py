"""Checks for AWS::Amplify::App."""
import re
from urllib.parse import urlsplit
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'AMPLIFY_ACCESS_TOKEN_PROVIDER': [CF+'aws-resource-amplify-app.html'],
}


def amplify_provider(raw):
    if not literal(raw) or len(raw) > 8192:
        return 'NEEDS_REVIEW'
    try:
        url = urlsplit(raw)
        if url.scheme != 'https' or url.username or url.password or url.port not in (None,443) or not url.path.strip('/'):
            return 'NEEDS_REVIEW'
        host = url.hostname
        if host == 'github.com':
            return 'PASS'
        if host == 'bitbucket.org' or host == 'gitlab.com' or host and re.fullmatch(r'git-codecommit\.[a-z0-9-]+\.amazonaws\.com(?:\.cn)?', host):
            return 'FAIL'
    except ValueError:
        pass
    return 'NEEDS_REVIEW'


@resource_check('AWS::Amplify::App')
def evaluate_amplify_access_token_provider(design, resource):
    ctx = _Context(design, resource); results = []
    def emit(rule, path, verdict, reason):
        f = ctx.finding(rule, path, verdict, reason); f['source_checked_at'] = '2026-10-04'; results.append(f)
    if resource.type == 'AWS::Amplify::App':
        token = value(ctx, resource, '/properties/AccessToken')
        if token is not ABSENT:
            emit('AMPLIFY_ACCESS_TOKEN_PROVIDER', '/properties/Repository', amplify_provider(value(ctx, resource, '/properties/Repository')) if literal(token) else 'NEEDS_REVIEW', 'explicit access token is GitHub-only for recognized HTTPS repository hosts; token content is not emitted; legacy GitHub OAuth, SSH/custom hosts and missing/update credentials held')
    return results
