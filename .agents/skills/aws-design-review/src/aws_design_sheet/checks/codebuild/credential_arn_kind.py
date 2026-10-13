"""Checks for AWS::CodeBuild::SourceCredential."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'CODEBUILD_CREDENTIAL_ARN_KIND': [CF+'aws-resource-codebuild-sourcecredential.html', 'https://docs.aws.amazon.com/dtconsole/latest/userguide/rename.html'],
}


def _emitter(ctx, results):
    def emit(rule, path, verdict, reason):
        finding = ctx.finding(rule, path, verdict, reason)
        finding['source_checked_at'] = '2026-10-04'
        results.append(finding)
    return emit


@resource_check('AWS::CodeBuild::SourceCredential')
def evaluate_codebuild_credential_arn_kind(design, resource):
    ctx = _Context(design, resource)
    results = []
    emit = _emitter(ctx, results)
    auth = value(ctx,resource,'/properties/AuthType')
    path = '/properties/Token'
    token = value(ctx,resource,path)
    if auth in ('CODECONNECTIONS','SECRETS_MANAGER') and token is not ABSENT:
        match = re.fullmatch(r'arn:aws(?:-[a-z0-9-]+)?:([a-z0-9-]+):[a-z0-9-]+:[0-9]{12}:(.+)',token) if literal(token) else None
        expected = bool(match and ((auth=='CODECONNECTIONS' and match[1] in ('codeconnections','codestar-connections') and match[2].startswith('connection/') and len(match[2])>11) or (auth=='SECRETS_MANAGER' and match[1]=='secretsmanager' and match[2].startswith('secret:') and len(match[2])>7)))
        emit('CODEBUILD_CREDENTIAL_ARN_KIND',path,'NEEDS_REVIEW' if not literal(token) else 'PASS' if expected else 'FAIL','explicit credential ARN service/resource kind only; secret values are never included in findings; existence, permissions and remaining ARN syntax stay separate')
    return results
