"""Checks for AWS::Forecast::Dataset."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'FORECAST_ENCRYPTION_ROLE_ACCOUNT': [CF+'aws-properties-forecast-dataset-encryptionconfig.html'],
}


@resource_check('AWS::Forecast::Dataset')
def evaluate_forecast_encryption_role_account(design,resource):
    ctx=_Context(design,resource)
    results=[]
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    if resource.type=='AWS::Forecast::Dataset':
        path='/properties/EncryptionConfig/RoleArn'
        raw=value(ctx,resource,path)
        if raw is not ABSENT:
            match=re.fullmatch(r'arn:aws(?:-[a-z0-9]+)*:iam::([0-9]{12}):role/[A-Za-z0-9_+=,.@/-]+',raw) if literal(raw) else None
            verdict='NEEDS_REVIEW' if not match or not re.fullmatch(r'[0-9]{12}',resource.scope.account) else 'PASS' if match[1]==resource.scope.account else 'FAIL'
            emit('FORECAST_ENCRYPTION_ROLE_ACCOUNT',path,verdict,'explicit role ARN account must match deployment account; Forecast account eligibility, role existence, trust and KMS permissions remain external')
    return results
