"""Checks for AWS::LakeFormation::DataLakeSettings."""
from ..registry import resource_check
from ..common.account_ids import account_id
from ..common.context_values import _Context, value
from ..common.literals import expand

ACCOUNTS='https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-identifiers.html'
CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'LAKEFORMATION_TRUSTED_ACCOUNTS': [CF+'aws-resource-lakeformation-datalakesettings.html',ACCOUNTS],
}


def _emitter(ctx,results):
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    return emit


def _accounts(ctx,resource,emit,rule,pattern):
    for path in expand(ctx,resource,pattern):
        emit(rule,path,account_id(value(ctx,resource,path)),'literal account identifier must contain twelve ASCII digits; unknown/dynamic values, account existence, permissions and external filtering principal semantics remain held')


@resource_check('AWS::LakeFormation::DataLakeSettings')
def evaluate_lakeformation_trusted_accounts(design,resource):
    ctx=_Context(design,resource)
    results=[]
    emit=_emitter(ctx,results)
    _accounts(ctx,resource,emit,'LAKEFORMATION_TRUSTED_ACCOUNTS','/properties/TrustedResourceOwners/*')
    return results
