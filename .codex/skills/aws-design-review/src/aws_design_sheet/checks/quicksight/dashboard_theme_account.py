"""Checks for AWS::QuickSight::Dashboard."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'QUICKSIGHT_DASHBOARD_THEME_ACCOUNT': [CF+'aws-resource-quicksight-dashboard.html'],
}


def theme_account(ctx,resource):
    raw=value(ctx,resource,'/properties/ThemeArn')
    account=value(ctx,resource,'/properties/AwsAccountId')
    if not resolved(resource) or not literal(raw) or not literal(account):return 'NEEDS_REVIEW'
    # Built-in themes with an empty account and unresolved ARN forms remain held.
    match=re.fullmatch(r'arn:[a-z0-9-]+:quicksight:[a-z0-9-]+:([0-9]{12}):theme/[A-Za-z0-9_-]+',raw)
    if not match or not re.fullmatch(r'[0-9]{12}',account):return 'NEEDS_REVIEW'
    return 'PASS' if match[1]==account else 'FAIL'


@resource_check('AWS::QuickSight::Dashboard')
def evaluate_quicksight_dashboard_theme_account(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict):
        finding=ctx.finding(rule,path,verdict,'explicit local constraint only; unknown/default values, unresolved targets, permissions and actual service/asset state remain held')
        finding['source_checked_at']='2026-10-04';results.append(finding)
    if resource.type=='AWS::QuickSight::Dashboard' and value(ctx,resource,'/properties/ThemeArn') is not ABSENT:
        emit('QUICKSIGHT_DASHBOARD_THEME_ACCOUNT','/properties/ThemeArn',theme_account(ctx,resource))
    return results
