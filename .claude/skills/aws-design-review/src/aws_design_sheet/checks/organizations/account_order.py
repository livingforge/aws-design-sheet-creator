"""Checks for AWS::Organizations::Account."""
from ..registry import resource_check
from ..common.account_order import sequential
from ..common.context_values import _Context

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={'ORGANIZATIONS_ACCOUNT_SEQUENTIAL_CREATION':[CF+'aws-resource-organizations-account.html',CF+'aws-attribute-dependson.html']}


@resource_check('AWS::Organizations::Account')
def evaluate_organizations_account_order(design,resource):
    if resource.type!='AWS::Organizations::Account':return []
    ctx=_Context(design,resource)
    f=ctx.finding('ORGANIZATIONS_ACCOUNT_SEQUENTIAL_CREATION','/template/depends_on',sequential(ctx,resource),'Multiple Organizations accounts in one explicit template must be ordered sequentially using DependsOn. Verify a total order across every account pair, including transitive explicit dependencies; a fork is insufficient. Cycles and complete unordered graphs fail. Unknown membership/dependencies and ordering established only through implicit references remain reviewable. PASS does not certify live account readiness or quotas.')
    f['source_checked_at']='2026-10-04';return [f]
