"""Explicit serialization of Security Lake sources in one template and scope."""
from ..registry import resource_check
from ..common.account_order import sequential
from ..common.context_values import _Context

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={'SECURITYLAKE_SOURCE_SEQUENTIAL':[CF+'aws-resource-securitylake-awslogsource.html',CF+'aws-resource-securitylake-datalake.html',CF+'aws-attribute-dependson.html']}


@resource_check('AWS::SecurityLake::AwsLogSource')
def evaluate_securitylake_source_order(design,resource):
    if resource.type!='AWS::SecurityLake::AwsLogSource':return []
    ctx=_Context(design,resource)
    f=ctx.finding('SECURITYLAKE_SOURCE_SEQUENTIAL','/template/depends_on',sequential(ctx,resource),'Multiple AwsLogSource resources in one explicit template and scope require sequential DependsOn ordering. Every pair must be ordered, including transitive paths; a shared predecessor does not serialize siblings. Cycles fail and incomplete graphs remain reviewable. PASS covers local template order only; cross-Region and cross-stack orchestration remains separate.')
    f['source_checked_at']='2026-10-04';return [f]
