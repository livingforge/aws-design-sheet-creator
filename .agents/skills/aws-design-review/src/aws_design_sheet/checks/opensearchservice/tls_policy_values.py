"""Checks for AWS::OpenSearchService::Domain."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'OPENSEARCH_TLS_POLICY_VALUES': [CF+'aws-properties-opensearchservice-domain-domainendpointoptions.html'],
}
TLS=('Policy-Min-TLS-1-0-2019-07','Policy-Min-TLS-1-2-2019-07','Policy-Min-TLS-1-2-PFS-2023-10','Policy-Min-TLS-1-2-RFC9151-FIPS-2024-08')


@resource_check('AWS::OpenSearchService::Domain')
def evaluate_opensearchservice_tls_policy_values(design,resource):
    ctx=_Context(design,resource)
    results=[]
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    if resource.type=='AWS::OpenSearchService::Domain':
        path='/properties/DomainEndpointOptions/TLSSecurityPolicy'
        raw=value(ctx,resource,path)
        if raw is not ABSENT:
            emit('OPENSEARCH_TLS_POLICY_VALUES',path,'PASS' if raw in TLS else 'FAIL' if literal(raw) else 'NEEDS_REVIEW','explicit TLS policy must use a documented enum value; unknown/default policy, other missing domain enums, instance/engine/Region support and volume sizing remain held')
    return results
