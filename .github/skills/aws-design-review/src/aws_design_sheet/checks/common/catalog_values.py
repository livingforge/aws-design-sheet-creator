"""Shared value rules for Service Catalog and Pinpoint sandbox checks."""
from .context_values import _Context, value
from .field_reads import ABSENT
from .literals import literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={
 'SERVICECATALOG_SOURCE_CONNECTION_TYPE':[CF+'aws-properties-servicecatalog-cloudformationproduct-sourceconnection.html','https://docs.aws.amazon.com/servicecatalog/latest/dg/API_SourceConnection.html'],
 'PINPOINT_APNS_VOIP_SANDBOX_AUTH_METHOD':[CF+'aws-resource-pinpoint-apnsvoipsandboxchannel.html'],
}
SPECS={
 'AWS::ServiceCatalog::CloudFormationProduct':('SERVICECATALOG_SOURCE_CONNECTION_TYPE','/properties/SourceConnection/Type',('CODESTAR',),'connection parameters, authorization and repository availability remain held'),
 'AWS::Pinpoint::APNSVoipSandboxChannel':('PINPOINT_APNS_VOIP_SANDBOX_AUTH_METHOD','/properties/DefaultAuthenticationMethod',('key','certificate'),'credential requiredness/validity and actual delivery remain held'),
}


def catalog_value(design,resource):
    spec=SPECS.get(resource.type)
    if spec is None:return []
    rule,path,allowed,residual=spec
    ctx=_Context(design,resource);raw=value(ctx,resource,path)
    if raw is ABSENT:return []
    verdict='NEEDS_REVIEW' if not literal(raw) else 'PASS' if raw in allowed else 'FAIL'
    f=ctx.finding(rule,path,verdict,'explicit documented values only; unknown/default values and '+residual)
    f['source_checked_at']='2026-10-04'
    return [f]
