"""Checks for AWS::PCAConnectorSCEP::Challenge."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'SCEP_CHALLENGE_GENERAL_CONNECTOR': [CF+'aws-resource-pcaconnectorscep-challenge.html',CF+'aws-resource-pcaconnectorscep-connector.html'],
}


def general_connector(ctx,resource):
    if not resolved(resource):return 'NEEDS_REVIEW'
    connector=linked(ctx,resource,'/properties/ConnectorArn','AWS::PCAConnectorSCEP::Connector')
    if not resolved(connector):return 'NEEDS_REVIEW'
    mdm=value(ctx,connector,'/properties/MobileDeviceManagement')
    if mdm is ABSENT:return 'PASS'
    if isinstance(mdm,dict) and isinstance(value(ctx,connector,'/properties/MobileDeviceManagement/Intune'),dict):return 'FAIL'
    return 'NEEDS_REVIEW'


@resource_check('AWS::PCAConnectorSCEP::Challenge')
def evaluate_pcaconnectorscep_challenge_connector(design,resource):
    ctx=_Context(design,resource)
    results=[]
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    if resource.type=='AWS::PCAConnectorSCEP::Challenge' and value(ctx,resource,'/properties/ConnectorArn') is not ABSENT:
        emit('SCEP_CHALLENGE_GENERAL_CONNECTOR','/properties/ConnectorArn',general_connector(ctx,resource),'challenge requires a general-purpose connector; known MDM omission is documented as general-purpose and explicit Intune configuration is incompatible; unknown/empty MDM, external connector and certificate/service state remain held')
    return results
