"""Checks for AWS::MediaConnect::FlowVpcInterface."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import literal
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'MEDIACONNECT_INTERFACE_FLOW_AZ': [CF+'aws-resource-mediaconnect-flowvpcinterface.html'],
}


def interface_az(ctx,resource):
    if not resolved(resource):return 'NEEDS_REVIEW'
    flow=linked(ctx,resource,'/properties/FlowArn','AWS::MediaConnect::Flow')
    subnet=linked(ctx,resource,'/properties/SubnetId','AWS::EC2::Subnet')
    if not resolved(flow) or not resolved(subnet):return 'NEEDS_REVIEW'
    azs=[value(ctx,r,'/properties/AvailabilityZone') for r in (flow,subnet)]
    if not all(literal(az) and re.fullmatch(re.escape(resource.scope.region)+r'[a-z]',az) for az in azs):return 'NEEDS_REVIEW'
    return 'PASS' if azs[0]==azs[1] else 'FAIL'


@resource_check('AWS::MediaConnect::FlowVpcInterface')
def evaluate_mediaconnect_interface_flow_az(design,resource):
    ctx=_Context(design,resource)
    results=[]
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    if resource.type=='AWS::MediaConnect::FlowVpcInterface':
        path='/properties/SubnetId'
        if value(ctx,resource,path) is not ABSENT:
            emit('MEDIACONNECT_INTERFACE_FLOW_AZ',path,interface_az(ctx,resource),'unique same-account/Region flow and subnet links must have equal explicit ordinary AZ names; omitted placement, AZ IDs, local zones, other interfaces, deployment sequence and actual availability remain held')
    return results
