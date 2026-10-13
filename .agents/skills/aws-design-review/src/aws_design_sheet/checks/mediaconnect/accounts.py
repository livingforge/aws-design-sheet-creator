"""Checks for AWS::MediaConnect::Flow, AWS::MediaConnect::FlowEntitlement."""
import re
from ..registry import resource_check
from ..common.account_ids import account_id
from ..common.context_values import _Context, linked, value
from ..common.literals import expand, known_scope, literal

ACCOUNTS='https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-identifiers.html'
CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'MEDIACONNECT_SUBSCRIBER_ACCOUNTS': [CF+'aws-resource-mediaconnect-flowentitlement.html',ACCOUNTS],
    'MEDIACONNECT_FLOW_SUBNET_AZ': [CF+'aws-properties-mediaconnect-flow-vpcinterface.html'],
}


def subnet_az(ctx,resource,path):
    if not known_scope(resource):return 'NEEDS_REVIEW'
    if resource.template is not None and resource.template.state.value!='KNOWN':return 'NEEDS_REVIEW'
    subnet=linked(ctx,resource,path,'AWS::EC2::Subnet')
    if subnet is None or not known_scope(subnet) or subnet.template is not None and subnet.template.state.value!='KNOWN':return 'NEEDS_REVIEW'
    flow_az=value(ctx,resource,'/properties/AvailabilityZone')
    subnet_az=value(ctx,subnet,'/properties/AvailabilityZone')
    # AZ names are comparable only within the account/Region enforced by linked.
    pattern=re.escape(resource.scope.region)+r'[a-z]'
    if not all(literal(az) and re.fullmatch(pattern,az) for az in (flow_az,subnet_az)):return 'NEEDS_REVIEW'
    return 'PASS' if flow_az==subnet_az else 'FAIL'


def _emitter(ctx,results):
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    return emit


def _accounts(ctx,resource,emit,rule,pattern):
    for path in expand(ctx,resource,pattern):
        emit(rule,path,account_id(value(ctx,resource,path)),'literal account identifier must contain twelve ASCII digits; unknown/dynamic values, account existence, permissions and external filtering principal semantics remain held')


@resource_check('AWS::MediaConnect::FlowEntitlement','AWS::MediaConnect::Flow')
def evaluate_mediaconnect_accounts(design,resource):
    ctx=_Context(design,resource)
    results=[]
    emit=_emitter(ctx,results)
    if resource.type=='AWS::MediaConnect::FlowEntitlement':
        _accounts(ctx,resource,emit,'MEDIACONNECT_SUBSCRIBER_ACCOUNTS','/properties/Subscribers/*')
    if resource.type=='AWS::MediaConnect::Flow':
        for path in expand(ctx,resource,'/properties/VpcInterfaces/*/SubnetId'):
            emit('MEDIACONNECT_FLOW_SUBNET_AZ',path,subnet_az(ctx,resource,path),'uniquely linked same-account/Region subnet and flow must have equal explicit ordinary AZ names; omitted placement, AZ IDs, local zones, external/conditional links and deployed availability remain held')
    return results
