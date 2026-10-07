"""Checks for AWS::MSK::Cluster."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import literal
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'MSK_CLIENT_SUBNET_DISTINCT_AZS': [CF+'aws-properties-msk-cluster-brokernodegroupinfo.html'],
}


def distinct_zones(ctx,resource):
    if not resolved(resource):return 'NEEDS_REVIEW'
    base='/properties/BrokerNodeGroupInfo/ClientSubnets'
    ids=value(ctx,resource,base)
    if not isinstance(ids,list) or not ids or len(ids)>1000:return 'NEEDS_REVIEW'
    pending=False
    duplicate=False
    zones=set()
    for i in range(len(ids)):
        subnet=linked(ctx,resource,base+'/'+str(i),'AWS::EC2::Subnet')
        if not resolved(subnet):
            pending=True
            continue
        az=value(ctx,subnet,'/properties/AvailabilityZone')
        if not literal(az) or not re.fullmatch(re.escape(resource.scope.region)+r'[a-z]',az):
            pending=True
            continue
        if az in zones:duplicate=True
        zones.add(az)
    return 'FAIL' if duplicate else 'NEEDS_REVIEW' if pending else 'PASS'


@resource_check('AWS::MSK::Cluster')
def evaluate_msk_client_subnet_distinct_azs(design,resource):
    ctx=_Context(design,resource)
    results=[]
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    if resource.type=='AWS::MSK::Cluster' and value(ctx,resource,'/properties/BrokerNodeGroupInfo/ClientSubnets') is not ABSENT:
        emit('MSK_CLIENT_SUBNET_DISTINCT_AZS','/properties/BrokerNodeGroupInfo/ClientSubnets',distinct_zones(ctx,resource),'explicit ordinary AZ names of unique linked same-account/Region subnets must be distinct; unknown/default placement, AZ IDs including use1-az3 exclusion, California subnet count and regional availability remain held')
    return results
