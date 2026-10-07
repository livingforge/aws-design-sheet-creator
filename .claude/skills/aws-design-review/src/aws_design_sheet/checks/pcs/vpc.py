"""Checks for AWS::PCS::ComputeNodeGroup."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, read
from ..common.logical_vpc_identity import identity
from ..common.scoped_resolution import resolved
from ..common.subnet_zones import explicit

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={'PCS_COMPUTE_CLUSTER_VPC':[CF+'aws-resource-pcs-computenodegroup.html',CF+'aws-properties-pcs-cluster-networking.html']}


def subnets(ctx,r,path):
    raw=value(ctx,r,path)
    if not isinstance(raw,list) or not 1<=len(raw)<=100:return [None]
    return [explicit(ctx,r,path+'/'+str(i),'AWS::EC2::Subnet') for i in range(len(raw))]


def placement(ctx,r):
    if not resolved(r) or read(ctx,r,'/properties/ClusterId') is not ABSENT:return 'NEEDS_REVIEW'
    cluster=linked(ctx,r,'/properties/ClusterId','AWS::PCS::Cluster')
    if not resolved(cluster):return 'NEEDS_REVIEW'
    nodes=subnets(ctx,r,'/properties/SubnetIds')
    controls=subnets(ctx,cluster,'/properties/Networking/SubnetIds')
    identities=[identity(ctx,s) for s in nodes+controls]
    known=[v for v in identities if v is not None]
    if any(a[0]==b[0] and a!=b for a in known for b in known):return 'FAIL'
    return 'PASS' if len(known)==len(identities) and len(set(known))==1 else 'NEEDS_REVIEW'


@resource_check('AWS::PCS::ComputeNodeGroup')
def evaluate_pcs_vpc(design,resource):
    if resource.type!='AWS::PCS::ComputeNodeGroup':return []
    ctx=_Context(design,resource)
    f=ctx.finding('PCS_COMPUTE_CLUSTER_VPC','/properties/SubnetIds',placement(ctx,resource),'Compute-node and cluster control-plane subnets must share a VPC. Compare all explicit resolved subnet relationships in the same scope. Missing, conditional, ambiguous, mixed logical/physical identities and external topology remain reviewable. PASS covers declared VPC placement only, not availability, IP capacity or connectivity.')
    f['source_checked_at']='2026-10-04';return [f]
