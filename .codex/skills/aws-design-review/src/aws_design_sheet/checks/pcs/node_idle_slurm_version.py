"""Checks for AWS::PCS::ComputeNodeGroup."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import literal
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'PCS_NODE_IDLE_SLURM_VERSION': [CF+'aws-properties-pcs-computenodegroup-slurmconfiguration.html'],
}


def slurm_version(ctx,resource):
    raw=value(ctx,resource,'/properties/SlurmConfiguration/ScaleDownIdleTimeInSeconds')
    if not resolved(resource) or type(raw) is not int or not 1<=raw<=10000000:return 'NEEDS_REVIEW'
    cluster=linked(ctx,resource,'/properties/ClusterId','AWS::PCS::Cluster')
    if not resolved(cluster) or value(ctx,cluster,'/properties/Scheduler/Type')!='SLURM':return 'NEEDS_REVIEW'
    version=value(ctx,cluster,'/properties/Scheduler/Version')
    if not literal(version) or not re.fullmatch(r'[0-9]{2}\.[0-9]{2}',version):return 'NEEDS_REVIEW'
    return 'PASS' if tuple(map(int,version.split('.')))>=(25,11) else 'FAIL'


@resource_check('AWS::PCS::ComputeNodeGroup')
def evaluate_pcs_node_idle_slurm_version(design,resource):
    ctx=_Context(design,resource)
    results=[]
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    if resource.type=='AWS::PCS::ComputeNodeGroup' and value(ctx,resource,'/properties/SlurmConfiguration/ScaleDownIdleTimeInSeconds') is not ABSENT:
        emit('PCS_NODE_IDLE_SLURM_VERSION','/properties/SlurmConfiguration/ScaleDownIdleTimeInSeconds',slurm_version(ctx,resource),'explicit valid idle setting requires unique linked SLURM cluster with canonical version at least 25.11; unknown/default/noncanonical versions, lifecycle support and actual cluster state remain held')
    return results
