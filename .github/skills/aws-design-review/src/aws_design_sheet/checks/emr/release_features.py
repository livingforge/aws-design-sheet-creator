"""Documented EMR release gates, retaining ambiguous/deprecated behavior for review."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT, UNKNOWN
from ..common.literals import expand
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={rule:[CF+'aws-resource-emr-cluster.html',CF+'aws-properties-emr-cluster-jobflowinstancesconfig.html',CF+'aws-properties-emr-cluster-ondemandprovisioningspecification.html',CF+'aws-properties-emr-cluster-placementgroupconfig.html','https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-scaledown-behavior.html'] for rule in ('EMR_RELEASE_FEATURE_AVAILABILITY','EMR_PLACEMENT_ROLE_STRATEGY')}


def release(ctx,r):
    raw=value(ctx,r,'/properties/ReleaseLabel')
    if not resolved(r) or not isinstance(raw,str):return None
    match=re.fullmatch(r'emr-([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})',raw)
    version=tuple(map(int,match.groups())) if match else None
    # ReleaseLabel only represents 4.0+; do not infer an old AMI release from omission.
    return version if version and version>=(4,0,0) else None


@resource_check('AWS::EMR::Cluster')
def evaluate_emr_release_features(design,resource):
    if resource.type!='AWS::EMR::Cluster':return []
    ctx=_Context(design,resource);v=release(ctx,resource);out=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason+' Exact explicit release labels only; unknown/legacy AMI releases remain reviewable. PASS concerns this version gate only, not release availability or full configuration validity.')
        f['source_checked_at']='2026-10-04';out.append(f)
    def gate(path,allowed,shape=None):
        raw=value(ctx,resource,path)
        if raw is ABSENT or raw==[]:return
        verdict='NEEDS_REVIEW' if v is None or raw is UNKNOWN or (shape and not isinstance(raw,shape)) else 'PASS' if allowed(v) else 'FAIL'
        emit('EMR_RELEASE_FEATURE_AVAILABILITY',path,verdict,'EMR feature is restricted to its documented release range.')
    gate('/properties/Configurations',lambda v:v>=(4,0,0),list)
    gate('/properties/Instances/HadoopVersion',lambda v:v<(4,0,0),str)
    for pattern in ('/properties/Instances/MasterInstanceFleet','/properties/Instances/CoreInstanceFleet','/properties/Instances/TaskInstanceFleets/*'):
        for path in expand(ctx,resource,pattern):
            if path.count('/')!=pattern.count('/'):
                emit('EMR_RELEASE_FEATURE_AVAILABILITY',path,'NEEDS_REVIEW','Fleet container is unresolved.');continue
            gate(path,lambda v:v>=(4,8,0) and v[:2]!=(5,0),dict)
            gate(path+'/LaunchSpecifications/OnDemandSpecification/AllocationStrategy',lambda v:v>=(5,12,1),str)
    path='/properties/ScaleDownBehavior';raw=value(ctx,resource,path)
    if raw is not ABSENT:
        minimum={'TERMINATE_AT_TASK_COMPLETION':(4,1,0),'TERMINATE_AT_INSTANCE_HOUR':(5,1,0)}.get(raw) if isinstance(raw,str) else None
        verdict='NEEDS_REVIEW'
        if v and minimum and v<(5,10,0):verdict='PASS' if v>=minimum else 'FAIL'
        emit('EMR_RELEASE_FEATURE_AVAILABILITY',path,verdict,'CFN states minimum versions, but the management guide deprecates scale-down options from 5.10.0. At 5.10.0+ the parameter acceptance/ignored behavior remains unresolved rather than assuming deployment failure.')
    pattern='/properties/PlacementGroupConfigs/*'
    for path in expand(ctx,resource,pattern):
        verdict='NEEDS_REVIEW'
        if path.count('/')==pattern.count('/') and v and v>=(5,23,0):
            role=value(ctx,resource,path+'/InstanceRole');strategy=value(ctx,resource,path+'/PlacementStrategy')
            if role in ('CORE','TASK') or strategy in ('PARTITION','CLUSTER'):verdict='FAIL'
            elif role=='MASTER' and strategy=='SPREAD':verdict='PASS'
        emit('EMR_PLACEMENT_ROLE_STRATEGY',path,verdict,'From 5.23.0 the documented supported role/strategy is MASTER/SPREAD. Earlier releases, omitted strategy and NONE semantics are not established by this source.')
    return out
