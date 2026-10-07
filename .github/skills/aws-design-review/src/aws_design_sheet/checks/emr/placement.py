"""Checks for AWS::EMR::InstanceFleetConfig, AWS::EMR::InstanceGroupConfig."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'EMR_FLEET_CLUSTER_MODE': [CF+'aws-resource-emr-instancefleetconfig.html'],
    'EMR_GROUP_CLUSTER_MODE': [CF+'aws-resource-emr-instancegroupconfig.html'],
}


def cluster_mode(ctx,resource,path,fleet):
    cluster = linked(ctx,resource,path,'AWS::EMR::Cluster')
    if cluster is None:
        return 'NEEDS_REVIEW'
    def fields(suffix):
        return [value(ctx,cluster,'/properties/Instances/'+role+'Instance'+suffix) for role in ('Master','Core','Task')]
    def present(raw):
        return isinstance(raw,(dict,list)) and bool(raw)
    same = fields('Fleet' if fleet else 'Group')
    opposite = fields('Group' if fleet else 'Fleet')
    # Task collections have plural property names.
    same[2] = value(ctx,cluster,'/properties/Instances/TaskInstance'+('Fleets' if fleet else 'Groups'))
    opposite[2] = value(ctx,cluster,'/properties/Instances/TaskInstance'+('Groups' if fleet else 'Fleets'))
    if any(present(raw) for raw in opposite):
        return 'FAIL'
    if any(present(raw) for raw in same) and all(raw is ABSENT or raw==[] for raw in opposite):
        return 'PASS'
    return 'NEEDS_REVIEW'


@resource_check('AWS::EMR::InstanceFleetConfig', 'AWS::EMR::InstanceGroupConfig')
def evaluate_emr_placement(design,resource):
    ctx = _Context(design,resource)
    results = []
    def emit(rule,path,verdict,reason):
        finding = ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at'] = '2026-10-04'
        results.append(finding)
    if resource.type in ('AWS::EMR::InstanceFleetConfig','AWS::EMR::InstanceGroupConfig'):
        fleet = resource.type.endswith('InstanceFleetConfig')
        path = '/properties/'+('ClusterId' if fleet else 'JobFlowId')
        emit('EMR_FLEET_CLUSTER_MODE' if fleet else 'EMR_GROUP_CLUSTER_MODE',path,cluster_mode(ctx,resource,path,fleet),'linked cluster cannot mix instance fleets and groups; only explicit nonempty configurations prove mode; release compatibility, external additions and other launch constraints remain held')
    return results
