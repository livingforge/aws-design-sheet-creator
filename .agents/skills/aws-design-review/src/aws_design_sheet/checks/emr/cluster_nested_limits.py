"""Checks for AWS::EMR::Cluster."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, literal
from ..common.unique_strings import unique_strings

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'EMR_CLUSTER_NESTED_LIMITS': [CF+'aws-properties-emr-cluster-'+p+'.html' for p in ('spotprovisioningspecification','spotresizingspecification','ondemandresizingspecification','volumespecification','scalingrule')],
}


@resource_check('AWS::EMR::Cluster')
def evaluate_emr_cluster_nested_limits(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(p):return value(ctx,resource,p)
    def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
    if resource.type=='AWS::EMR::Cluster':
        root='/properties/Instances/'
        fleets=[root+'MasterInstanceFleet',root+'CoreInstanceFleet',root+'TaskInstanceFleets/*']
        groups=[root+'MasterInstanceGroup',root+'CoreInstanceGroup',root+'TaskInstanceGroups/*']
        volumes=[]
        for pattern in fleets:
            for base in expand(ctx,resource,pattern):
                volumes.append(base+'/InstanceTypeConfigs/*/EbsConfiguration/EbsBlockDeviceConfigs/*/VolumeSpecification')
                for suffix,maximum in [('LaunchSpecifications/SpotSpecification/TimeoutDurationMinutes',1440),('ResizeSpecifications/SpotResizeSpecification/TimeoutDurationMinutes',10080),('ResizeSpecifications/OnDemandResizeSpecification/TimeoutDurationMinutes',10080)]:
                    p=base+'/'+suffix;raw=get(p)
                    if raw is not ABSENT:emit('EMR_CLUSTER_NESTED_LIMITS',p,'NEEDS_REVIEW' if type(raw) is not int else 'PASS' if 5<=raw<=maximum else 'FAIL','explicit nested fleet timeout uses documented inclusive bounds; omitted/unknown values and live provisioning held')
        for pattern in groups:
            for base in expand(ctx,resource,pattern):
                volumes.append(base+'/EbsConfiguration/EbsBlockDeviceConfigs/*/VolumeSpecification')
                p=base+'/AutoScalingPolicy/Rules'
                if get(p) is not ABSENT:emit('EMR_CLUSTER_NESTED_LIMITS',p,unique_strings(ctx,resource,p+'/*/Name'),'explicit scaling rule names are unique within one nested group policy; unknown names held; ignored Market warning remains separate')
        for pattern in volumes:
            for base in expand(ctx,resource,pattern):
                p=base+'/Throughput';raw=get(p);kind=get(base+'/VolumeType')
                if raw is not ABSENT:emit('EMR_CLUSTER_NESTED_LIMITS',p,'NEEDS_REVIEW' if not literal(kind) else 'PASS' if kind=='gp3' else 'FAIL','explicit nested Throughput property is only valid for gp3; actual throughput range and EC2 availability separate')
    return results
