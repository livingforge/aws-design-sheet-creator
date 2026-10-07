"""Checks for AWS::AutoScalingPlans::ScalingPlan."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'SCALINGPLAN_METRIC_UNIQUE': [CF+'aws-properties-autoscalingplans-scalingplan-scalinginstruction.html',CF+'aws-properties-autoscalingplans-scalingplan-predefinedscalingmetricspecification.html'],
    'SCALINGPLAN_ALB_SERVICE': [CF+'aws-properties-autoscalingplans-scalingplan-predefinedscalingmetricspecification.html'],
}
METRICS=('ASGAverageCPUUtilization','ASGAverageNetworkIn','ASGAverageNetworkOut','DynamoDBReadCapacityUtilization','DynamoDBWriteCapacityUtilization','ECSServiceAverageCPUUtilization','ECSServiceAverageMemoryUtilization','RDSReaderAverageCPUUtilization','RDSReaderAverageDatabaseConnections','EC2SpotFleetRequestAverageCPUUtilization','EC2SpotFleetRequestAverageNetworkIn','EC2SpotFleetRequestAverageNetworkOut')


def metric_identity(ctx,resource,path):
    base=path+'/PredefinedScalingMetricSpecification'
    if value(ctx,resource,path+'/CustomizedScalingMetricSpecification') is not ABSENT:return None
    kind=value(ctx,resource,base+'/PredefinedScalingMetricType');label=value(ctx,resource,base+'/ResourceLabel')
    if kind in METRICS and label is ABSENT:return (kind,)
    if kind=='ALBRequestCountPerTarget' and literal(label):return (kind,label)
    return None


def metric_unique(ctx,resource,path):
    raw=value(ctx,resource,path)
    if not isinstance(raw,list) or not raw:return 'NEEDS_REVIEW'
    seen=set();pending=False
    for i in range(len(raw)):
        identity=metric_identity(ctx,resource,path+'/'+str(i))
        if identity is None:pending=True;continue
        if identity in seen:return 'FAIL'
        seen.add(identity)
    return 'NEEDS_REVIEW' if pending else 'PASS'


@resource_check('AWS::AutoScalingPlans::ScalingPlan')
def evaluate_autoscalingplans_scaling_plan(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::AutoScalingPlans::ScalingPlan':
        for base in expand(ctx,resource,'/properties/ScalingInstructions/*'):
            path=base+'/TargetTrackingConfigurations'
            emit('SCALINGPLAN_METRIC_UNIQUE',path,metric_unique(ctx,resource,path),'each instruction needs unique comparable predefined metrics; ALB metrics include literal ResourceLabel in identity; custom, mixed and unknown metrics/labels remain held')
            for p in expand(ctx,resource,path+'/*/PredefinedScalingMetricSpecification'):
                kind=get(p+'/PredefinedScalingMetricType');namespace=get(base+'/ServiceNamespace')
                verdict='NEEDS_REVIEW'
                if kind in METRICS:verdict='NOT_APPLICABLE'
                elif kind=='ALBRequestCountPerTarget':
                    if namespace in ('autoscaling','ec2','ecs'):verdict='PASS'
                    elif namespace in ('rds','dynamodb'):verdict='FAIL'
                emit('SCALINGPLAN_ALB_SERVICE',p,verdict,'ALBRequestCountPerTarget supports Auto Scaling groups, Spot Fleet and ECS; unknown service/metric and external target-group attachment remain separate')
    return results
