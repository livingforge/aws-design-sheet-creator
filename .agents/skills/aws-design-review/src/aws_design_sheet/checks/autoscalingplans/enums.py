"""Documented ScalingPlan instruction enums."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.literals import expand, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={
 'SCALINGPLAN_INSTRUCTION_ENUMS':[CF+'aws-properties-autoscalingplans-scalingplan-'+p+'.html' for p in ('scalinginstruction','predefinedscalingmetricspecification','predefinedloadmetricspecification','customizedloadmetricspecification','customizedscalingmetricspecification')],
}
ENUMS={
 'CustomizedLoadMetricSpecification/Statistic':('Sum',),
 'TargetTrackingConfigurations/*/CustomizedScalingMetricSpecification/Statistic':('Average','Minimum','Maximum','SampleCount','Sum'),
 'ServiceNamespace':('autoscaling','ecs','ec2','rds','dynamodb'),
 'ScalableDimension':('autoscaling:autoScalingGroup:DesiredCapacity','ecs:service:DesiredCount','ec2:spot-fleet-request:TargetCapacity','rds:cluster:ReadReplicaCount','dynamodb:table:ReadCapacityUnits','dynamodb:table:WriteCapacityUnits','dynamodb:index:ReadCapacityUnits','dynamodb:index:WriteCapacityUnits'),
 'PredictiveScalingMaxCapacityBehavior':('SetForecastCapacityToMaxCapacity','SetMaxCapacityToForecastCapacity','SetMaxCapacityAboveForecastCapacity'),
 'PredictiveScalingMode':('ForecastAndScale','ForecastOnly'),
 'ScalingPolicyUpdateBehavior':('KeepExternalPolicies','ReplaceExternalPolicies'),
 'PredefinedLoadMetricSpecification/PredefinedLoadMetricType':('ASGTotalCPUUtilization','ASGTotalNetworkIn','ASGTotalNetworkOut','ALBTargetGroupRequestCount'),
 'TargetTrackingConfigurations/*/PredefinedScalingMetricSpecification/PredefinedScalingMetricType':('ASGAverageCPUUtilization','ASGAverageNetworkIn','ASGAverageNetworkOut','DynamoDBReadCapacityUtilization','DynamoDBWriteCapacityUtilization','ECSServiceAverageCPUUtilization','ECSServiceAverageMemoryUtilization','ALBRequestCountPerTarget','RDSReaderAverageCPUUtilization','RDSReaderAverageDatabaseConnections','EC2SpotFleetRequestAverageCPUUtilization','EC2SpotFleetRequestAverageNetworkIn','EC2SpotFleetRequestAverageNetworkOut'),
}


@resource_check('AWS::AutoScalingPlans::ScalingPlan')
def evaluate_autoscalingplans_enums(design,resource):
    ctx=_Context(design,resource);results=[];seen=set()
    def emit(rule,path,verdict,reason):
        if (rule,path) in seen:return
        seen.add((rule,path));f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    if resource.type=='AWS::AutoScalingPlans::ScalingPlan':
        for key,allowed in ENUMS.items():
            pattern='/properties/ScalingInstructions/*/'+key
            for path in expand(ctx,resource,pattern):
                raw=value(ctx,resource,path)
                exact=re.fullmatch(re.escape(pattern).replace(r'\*',r'\d+'),path)
                known=exact and (literal(raw) or raw=='')
                emit('SCALINGPLAN_INSTRUCTION_ENUMS',path,'NEEDS_REVIEW' if not known else 'PASS' if raw in allowed else 'FAIL','current explicit instruction/load/scaling metric enum only; unknown ancestors and values, applicability, metric dimensions and resource compatibility remain open')
    return results
