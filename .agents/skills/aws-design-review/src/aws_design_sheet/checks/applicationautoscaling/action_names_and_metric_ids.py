"""Checks for AWS::ApplicationAutoScaling::ScalableTarget, AWS::ApplicationAutoScaling::ScalingPolicy."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'APPLICATION_SCALING_ACTION_NAMES': [CF+'aws-properties-applicationautoscaling-scalabletarget-scheduledaction.html'],
    'APPLICATION_SCALING_METRIC_IDS': [CF+'aws-properties-applicationautoscaling-scalingpolicy-targettrackingmetricdataquery.html'],
}


@resource_check('AWS::ApplicationAutoScaling::ScalableTarget','AWS::ApplicationAutoScaling::ScalingPolicy')
def evaluate_applicationautoscaling_action_names_and_metric_ids(design,resource):
    ctx=_Context(design,resource); results=[]
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    configs={
        'AWS::ApplicationAutoScaling::ScalableTarget':('/properties/ScheduledActions','ScheduledActionName','APPLICATION_SCALING_ACTION_NAMES'),
        'AWS::ApplicationAutoScaling::ScalingPolicy':('/properties/TargetTrackingScalingPolicyConfiguration/CustomizedMetricSpecification/Metrics','Id','APPLICATION_SCALING_METRIC_IDS'),
    }
    if resource.type in configs:
        path,key,rule=configs[resource.type]; raw=value(ctx,resource,path)
        if raw is not ABSENT:
            seen=set(); duplicate=False; pending=not isinstance(raw,list)
            for i in range(len(raw)) if isinstance(raw,list) else ():
                name=value(ctx,resource,path+'/'+str(i)+'/'+key)
                if not literal(name):pending=True
                elif name in seen:duplicate=True
                else:seen.add(name)
            emit(rule,path,'FAIL' if duplicate else 'NEEDS_REVIEW' if pending else 'PASS','literal names/IDs must be unique within this declared collection; unresolved names and external scheduled actions remain unverified')
    return results
