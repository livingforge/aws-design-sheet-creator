"""Declared target-group attachment for Auto Scaling metric labels."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={'AUTOSCALING_METRIC_LABEL_ATTACHMENT':[CF+'aws-properties-autoscaling-scalingpolicy-'+page+'.html' for page in (
    'predefinedmetricspecification','predictivescalingpredefinedmetricpair',
    'predictivescalingpredefinedloadmetric','predictivescalingpredefinedscalingmetric')]}
SOURCES['AUTOSCALING_METRIC_LABEL_ATTACHMENT'].append(CF+'aws-properties-autoscaling-autoscalinggroup-trafficsourceidentifier.html')


@resource_check('AWS::AutoScaling::ScalingPolicy')
def scaling_labels(design,resource):
    ctx=_Context(design,resource)
    paths=['/properties/TargetTrackingConfiguration/PredefinedMetricSpecification/ResourceLabel']
    root='/properties/PredictiveScalingConfiguration/MetricSpecifications'
    items=value(ctx,resource,root)
    if isinstance(items,list):
        paths.extend(root+f'/{i}/{kind}/ResourceLabel' for i in range(len(items)) for kind in (
            'PredefinedMetricPairSpecification','PredefinedLoadMetricSpecification','PredefinedScalingMetricSpecification'))
    group=linked(ctx,resource,'/properties/AutoScalingGroupName','AWS::AutoScaling::AutoScalingGroup')
    arns=[]
    if group:
        entries=value(ctx,group,'/properties/TargetGroupARNs')
        if isinstance(entries,list):
            arns.extend(value(ctx,group,f'/properties/TargetGroupARNs/{i}') for i in range(len(entries)))
        entries=value(ctx,group,'/properties/TrafficSources')
        if isinstance(entries,list):
            arns.extend(value(ctx,group,f'/properties/TrafficSources/{i}/Identifier') for i in range(len(entries))
                        if value(ctx,group,f'/properties/TrafficSources/{i}/Type')=='elbv2')
    attached=set()
    for arn in arns:
        match=re.fullmatch(r'arn:[a-z0-9-]+:elasticloadbalancing:([a-z0-9-]+):(\d{12}):(targetgroup/[A-Za-z0-9-]+/[a-f0-9]+)',arn) if isinstance(arn,str) else None
        if match and group and match[1]==group.scope.region and match[2]==group.scope.account:
            attached.add(match[3])
    rows=[]
    for path in paths:
        label=value(ctx,resource,path)
        if label is ABSENT:continue
        match=re.fullmatch(r'app/[A-Za-z0-9-]+/[a-f0-9]+/(targetgroup/[A-Za-z0-9-]+/[a-f0-9]+)',label) if isinstance(label,str) else None
        proven=bool(match and match[1] in attached)
        rows.append(ctx.finding('AUTOSCALING_METRIC_LABEL_ATTACHMENT',path,'PASS' if proven else 'NEEDS_REVIEW',
            'the metric label target-group ARN suffix matches a same-scope group attachment declaration; ALB association, live attachment and unresolved generated ARN identifiers remain unverified'))
    return rows
