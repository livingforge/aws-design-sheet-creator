import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN

LABEL='app/lb/123456/targetgroup/tg/abcdef'
ARN='arn:aws:elasticloadbalancing:ap-northeast-1:111111111111:targetgroup/tg/abcdef'


@pytest.mark.parametrize('spec',['target','PredefinedMetricPairSpecification','PredefinedLoadMetricSpecification','PredefinedScalingMetricSpecification'])
@pytest.mark.parametrize('traffic',[False,True])
def test_declared_label_attachment(spec,traffic):
    props={'TargetTrackingConfiguration':{'PredefinedMetricSpecification':{'ResourceLabel':LABEL}}} if spec=='target' else {'PredictiveScalingConfiguration':{'MetricSpecifications':[{spec:{'ResourceLabel':LABEL}}]}}
    main=target('policy','AWS::AutoScaling::ScalingPolicy',AutoScalingGroupName={'Ref':'group'},**props)
    group=target('group','AWS::AutoScaling::AutoScalingGroup',**({'TrafficSources':[{'Type':'elbv2','Identifier':ARN}]} if traffic else {'TargetGroupARNs':[ARN]}))
    data=linked_design(main,[group],[('AutoScalingGroupName','group')])
    assert run_resource_checks(data,main)[0]['verdict']=='PASS'


@pytest.mark.parametrize('arn,label,change',[(ARN.replace('abcdef','123'),LABEL,''),(UNKNOWN,LABEL,''),(ARN,UNKNOWN,''),(ARN,LABEL,'conditional'),(ARN,LABEL,'cross-scope'),(ARN.replace('111111111111','222222222222'),LABEL,''),(ARN,'future-label','')])
def test_unproven_attachments_need_review(arn,label,change):
    main=target('policy','AWS::AutoScaling::ScalingPolicy',AutoScalingGroupName={'Ref':'group'},TargetTrackingConfiguration={'PredefinedMetricSpecification':{'ResourceLabel':label}})
    group=target('group','AWS::AutoScaling::AutoScalingGroup',TargetGroupARNs=[arn])
    data=linked_design(main,[group],[('AutoScalingGroupName','group')])
    if change=='conditional':data.relations[0].condition='optional'
    if change=='cross-scope':group.scope.region='us-west-2'
    assert run_resource_checks(data,main)[0]['verdict']=='NEEDS_REVIEW'
