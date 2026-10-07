import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('definition,expected',[(None,'FAIL'),('task:1','PASS'),(UNKNOWN,'NEEDS_REVIEW')])
def test_default_controller(definition,expected):
    resource=target('service','AWS::ECS::Service',**({'TaskDefinition':definition} if definition is not None else {}))
    findings={f['rule_id']:f['verdict'] for f in run_resource_checks(linked_design(resource),resource)}
    assert findings['ECS_SERVICE_DEFAULT_CONTROLLER_TASK']==expected


@pytest.mark.parametrize('controller',[{},UNKNOWN,{'Type':'EXTERNAL'},{'Type':'ECS'}])
def test_explicit_or_unknown_controller_not_defaulted(controller):
    resource=target('service','AWS::ECS::Service',DeploymentController=controller)
    assert not any(f['rule_id']=='ECS_SERVICE_DEFAULT_CONTROLLER_TASK' for f in run_resource_checks(linked_design(resource),resource))


@pytest.mark.parametrize('field,raw,expected',[
    ('GrpcCode','0','PASS'),('GrpcCode','0-99','PASS'),('GrpcCode','100','FAIL'),
    ('GrpcCode','0,1-5,12','PASS'),('GrpcCode','5-1','FAIL'),
    ('HttpCode','200-599','PASS'),('HttpCode','199','FAIL'),('HttpCode','600','FAIL'),
    ('HttpCode','200,202-299','PASS'),('HttpCode','200, 202','NEEDS_REVIEW'),
    ('HttpCode','200–399','NEEDS_REVIEW'),('HttpCode',UNKNOWN,'NEEDS_REVIEW'),
    ('GrpcCode','*','NEEDS_REVIEW')])
def test_matcher_ranges(field,raw,expected):
    resource=target('group','AWS::ElasticLoadBalancingV2::TargetGroup',Matcher={field:raw})
    assert next(f['verdict'] for f in run_resource_checks(linked_design(resource),resource)
                if f['rule_id']=='ELBV2_MATCHER_CODE_RANGE')==expected


@pytest.mark.parametrize('variation,expected',[('same','FAIL'),('case','NEEDS_REVIEW'),
    ('region','NEEDS_REVIEW'),('account','NEEDS_REVIEW'),('unknown','NEEDS_REVIEW'),('underscore','NEEDS_REVIEW')])
def test_eks_cluster_names(variation,expected):
    cluster=target('one','AWS::EKS::Cluster',Name='cluster')
    other=target('two','AWS::EKS::Cluster',Name='Cluster' if variation=='case' else UNKNOWN if variation=='unknown' else 'cluster')
    if variation=='region':other.scope.region='us-west-2'
    if variation=='account':other.scope.account='999999999999'
    if variation=='underscore':
        cluster=target('one','AWS::EKS::Cluster',Name='clu_ster')
        other=target('two','AWS::EKS::Cluster',Name='clu_ster')
    assert next(f['verdict'] for f in run_resource_checks(linked_design(cluster,[other]),cluster)
                if f['rule_id']=='EKS_CLUSTER_NAME_DUPLICATE')==expected
