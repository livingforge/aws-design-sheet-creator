import pytest
from aws_design_sheet.checks.quicksight.data_set import evaluate_quicksight_data_set
from aws_design_sheet.checks.pipes.batch_instance_applicability import evaluate_pipes_batch_instance_applicability
from aws_design_sheet.checks.registry import combine
dataset_maps_checks = combine(evaluate_quicksight_data_set, evaluate_pipes_batch_instance_applicability)
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_template_dependencies import link


@pytest.mark.parametrize('platform,want',[(None,'PASS'),(['EC2'],'PASS'),(['MANAGED_INSTANCES'],'PASS'),(['FARGATE'],'FAIL'),([], 'NEEDS_REVIEW'),(['EC2','FARGATE'],'NEEDS_REVIEW'),([UNKNOWN],'NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_declared_multinode_platform(platform,want):
    r=target('pipe','AWS::Pipes::Pipe',TargetParameters={'BatchJobParameters':{'ContainerOverrides':{'InstanceType':'m5.large'}}})
    props={'Type':'multinode'}
    if platform is not None:props['PlatformCapabilities']=platform
    job=target('job','AWS::Batch::JobDefinition',**props)
    d=linked_design(r,[job]);link(d,r,'TargetParameters/BatchJobParameters/JobDefinition',job)
    assert dataset_maps_checks(d,r)[0]['verdict']==want
