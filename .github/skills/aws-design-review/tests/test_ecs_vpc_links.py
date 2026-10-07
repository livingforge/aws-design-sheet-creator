import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('kind,property_name,rule', [
    ('Service','AwsvpcConfiguration','ECS_SERVICE_VPC_MEMBERSHIP'),
    ('TaskSet','AwsVpcConfiguration','ECS_TASKSET_VPC_MEMBERSHIP'),
])
@pytest.mark.parametrize('vpc,linked_sg,expected', [
    ('vpc-123',True,'PASS'), ('vpc-456',True,'FAIL'),
    (UNKNOWN,True,'NEEDS_REVIEW'), ('vpc-123',False,'NEEDS_REVIEW'),
])
def test_ecs_vpc_membership(kind,property_name,rule,vpc,linked_sg,expected):
    resource = target('main','AWS::ECS::'+kind,NetworkConfiguration={property_name:{'Subnets':[{'Ref':'subnet'}],'SecurityGroups':[{'Ref':'sg'}]}})
    subnet = target('subnet','AWS::EC2::Subnet',VpcId='vpc-123')
    sg = target('sg','AWS::EC2::SecurityGroup',VpcId=vpc)
    links = [(f'NetworkConfiguration/{property_name}/Subnets/0','subnet')]
    if linked_sg:
        links.append((f'NetworkConfiguration/{property_name}/SecurityGroups/0','sg'))
    data = linked_design(resource,[subnet,sg],links)
    findings = {r['rule_id']:r['verdict'] for r in run_resource_checks(data,resource)}
    assert findings[rule] == expected


def test_event_network_mode_omission_is_not_assumed_bridge():
    resource = target('event','AWS::Events::Rule',Targets=[{'EcsParameters':{
        'TaskDefinitionArn':{'Ref':'task'}, 'NetworkConfiguration':{'AwsVpcConfiguration':{'Subnets':[]}}}}])
    task = target('task','AWS::ECS::TaskDefinition',RuntimePlatform={'OperatingSystemFamily':'WINDOWS_SERVER_2022_CORE'})
    data = linked_design(resource,[task],[('Targets/0/EcsParameters/TaskDefinitionArn','task')])
    findings = {r['rule_id']:r['verdict'] for r in run_resource_checks(data,resource)}
    assert findings['EVENTS_ECS_TASK_COMPATIBILITY'] == 'NEEDS_REVIEW'
