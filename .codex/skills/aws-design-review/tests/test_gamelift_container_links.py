import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.gamelift.container_links import evaluate_gamelift_container_links
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


def fixture(start=1026,end=60000):
    r=target('main','AWS::GameLift::ContainerFleet',GameServerContainerGroupDefinitionName='game',InstanceInboundPermissions=[{'FromPort':start,'ToPort':end}])
    g=target('game','AWS::GameLift::ContainerGroupDefinition',Name='game',OperatingSystem='AMAZON_LINUX_2023',ContainerGroupType='GAME_SERVER')
    d=linked_design(r,[g],[('GameServerContainerGroupDefinitionName','game')])
    return d,r,g


@pytest.mark.parametrize('start,end,expected',[(22,22,'PASS'),(22,1026,'FAIL'),(1025,1026,'FAIL'),(1026,60000,'PASS'),(60000,60000,'PASS'),(60000,60001,'FAIL'),(1027,1026,'FAIL'),(0,0,'FAIL'),(True,True,'NEEDS_REVIEW'),(UNKNOWN,1026,'NEEDS_REVIEW')])
def test_inclusive_ports(start,end,expected):
    d,r,g=fixture(start,end)
    assert evaluate_gamelift_container_links(d,r)[-1]['verdict']==expected


@pytest.mark.parametrize('mode',['conditional','external','scope','template','unknown_os','version_missing','version_mismatch','arn_scope','name_mismatch','unknown_collection'])
def test_unknown_evidence(mode):
    d,r,g=fixture(22,22)
    if mode=='conditional':d.relations[0].condition='maybe'
    if mode=='external':d.relations=[]
    if mode=='scope':g.scope.region='us-east-1'
    if mode=='template':g.template=TemplateContext(state='UNRESOLVED')
    if mode=='unknown_os':next(f for f in g.fields if f.path=='/properties/OperatingSystem').candidates[0].value=UNKNOWN
    if mode.startswith('version') or mode=='arn_scope':
        next(f for f in r.fields if f.path=='/properties/GameServerContainerGroupDefinitionName').candidates[0].value='arn:aws:gamelift:'+ ('us-east-1' if mode=='arn_scope' else g.scope.region)+':'+g.scope.account+':containergroupdefinition/game:2'
        if mode=='version_mismatch':g.fields.extend(target('extra','x',VersionNumber=1).fields)
    if mode=='name_mismatch':next(f for f in g.fields if f.path=='/properties/Name').candidates[0].value='other'
    if mode=='unknown_collection':next(f for f in r.fields if f.path=='/properties/InstanceInboundPermissions').candidates[0].value=UNKNOWN
    assert evaluate_gamelift_container_links(d,r)[-1]['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('mode,expected',[('correct','PASS'),('wrong_game','FAIL'),('default_game','PASS'),('wrong_per','FAIL'),('correct_per','PASS'),('empty','PASS'),('per_only','NEEDS_REVIEW'),('unknown_type','NEEDS_REVIEW'),('version_match','PASS')])
def test_group_types(mode,expected):
    from test_template_dependencies import link
    d,r,g=fixture()
    if mode=='wrong_game':next(f for f in g.fields if f.path=='/properties/ContainerGroupType').candidates[0].value='PER_INSTANCE'
    if mode=='unknown_type':next(f for f in g.fields if f.path=='/properties/ContainerGroupType').candidates[0].value=UNKNOWN
    if mode=='default_game':g.fields=[f for f in g.fields if f.path!='/properties/ContainerGroupType']
    if mode in ('wrong_per','correct_per','per_only'):
        p=target('per','AWS::GameLift::ContainerGroupDefinition',Name='per',ContainerGroupType='GAME_SERVER' if mode=='wrong_per' else 'PER_INSTANCE');d.resources.append(p)
        r.fields.extend(target('extra','x',PerInstanceContainerGroupDefinitionName='per').fields);link(d,r,'PerInstanceContainerGroupDefinitionName',p)
    if mode in ('empty','per_only'):
        r.fields=[f for f in r.fields if f.path!='/properties/GameServerContainerGroupDefinitionName'];d.relations.pop(0)
    if mode=='version_match':
        next(f for f in r.fields if f.path=='/properties/GameServerContainerGroupDefinitionName').candidates[0].value='arn:aws:gamelift:'+g.scope.region+':'+g.scope.account+':containergroupdefinition/game:2'
        g.fields.extend(target('extra','x',VersionNumber=2).fields)
    assert evaluate_gamelift_container_links(d,r)[0]['verdict']==expected


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1];d,r,g=fixture(22,1026)
    assert any(f['rule_id']=='GAMELIFT_CONTAINER_OS_PORTS' and f['verdict']=='FAIL' for f in Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results'])
