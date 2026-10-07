import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.location.action_resources import evaluate_location_action_resources, FAMILIES
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


def arn(kind):
    return 'arn:aws:'+kind+':ap-northeast-1::provider/default' if kind.startswith('geo-') else 'arn:aws:geo:ap-northeast-1:123456789012:'+kind+'/example*'


def check(actions,resources,template=False):
    r=target('main','AWS::Location::APIKey',Restrictions={'AllowActions':actions,'AllowResources':resources})
    if template:r.template=TemplateContext(state='UNRESOLVED')
    return evaluate_location_action_resources(linked_design(r),r)[0]['verdict']


@pytest.mark.parametrize('kind,action',[(kind,action) for kind,actions in FAMILIES.items() for action in sorted(actions)])
def test_documented_actions_cover_their_family(kind,action):
    assert check([action],[arn(kind)])=='PASS'


@pytest.mark.parametrize('kind',list(FAMILIES))
def test_known_wrong_family(kind):
    action='geo:GetPlace' if kind!='place-index' else 'geo:GetMap*'
    assert check([action],[arn(kind)])=='FAIL'


@pytest.mark.parametrize('mode,expected',[
    ('all','PASS'),('missing_route','FAIL'),('unknown_action','NEEDS_REVIEW'),('unknown_resource','NEEDS_REVIEW'),
    ('invalid_wildcard','NEEDS_REVIEW'),('empty_actions','FAIL'),('empty_resources','NEEDS_REVIEW'),
    ('template','NEEDS_REVIEW'),('legacy_vs_enhanced','FAIL'),('unknown_collection','NEEDS_REVIEW'),
])
def test_mixed_coverage_and_unknowns(mode,expected):
    actions=['geo:GetMap*','geo:GetPlace','geo:CalculateRoute'];resources=[arn(k) for k in ('map','place-index','route-calculator')]
    if mode=='missing_route':actions.pop()
    if mode=='unknown_action':actions[-1]=UNKNOWN
    if mode=='unknown_resource':resources[-1]=UNKNOWN
    if mode=='invalid_wildcard':actions[-1]='geo:*'
    if mode=='empty_actions':actions=[]
    if mode=='empty_resources':resources=[]
    if mode=='legacy_vs_enhanced':resources=[arn('geo-places')];actions=['geo:GetPlace']
    if mode=='unknown_collection':resources=UNKNOWN
    assert check(actions,resources,mode=='template')==expected


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('main','AWS::Location::APIKey',Restrictions={'AllowActions':['geo:GetMap*'],'AllowResources':[arn('place-index')]})
    assert any(f['rule_id']=='LOCATION_RESOURCE_ACTION_COVERAGE' and f['verdict']=='FAIL' for f in Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results'])
