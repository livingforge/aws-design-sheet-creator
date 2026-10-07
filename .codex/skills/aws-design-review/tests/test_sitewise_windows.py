from pathlib import Path
import pytest
from aws_design_sheet.checks.iotsitewise.windows import interval_range, evaluate_iotsitewise_windows
from aws_design_sheet.checks.gamelift.ruleset_local_config_regions import evaluate_gamelift_ruleset_local_config_regions
from aws_design_sheet.checks.registry import combine
sitewise_windows_checks = combine(evaluate_iotsitewise_windows, evaluate_gamelift_ruleset_local_config_regions)
from aws_design_sheet.models import Relation, TemplateContext
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('raw,expected',[
    ('1m','PASS'),('1w','PASS'),('7d','PASS'),('168h','PASS'),('10080m','PASS'),
    ('0m','FAIL'),('8d','FAIL'),('10081m','FAIL'),('PT59S','FAIL'),('PT60S','PASS'),
    ('PT604800S','PASS'),('PT604801S','FAIL'),('PT5M','PASS'),('PT24H','PASS'),('P7D','PASS'),('P1W','PASS'),
    ('P1M','NEEDS_REVIEW'),('P1Y','NEEDS_REVIEW'),('PT1H30M','NEEDS_REVIEW'),('1.5h','NEEDS_REVIEW'),
    ('60s','NEEDS_REVIEW'),('5M','NEEDS_REVIEW'),('1m\n','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW'),
    ('9'*70+'m','NEEDS_REVIEW'),
])
def test_interval(raw,expected):
    assert interval_range(raw)==expected


@pytest.mark.parametrize('composite',[False,True])
@pytest.mark.parametrize('mode',['valid','invalid','unknown'])
def test_nested(composite,mode):
    props=[{'Type':{'Metric':{'Window':{'Tumbling':{'Interval':'1h' if mode=='valid' else '8d' if mode=='invalid' else UNKNOWN}}}}}]
    r=target('main','AWS::IoTSiteWise::AssetModel',**({'AssetModelCompositeModels':[{'CompositeModelProperties':props}]} if composite else {'AssetModelProperties':props}))
    results=sitewise_windows_checks(linked_design(r),r)
    assert len(results)==1 and results[0]['verdict']=={'valid':'PASS','invalid':'FAIL','unknown':'NEEDS_REVIEW'}[mode]


@pytest.mark.parametrize('mode',['SSO','IAM','UNKNOWN'])
@pytest.mark.parametrize('region',['cn-north-1','cn-northwest-1','ap-northeast-1','unknown'])
def test_portal(mode,region):
    r=target('main','AWS::IoTSiteWise::Portal',PortalAuthMode=UNKNOWN if mode=='UNKNOWN' else mode);r.scope.region=region
    expected='NEEDS_REVIEW' if mode!='SSO' or region=='unknown' else 'FAIL' if region.startswith('cn-') else 'PASS'
    assert sitewise_windows_checks(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('mode',['same','different','none','name','conditional','ambiguous','account','environment','template','consumer_template','scope','arn'])
def test_reverse(mode):
    r=target('main','AWS::GameLift::MatchmakingRuleSet',Name='rules')
    c=target('consumer','AWS::GameLift::MatchmakingConfiguration',RuleSetName='other' if mode=='name' else 'arn:aws:gamelift:us-east-1:111111111111:matchmakingruleset/rules' if mode=='arn' else 'rules')
    if mode!='same':c.scope.region='us-east-1'
    if mode=='account':c.scope.account='222222222222'
    if mode=='environment':c.scope.environment='other'
    if mode=='scope':c.scope.region='unknown'
    if mode=='template':r.template=TemplateContext(state='UNRESOLVED')
    if mode=='consumer_template':c.template=TemplateContext(state='UNRESOLVED')
    d=linked_design(r,[c])
    if mode!='none':d.relations.append(Relation(id='use',source_resource_id='consumer',source_path='/properties/RuleSetName',target_resource_id='main',evidence_ids=[],condition='Maybe' if mode=='conditional' else None))
    if mode=='ambiguous':d.relations.append(d.relations[0].model_copy(update={'id':'duplicate'}))
    assert sitewise_windows_checks(d,r)[0]['verdict']==('FAIL' if mode=='different' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('region',['ap-northeast-1','cn-north-1'])
def test_checker_portal(region):
    r=target('main','AWS::IoTSiteWise::Portal',PortalAuthMode='SSO');r.scope.region=region
    root=Path(__file__).resolve().parents[1]
    report=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))
    results=report['results']
    if region=='ap-northeast-1':
        assert any(f['rule_id']=='SITEWISE_PORTAL_SSO_REGION' and f['verdict']=='PASS' for f in results)
    else:
        assert not any(f['rule_id']=='SITEWISE_PORTAL_SSO_REGION' for f in results)
        assert any(f['kind']=='REGION_SCHEMA' for f in report['coverage'])
