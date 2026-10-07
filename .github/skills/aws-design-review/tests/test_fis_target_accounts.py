import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.fis.target_accounts import evaluate_fis_target_accounts
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_template_dependencies import link

ACCOUNT='222222222222'
ARN='arn:aws:ec2:ap-northeast-1:'+ACCOUNT+':instance/i-12345678'


def fixture():
    r=target('template','AWS::FIS::ExperimentTemplate',ExperimentOptions={'AccountTargeting':'multi-account'},Targets={'instances':{'ResourceArns':[ARN]}})
    config=target('config','AWS::FIS::TargetAccountConfiguration',AccountId=ACCOUNT,RoleArn='arn:aws:iam::'+ACCOUNT+':role/FIS')
    d=linked_design(r,[config]);link(d,config,'ExperimentTemplateId',r)
    return d,r,config


@pytest.mark.parametrize('mode,expected',[
    ('explicit','PASS'),('single','NOT_APPLICABLE'),('omitted','NOT_APPLICABLE'),
    ('unknown_mode','NEEDS_REVIEW'),('missing_config','NEEDS_REVIEW'),
    ('wrong_account','NEEDS_REVIEW'),('wrong_role_account','NEEDS_REVIEW'),
    ('unknown_role','NEEDS_REVIEW'),('conditional','NEEDS_REVIEW'),
    ('template','NEEDS_REVIEW'),('external_id','NEEDS_REVIEW'),
    ('tag_selection','NEEDS_REVIEW'),('unknown_arn','NEEDS_REVIEW'),
    ('other_region','NEEDS_REVIEW'),('other_target','NEEDS_REVIEW'),
    ('cross_scope','NEEDS_REVIEW'),('dynamic_name','NEEDS_REVIEW')])
def test_account_coverage_evidence(mode,expected):
    d,r,c=fixture();options=r.fields[0].candidates[0].value;targets=r.fields[1].candidates[0].value
    if mode=='single':options['AccountTargeting']='single-account'
    if mode=='omitted':options.clear()
    if mode=='unknown_mode':options['AccountTargeting']=UNKNOWN
    if mode=='missing_config':d.resources.remove(c)
    if mode=='wrong_account':c.fields[0].candidates[0].value='333333333333'
    if mode=='wrong_role_account':c.fields[1].candidates[0].value='arn:aws:iam::333333333333:role/FIS'
    if mode=='unknown_role':c.fields[1].candidates[0].value=UNKNOWN
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='template':r.template=TemplateContext(state='UNRESOLVED')
    if mode=='external_id':c.fields+=target('dummy',c.type,ExperimentTemplateId='EXT123').fields
    if mode=='tag_selection':targets['instances']={'ResourceTags':{'Name':'test'}}
    if mode=='unknown_arn':targets['instances']['ResourceArns']=[UNKNOWN]
    if mode=='other_region':targets['instances']['ResourceArns']=[ARN.replace('ap-northeast-1','us-east-1')]
    if mode=='other_target':targets['instances']['ResourceArns'].append(ARN.replace(ACCOUNT,'333333333333'))
    if mode=='cross_scope':c.scope.account=ACCOUNT
    if mode=='dynamic_name':targets['bad/name']=targets.pop('instances')
    assert evaluate_fis_target_accounts(d,r)[0]['verdict']==expected


def test_all_known_accounts_can_be_covered():
    d,r,c=fixture();other='333333333333'
    r.fields[1].candidates[0].value['instances']['ResourceArns'].append(ARN.replace(ACCOUNT,other))
    c2=target('config2',c.type,AccountId=other,RoleArn='arn:aws:iam::'+other+':role/path/FIS')
    d.resources.append(c2);link(d,c2,'ExperimentTemplateId',r)
    assert evaluate_fis_target_accounts(d,r)[0]['verdict']=='PASS'


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    d,r,*_=fixture();root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results']
    assert any(f['rule_id']=='FIS_MULTI_ACCOUNT_CONFIG_COVERAGE' and f['verdict']=='PASS' for f in results)
