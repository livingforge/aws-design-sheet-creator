import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.entityresolution.normalization_groups import evaluate_entityresolution_normalization_groups
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_template_dependencies import link


def fixture(fields=None,flag=True):
    r=target('schema','AWS::EntityResolution::SchemaMapping',SchemaName='schema',MappedInputFields=fields if fields is not None else [{'Type':'NAME_FIRST','GroupName':'custom-name','Hashed':False},{'Type':'NAME_LAST','GroupName':'custom-name','Hashed':False}])
    w=target('workflow','AWS::EntityResolution::MatchingWorkflow',InputSourceConfig=[{'ApplyNormalization':flag}])
    d=linked_design(r,[w]);link(d,w,'InputSourceConfig/0/SchemaArn',r)
    return d,r,w


@pytest.mark.parametrize('types,group',[(['NAME_FIRST','NAME_LAST'],'custom-name'),(['ADDRESS_STREET1','ADDRESS_CITY'],'home-address'),(['PHONE_NUMBER','PHONE_COUNTRYCODE'],'contact-phone')])
def test_custom_group_names(types,group):
    d,r,_=fixture([{'Type':t,'GroupName':group,'Hashed':False} for t in types])
    assert evaluate_entityresolution_normalization_groups(d,r)[0]['verdict']=='PASS'


@pytest.mark.parametrize('mode,expected',[
    ('absent_group','FAIL'),('empty_group','FAIL'),('unknown_group','NEEDS_REVIEW'),('singleton','NEEDS_REVIEW'),
    ('mixed','NEEDS_REVIEW'),('hashed','NEEDS_REVIEW'),('unknown_hash','NEEDS_REVIEW'),('omitted_hash','NEEDS_REVIEW'),
    ('unknown_type','NEEDS_REVIEW'),('unknown_fields','NEEDS_REVIEW'),('full_type','NOT_APPLICABLE')])
def test_group_evidence(mode,expected):
    d,r,_=fixture();fields=r.fields[1].candidates[0].value
    if mode=='absent_group':del fields[0]['GroupName']
    if mode=='empty_group':fields[0]['GroupName']=''
    if mode=='unknown_group':fields[0]['GroupName']=UNKNOWN
    if mode=='singleton':fields.pop()
    if mode=='mixed':fields[1]['Type']='PHONE_NUMBER'
    if mode=='hashed':fields[0]['Hashed']=True
    if mode=='unknown_hash':fields[0]['Hashed']=UNKNOWN
    if mode=='omitted_hash':del fields[0]['Hashed']
    if mode=='unknown_type':fields[0]['Type']=UNKNOWN
    if mode=='unknown_fields':r.fields[1].candidates[0].value=UNKNOWN
    if mode=='full_type':r.fields[1].candidates[0].value=[{'Type':'NAME'}]
    assert evaluate_entityresolution_normalization_groups(d,r)[0]['verdict']==expected


@pytest.mark.parametrize('mode,expected',[(x,'NOT_APPLICABLE' if x=='disabled' else 'PASS' if x=='matching_arn' else 'NEEDS_REVIEW') for x in ('disabled','unknown','external','conditional','scope','template','wrong_name','matching_arn')])
def test_workflow_context(mode,expected):
    d,r,w=fixture(flag=False if mode=='disabled' else UNKNOWN if mode=='unknown' else True)
    if mode=='external':d.relations=[]
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='scope':w.scope.region='us-east-1'
    if mode=='template':r.template=TemplateContext(state='UNRESOLVED')
    if mode in ('matching_arn','wrong_name'):w.fields[0].candidates[0].value[0]['SchemaArn']='arn:aws:entityresolution:ap-northeast-1:111111111111:schemamapping/'+('schema' if mode=='matching_arn' else 'wrong')
    assert evaluate_entityresolution_normalization_groups(d,r)[0]['verdict']==expected


def test_one_enabled_workflow_establishes_normalization_requirement():
    d,r,w=fixture(flag=False)
    other=target('other','AWS::EntityResolution::MatchingWorkflow',InputSourceConfig=[{'ApplyNormalization':True}])
    d.resources.append(other);link(d,other,'InputSourceConfig/0/SchemaArn',r)
    assert evaluate_entityresolution_normalization_groups(d,r)[0]['verdict']=='PASS'


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    d,r,*_=fixture();root=Path(__file__).resolve().parents[1]
    actual=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results']
    assert any(f['rule_id']=='ENTITY_NORMALIZATION_SUBTYPE_GROUPS' and f['verdict']=='PASS' for f in actual)
