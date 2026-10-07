from pathlib import Path
import pytest
from aws_design_sheet.checks.customerprofiles.object_type_keys import evaluate_customerprofiles_object_type_keys
from aws_design_sheet.checks.datasync.hdfs_block_multiple import evaluate_datasync_hdfs_block_multiple
from aws_design_sheet.checks.databrew.ruleset_dataset import evaluate_databrew_ruleset_dataset
from aws_design_sheet.checks.deadline.accelerator_runtime import evaluate_deadline_accelerator_runtime
from aws_design_sheet.checks.docdb.source_id_hyphens import evaluate_docdb_source_id_hyphens
from aws_design_sheet.checks.registry import combine
data_links_checks = combine(evaluate_customerprofiles_object_type_keys, evaluate_datasync_hdfs_block_multiple, evaluate_databrew_ruleset_dataset, evaluate_deadline_accelerator_runtime, evaluate_docdb_source_id_hyphens)
from aws_design_sheet.models import Relation
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


def check(kind,**props):
    r=target('subject',kind,**props)
    return data_links_checks(linked_design(r),r)


@pytest.mark.parametrize('group,selected,attr,expected',[
    ('Address',['BusinessAddress'],'Address.City','PASS'),('Address',['BusinessAddress'],'BusinessAddress.City','FAIL'),
    ('Address',['ShippingAddress'],'ShippingAddress.City','FAIL'),('Address',['MaillingAddress'],'Address.City','NEEDS_REVIEW'),
    ('EmailAddress',['PersonalEmailAddress'],'EmailAddress','PASS'),('EmailAddress',['PersonalEmailAddress'],'PersonalEmailAddress','FAIL'),
    ('PhoneNumber',['MobilePhoneNumber'],'MobilePhoneNumber','FAIL'),('PhoneNumber',['HomePhoneNumber'],'PhoneNumber','PASS'),
    ('Address',UNKNOWN,'Address.City','NEEDS_REVIEW'),('Address',['BusinessAddress'],UNKNOWN,'NEEDS_REVIEW')])
def test_matching(group,selected,attr,expected):
    assert check('AWS::CustomerProfiles::Domain',RuleBasedMatching={'AttributeTypesSelector':{
        'AttributeMatchingModel':'MANY_TO_MANY',group:selected},'MatchingRules':[{'Rule':[attr]}]})[0]['verdict']==expected


def key(name,ids):return {'Name':name,'ObjectTypeKeyList':[{'StandardIdentifiers':ids}]}


@pytest.mark.parametrize('keys,expected',[
    ([key('a',['UNIQUE']),key('b',['PROFILE'])],'PASS'),([key('a',['UNIQUE']),key('b',['UNIQUE'])],'FAIL'),
    ([key('a',['UNIQUE']),key('a',['UNIQUE'])],'NEEDS_REVIEW'),([key('a',['UNIQUE']),key('b',[UNKNOWN])],'NEEDS_REVIEW'),
    ([key('a',['PROFILE']),key('b',['PROFILE'])],'PASS'),
    ([{'Name':'a','ObjectTypeKeyList':[{'StandardIdentifiers':['UNIQUE']},{'StandardIdentifiers':['UNIQUE']}]}],'NEEDS_REVIEW')])
def test_unique_keys(keys,expected):
    assert check('AWS::CustomerProfiles::ObjectType',Keys=keys)[0]['verdict']==expected


@pytest.mark.parametrize('size,expected',[(1048576,'PASS'),(1049088,'PASS'),(1048577,'FAIL'),(1073741824,'PASS'),
    ('1048576','NEEDS_REVIEW'),(True,'NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_block_size(size,expected):
    assert check('AWS::DataSync::LocationHDFS',BlockSize=size)[0]['verdict']==expected


@pytest.mark.parametrize('mode,expected',[('same','PASS'),('different','FAIL'),('external','NEEDS_REVIEW'),
    ('conditional','NEEDS_REVIEW'),('cross_scope','NEEDS_REVIEW'),('unknown_scope','NEEDS_REVIEW'),('recipe','NEEDS_REVIEW')])
def test_databrew_links(mode,expected):
    r=target('job','AWS::DataBrew::Job',Type='RECIPE' if mode=='recipe' else 'PROFILE',DatasetName='a',ValidationConfigurations=[{'RulesetArn':'rules'}])
    a=target('a','AWS::DataBrew::Dataset',Name='a'); b=target('b','AWS::DataBrew::Dataset',Name='b')
    rules=target('rules','AWS::DataBrew::Ruleset',TargetArn='dataset')
    d=linked_design(r,[a,b,rules],[('DatasetName','a'),('ValidationConfigurations/0/RulesetArn','rules')])
    if mode!='external':d.relations.append(Relation(id='rules-target',source_resource_id='rules',source_path='/properties/TargetArn',target_resource_id='b' if mode=='different' else 'a',evidence_ids=['e1']))
    if mode=='conditional':d.relations[-1].condition='flag'
    if mode=='cross_scope':rules.scope.region='eu-west-1'
    if mode=='unknown_scope':r.scope.account='unknown'
    assert data_links_checks(d,r)[0]['verdict']==expected


@pytest.mark.parametrize('runtimes,expected',[
    (['grid:r570','grid:r570'],'PASS'),(['grid:r535','grid:r570'],'FAIL'),(['latest','latest'],'PASS'),
    (['latest',None],'FAIL'),([None,None],'PASS'),(['grid:r580','latest'],'NEEDS_REVIEW'),
    (['grid:r580',None],'NEEDS_REVIEW'),(['grid:r570',UNKNOWN],'NEEDS_REVIEW'),(['future','future'],'NEEDS_REVIEW')])
def test_runtimes(runtimes,expected):
    selections=[{'Name':str(i),**({'Runtime':r} if r is not None else {})} for i,r in enumerate(runtimes)]
    assert check('AWS::Deadline::Fleet',Configuration={'ServiceManagedEc2':{'InstanceCapabilities':{
        'AcceleratorCapabilities':{'Selections':selections}}}})[0]['verdict']==expected


@pytest.mark.parametrize('ids,expected',[(['db-one'],'PASS'),(['db--one'],'FAIL'),(['db-'],'FAIL'),
    (['db-one',UNKNOWN],'NEEDS_REVIEW'),(['db--one',UNKNOWN],'FAIL')])
def test_docdb_ids(ids,expected):
    assert check('AWS::DocDB::EventSubscription',SourceIds=ids)[0]['verdict']==expected


def test_checker_integration():
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('subject','AWS::DataSync::LocationHDFS',BlockSize=1048577)
    result=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))
    row=next(r for r in result['results'] if r['rule_id']=='DATASYNC_HDFS_BLOCK_MULTIPLE')
    assert row['verdict']=='FAIL' and row['source_urls'] and row['evidence_ids']
