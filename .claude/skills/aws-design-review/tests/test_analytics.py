"""Collection boundaries, conservative identity matching and checker integration."""
import json
import zipfile
from pathlib import Path
import pytest
from aws_design_sheet.checks.quicksight.refresh_schedule import evaluate_quicksight_refresh_schedule, VISUALS
from aws_design_sheet.checks.s3express.prefix_bytes import evaluate_s3express_prefix_bytes
from aws_design_sheet.checks.scheduler.capacity_base_count import evaluate_scheduler_capacity_base_count
from aws_design_sheet.checks.sagemaker.clarify_and_trial import evaluate_sagemaker_clarify_and_trial
from aws_design_sheet.checks.registry import combine
from aws_design_sheet.models import Relation,ValueState
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
analytics_checks=combine(evaluate_quicksight_refresh_schedule,evaluate_s3express_prefix_bytes,evaluate_scheduler_capacity_base_count,evaluate_sagemaker_clarify_and_trial)


def check(kind,**props):
    r=target('subject','AWS::'+kind,**props)
    return analytics_checks(linked_design(r),r)


def visual(ident,kind='BarChartVisual'):
    return {kind:{'VisualId':ident}}


@pytest.mark.parametrize('kind',['Analysis','Dashboard','Template'])
@pytest.mark.parametrize('sheets,expected',[
    ([{'Visuals':[visual('a')]},{'Visuals':[visual('b','TableVisual')]}],'PASS'),
    ([{'Visuals':[visual('a')]},{'Visuals':[visual('a','TableVisual')]}],'FAIL'),
    ([{'TextBoxes':[{'SheetTextBoxId':'a'}]},{'TextBoxes':[{'SheetTextBoxId':'a'}]}],'FAIL'),
    ([{'Visuals':[visual('a')],'TextBoxes':[{'SheetTextBoxId':'a'}]}],'NEEDS_REVIEW'),
    ([{'Visuals':[visual('a'),visual(UNKNOWN)]}],'NEEDS_REVIEW'),
    ([{'Visuals':[visual('a'),visual('a'),UNKNOWN]}],'FAIL'),
    ([{'Visuals':[{'BarChartVisual':{'VisualId':'a'},'TableVisual':{'VisualId':'a'}}]}],'NEEDS_REVIEW'),
    ([{'Visuals':[{'FutureVisual':{'VisualId':'a'}}]}],'NEEDS_REVIEW'),
    ([{'Visuals':[{}]}],'NEEDS_REVIEW'),([UNKNOWN],'NEEDS_REVIEW'),
    (UNKNOWN,'NEEDS_REVIEW'),([{'TextBoxes':UNKNOWN}],'NEEDS_REVIEW'),
    ([{'Visuals':[visual('A'),visual('a')]}],'PASS'),([], 'PASS')])
def test_element_ids(kind,sheets,expected):
    assert check('QuickSight::'+kind,Definition={'Sheets':sheets})[0]['verdict']==expected


def test_pinned_visual_members():
    root=Path(__file__).resolve().parents[1]
    with zipfile.ZipFile(root/'schemas/CloudformationSchema.zip') as z:
        for kind in ('analysis','dashboard','template'):
            schema=json.loads(z.read('aws-quicksight-'+kind+'.json'))
            assert set(schema['definitions']['Visual']['properties'])==VISUALS


def schedule(id,interval='HOURLY',dataset='dataset',sid=None,account='111111111111'):
    return target(id,'AWS::QuickSight::RefreshSchedule',AwsAccountId=account,DataSetId=dataset,
                  Schedule={'ScheduleId':sid or id,'ScheduleFrequency':{'Interval':interval}})


@pytest.mark.parametrize('first,second,expected',[
    ('MINUTE15','MINUTE15','FAIL'),('MINUTE15','MINUTE30','FAIL'),('HOURLY','DAILY','FAIL'),
    ('DAILY','HOURLY','FAIL'),('WEEKLY','MONTHLY','PASS'),('MINUTE30','MONTHLY','FAIL'),
    ('HOURLY',UNKNOWN,'NEEDS_REVIEW'),(UNKNOWN,'HOURLY','NEEDS_REVIEW')])
def test_schedule_intervals(first,second,expected):
    a=schedule('a',first);b=schedule('b',second)
    assert analytics_checks(linked_design(a,[b]),a)[0]['verdict']==expected


@pytest.mark.parametrize('mode,expected',[
    ('distinct_dataset','PASS'),('unknown_dataset','NEEDS_REVIEW'),('same_schedule','NEEDS_REVIEW'),
    ('distinct_scope','PASS'),('unknown_account','NEEDS_REVIEW'),('wrong_account','NEEDS_REVIEW'),
    ('unknown_scope','NEEDS_REVIEW'),('single','PASS')])
def test_schedule_identity(mode,expected):
    a=schedule('a');b=schedule('b')
    if mode=='distinct_dataset':b=schedule('b',dataset='other')
    if mode=='unknown_dataset':b=schedule('b',dataset=UNKNOWN)
    if mode=='same_schedule':b=schedule('b',sid='a')
    if mode=='distinct_scope':b.scope.region='us-east-1'
    if mode=='unknown_account':a=schedule('a',account=UNKNOWN)
    if mode=='wrong_account':a=schedule('a',account='222222222222')
    if mode=='unknown_scope':a.scope.region='unknown'
    assert analytics_checks(linked_design(a,[] if mode=='single' else [b]),a)[0]['verdict']==expected


@pytest.mark.parametrize('mode,expected',[
    ('same_link','FAIL'),('different_link','PASS'),('mixed','NEEDS_REVIEW'),
    ('conditional','NEEDS_REVIEW'),('unknown_link_value','NEEDS_REVIEW'),('wrong_type','NEEDS_REVIEW'),
    ('dataset_account_unknown','NEEDS_REVIEW')])
def test_linked_schedules(mode,expected):
    a=schedule('a');b=schedule('b')
    ds=target('ds','AWS::QuickSight::DataSet',AwsAccountId='111111111111')
    ds2=target('ds2','AWS::QuickSight::DataSet',AwsAccountId='111111111111')
    d=linked_design(a,[b,ds,ds2],[('DataSetId','ds')])
    if mode!='mixed':d.relations.append(Relation(id='b-link',source_resource_id='b',source_path='/properties/DataSetId',target_resource_id='ds2' if mode=='different_link' else 'ds',evidence_ids=['e1']))
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='unknown_link_value':a.field('/properties/DataSetId').state=ValueState.UNRESOLVED
    if mode=='wrong_type':ds.type='AWS::S3::Bucket'
    if mode=='dataset_account_unknown':ds.field('/properties/AwsAccountId').state=ValueState.UNRESOLVED
    assert analytics_checks(d,a)[0]['verdict']==expected


@pytest.mark.parametrize('prefixes,expected',[
    (['a'*255],'PASS'),(['a'*256],'FAIL'),(['a'*128,'b'*128],'FAIL'),
    (['\u65e5'*85],'PASS'),(['\u65e5'*85,'a'],'FAIL'),(['\U0001f600'*64],'FAIL'),
    (['e\u0301'*85],'PASS'),(['%20'*85],'PASS'),(['a'*255,'*'],'FAIL'),
    ([], 'PASS'),([''], 'PASS'),([UNKNOWN],'NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW'),
    (['a'*256,UNKNOWN],'FAIL'),(['a',UNKNOWN],'NEEDS_REVIEW'),(['${prefix}'],'NEEDS_REVIEW'),
    (['\ud800'],'NEEDS_REVIEW'),([True],'NEEDS_REVIEW')])
def test_prefix_bytes(prefixes,expected):
    assert check('S3Express::AccessPoint',Scope={'Prefixes':prefixes})[0]['verdict']==expected


@pytest.mark.parametrize('strategy,expected',[
    ([{'CapacityProvider':'a','Base':0},{'CapacityProvider':'b','Weight':1}],'PASS'),
    ([{'CapacityProvider':'a','Base':0},{'CapacityProvider':'b','Base':0}],'FAIL'),
    ([{'CapacityProvider':'a','Base':1.0},{'CapacityProvider':'b','Base':2.0}],'FAIL'),
    ([{'CapacityProvider':'a','Base':1},{'CapacityProvider':'a','Base':2}],'NEEDS_REVIEW'),
    ([{'CapacityProvider':'a','Base':True}],'NEEDS_REVIEW'),([UNKNOWN],'NEEDS_REVIEW'),
    ([{'CapacityProvider':'a','Base':1},{'CapacityProvider':'b','Base':2},UNKNOWN],'FAIL')])
def test_scheduler_base(strategy,expected):
    assert check('Scheduler::Schedule',Target={'EcsParameters':{'CapacityProviderStrategy':strategy}})[0]['verdict']==expected


@pytest.mark.parametrize('features,expected',[
    (['text'],'PASS'),(['text',UNKNOWN],'PASS'),(['numerical'],'FAIL'),([], 'FAIL'),
    (['Text'],'FAIL'),([UNKNOWN],'NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_feature_types(features,expected):
    assert check('SageMaker::EndpointConfig',ExplainerConfig={'ClarifyExplainerConfig':{'InferenceConfig':{'FeatureTypes':features}}})[0]['verdict']==expected


@pytest.mark.parametrize('params,expected',[
    ({'a':{'NumberValue':0}},'PASS'),({'a':{'StringValue':''}},'PASS'),
    ({'a':{'NumberValue':0,'StringValue':''}},'FAIL'),
    ({'a':{'NumberValue':UNKNOWN,'StringValue':'x'}},'NEEDS_REVIEW'),
    ({'a/b':{'NumberValue':0,'StringValue':'x'}},'NEEDS_REVIEW'),
    ({'a~b':{'NumberValue':0,'StringValue':'x'}},'NEEDS_REVIEW'),
    ({'a':{}},'NEEDS_REVIEW'),({'a':UNKNOWN},'NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW'),
    ({'a':{'NumberValue':True}},'NEEDS_REVIEW'),
    ({'a':{'NumberValue':1,'StringValue':'x'},'b':UNKNOWN},'FAIL')])
def test_parameter_union(params,expected):
    assert check('SageMaker::TrialComponent',Parameters=params)[0]['verdict']==expected


def test_absence_and_independent_resources():
    assert check('QuickSight::Analysis',SourceEntity={})==[]
    assert check('S3Express::AccessPoint',Scope={})==[]
    a=target('a','AWS::QuickSight::Analysis',Definition={'Sheets':[{'Visuals':[visual('same')]}]})
    b=target('b','AWS::QuickSight::Analysis',Definition={'Sheets':[{'Visuals':[visual('same')]}]})
    assert analytics_checks(linked_design(a,[b]),a)[0]['verdict']=='PASS'


def test_checker_integration():
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('subject','AWS::S3Express::AccessPoint',Scope={'Prefixes':['a'*256]})
    row=next(x for x in Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results'] if x['rule_id']=='S3EXPRESS_PREFIX_BYTES')
    assert row['verdict']=='FAIL' and row['source_urls'] and row['evidence_ids']
