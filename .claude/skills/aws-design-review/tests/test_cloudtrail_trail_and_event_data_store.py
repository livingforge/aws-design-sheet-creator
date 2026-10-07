from pathlib import Path
import pytest
from aws_design_sheet.checks.cloudtrail.trail_and_event_data_store import evaluate_cloudtrail_trail_and_event_data_store
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


def check(kind,props,rule):
    r=target('main','AWS::CloudTrail::'+kind,**props)
    return [x for x in evaluate_cloudtrail_trail_and_event_data_store(linked_design(r),r) if x['rule_id']==rule]


@pytest.mark.parametrize('raw,expected',[('$StartTime$','PASS'),('$EndTime$','PASS'),('$Period$','PASS'),('$Other$','FAIL'),(UNKNOWN,'NEEDS_REVIEW'),('${P}','NEEDS_REVIEW')])
def test_widget(raw,expected):
    assert check('Dashboard',{'Widgets':[{'QueryParameters':[raw]}]},'CLOUDTRAIL_WIDGET_PARAMETERS')[0]['verdict']==expected


@pytest.mark.parametrize('raw',[UNKNOWN,[UNKNOWN]])
def test_unknown_widget(raw):
    assert check('Dashboard',{'Widgets':raw},'CLOUDTRAIL_WIDGET_PARAMETERS')[0]['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('category,expected',[('Insight','PASS'),('Management','FAIL'),('Data','FAIL'),('Future','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
@pytest.mark.parametrize('mode',['linked','literal','conditional','scope'])
def test_destination(category,expected,mode):
    r=target('main','AWS::CloudTrail::EventDataStore',InsightsDestination='dest')
    d=target('dest','AWS::CloudTrail::EventDataStore',AdvancedEventSelectors=[{'FieldSelectors':[{'Field':'eventCategory','Equals':[category]}]}])
    design=linked_design(r,[d],[] if mode=='literal' else [('InsightsDestination','dest')])
    if mode=='conditional':design.relations[0].condition='Maybe'
    if mode=='scope':d.scope.account='222222222222'
    assert evaluate_cloudtrail_trail_and_event_data_store(design,r)[0]['verdict']==(expected if mode=='linked' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('counts,expected',[([250],'PASS'),([251],'FAIL'),([125,125],'PASS'),([125,126],'FAIL'),([],'PASS')])
def test_aggregate(counts,expected):
    selectors=[];offset=0
    for count in counts:
        selectors.append({'DataResources':[{'Type':'AWS::S3::Object','Values':[f'arn:aws:s3:::bucket{i}/' for i in range(offset,offset+count)]}]});offset+=count
    assert check('Trail',{'EventSelectors':selectors},'CLOUDTRAIL_DATA_RESOURCE_TOTAL')[0]['verdict']==expected


@pytest.mark.parametrize('extra',[UNKNOWN,'arn:aws:s3','arn:aws:lambda','arn:aws:dynamodb','arn:aws:s3:::bucket/*'])
def test_all_resource_exception(extra):
    values=[f'arn:aws:s3:::bucket{i}/' for i in range(251)]+[extra]
    assert check('Trail',{'EventSelectors':[{'DataResources':[{'Values':values}]}]},'CLOUDTRAIL_DATA_RESOURCE_TOTAL')[0]['verdict']=='NEEDS_REVIEW'


def test_duplicate_count_held():
    assert check('Trail',{'EventSelectors':[{'DataResources':[{'Values':['arn:aws:s3:::bucket/']*251}]}]},'CLOUDTRAIL_DATA_RESOURCE_TOTAL')[0]['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('fields,expected',[
    ([], 'FAIL'),(UNKNOWN,'NEEDS_REVIEW'),([UNKNOWN],'NEEDS_REVIEW'),
    ([{'Field':'eventCategory','Equals':['Management']}],'PASS'),
    ([{'Field':'eventCategory','Equals':['Insight']}],'FAIL'),
    ([{'Field':'eventCategory','Equals':[UNKNOWN]}],'NEEDS_REVIEW'),
    ([{'Field':'eventCategory','StartsWith':['Data']}],'FAIL'),
    ([{'Field':'eventCategory','Equals':['Data']}],'FAIL'),
    ([{'Field':'eventCategory','Equals':['Data']},UNKNOWN],'NEEDS_REVIEW'),
    ([{'Field':'eventCategory','Equals':['Data']},{'Field':'resources.type','Equals':['AWS::S3::Object']}],'PASS'),
    ([{'Field':'eventCategory','Equals':['Data']},{'Field':'resources.type'},{'Field':'resources.type'}],'FAIL'),
    ([{'Field':'eventCategory','Equals':['NetworkActivity']}],'FAIL'),
    ([{'Field':'eventCategory','Equals':['NetworkActivity']},{'Field':'eventSource','Equals':['kms.amazonaws.com']}],'PASS'),
    ([{'Field':'eventCategory','Equals':['NetworkActivity']},{'Field':'eventSource','NotEquals':['kms.amazonaws.com']}],'FAIL'),
    ([{'Field':'eventCategory','Equals':['NetworkActivity']},{'Field':'eventSource','Equals':UNKNOWN}],'NEEDS_REVIEW'),
    ([{'Field':'eventCategory','Equals':['Management']},{'Field':'eventCategory','Equals':['Data']}],'NEEDS_REVIEW'),
],ids=range(16))
def test_advanced(fields,expected):
    assert check('Trail',{'AdvancedEventSelectors':[{'FieldSelectors':fields}]},'CLOUDTRAIL_ADVANCED_FIELD_REQUIREMENTS')[0]['verdict']==expected


def test_checker():
    r=target('main','AWS::CloudTrail::Trail',AdvancedEventSelectors=[{'FieldSelectors':[]}])
    root=Path(__file__).resolve().parents[1]
    result=next(x for x in Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results'] if x['rule_id']=='CLOUDTRAIL_ADVANCED_FIELD_REQUIREMENTS')
    assert result['verdict']=='FAIL' and result['source_urls']
