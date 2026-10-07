from pathlib import Path
import pytest
from aws_design_sheet.checks.m2.maintenance_duration import evaluate_m2_maintenance_duration
from aws_design_sheet.checks.macie.text_and_collection_bounds import evaluate_macie_text_and_collection_bounds
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from aws_design_sheet.checks.registry import combine
service_bounds_checks=combine(evaluate_m2_maintenance_duration,evaluate_macie_text_and_collection_bounds)


def check(kind,**props):
    r=target('subject','AWS::'+kind,**props)
    return service_bounds_checks(linked_design(r),r)


@pytest.mark.parametrize('raw,expected',[
    ('mon:00:00-mon:23:59','PASS'),('mon:00:00-tue:00:00','FAIL'),('mon:00:00-tue:00:01','FAIL'),
    ('sun:23:45-mon:00:15','PASS'),('sun:12:00-mon:12:00','FAIL'),
    ('mon:00:00-sun:23:59','FAIL'),('mon:00:00-mon:00:00','NEEDS_REVIEW'),
    ('mon:24:00-tue:00:30','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_m2_window(raw,expected):
    assert check('M2::Environment',PreferredMaintenanceWindow=raw)[0]['verdict']==expected


@pytest.mark.parametrize('kind,key,low,high',[
    ('AllowList','Name',1,128),('AllowList','Description',1,512),('AllowList','Criteria/Regex',1,512),
    ('CustomDataIdentifier','Name',1,128),('CustomDataIdentifier','Description',1,512),('CustomDataIdentifier','Regex',1,512),
    ('FindingsFilter','Name',3,64),('FindingsFilter','Description',1,512)])
@pytest.mark.parametrize('boundary',['below','low','high','above','unknown'])
def test_text_bounds(kind,key,low,high,boundary):
    n={'below':low-1,'low':low,'high':high,'above':high+1}.get(boundary)
    raw=UNKNOWN if n is None else '字'*n
    props={'Criteria':{'Regex':raw}} if '/' in key else {key:raw}
    expected='NEEDS_REVIEW' if n is None else 'FAIL' if boundary in ('below','above') else 'PASS'
    assert check('Macie::'+kind,**props)[0]['verdict']==expected


@pytest.mark.parametrize('key,limit,minimum',[('Keywords',50,3),('IgnoreWords',10,4)])
@pytest.mark.parametrize('mode',['empty','minimum','maximum_length','short','long','limit','over','unknown','partial','known_over'])
def test_word_bounds(key,limit,minimum,mode):
    values={
        'empty':[],'minimum':['a'*minimum],'maximum_length':['a'*90],
        'short':['a'*(minimum-1)],'long':['a'*91],'limit':['abcd']*limit,
        'over':['abcd']*(limit+1),'unknown':UNKNOWN,'partial':['abcd',UNKNOWN],
        'known_over':['abcd']*(limit+1)+[UNKNOWN]}
    expected='FAIL' if mode in ('empty','short','long','over','known_over') else 'NEEDS_REVIEW' if mode in ('unknown','partial') else 'PASS'
    assert check('Macie::CustomDataIdentifier',**{key:values[mode]})[0]['verdict']==expected


@pytest.mark.parametrize('n,expected',[(0,'FAIL'),(1,'PASS'),(300,'PASS'),(301,'FAIL'),(True,'NEEDS_REVIEW'),('2','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_distance(n,expected):
    assert check('Macie::CustomDataIdentifier',MaximumMatchDistance=n)[0]['verdict']==expected


def test_regex_not_executed():
    assert check('Macie::CustomDataIdentifier',Regex='(a+)+$')[0]['verdict']=='PASS'
    assert check('Macie::CustomDataIdentifier',Regex='${Expression}')[0]['verdict']=='NEEDS_REVIEW'


def test_checker_integration():
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('subject','AWS::M2::Environment',PreferredMaintenanceWindow='mon:00:00-tue:00:00')
    result=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))
    row=next(x for x in result['results'] if x['rule_id']=='M2_MAINTENANCE_DURATION')
    assert row['verdict']=='FAIL' and row['source_urls'] and row['evidence_ids']
