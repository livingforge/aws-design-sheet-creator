import json
import pytest
from aws_design_sheet.checks.rum.custom_dimensions import evaluate_rum_custom_dimensions
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


def fixture(pattern=None,keys=None,namespace='Custom',destination='CloudWatch'):
    pattern=pattern if pattern is not None else {'event_type':['custom'],'event_details':{'url':['example.com']}}
    metric={'Name':'Visits','Namespace':namespace,'DimensionKeys':keys if keys is not None else {'event_details.url':'URL'},'EventPattern':pattern if isinstance(pattern,str) else json.dumps(pattern)}
    r=target('rum','AWS::RUM::AppMonitor',AppMonitorConfiguration={'MetricDestinations':[{'Destination':destination,'MetricDefinitions':[metric]}]})
    return linked_design(r),r,metric


def verdict(d,r):return evaluate_rum_custom_dimensions(d,r)[0]['verdict']


@pytest.mark.parametrize('pattern,want',[
    ({'event_type':['custom'],'event_details':{'url':['example.com']}},'PASS'),
    ({'event_type':['custom'],'event_details':{'other':['x']}},'FAIL'),
    ({'event_type':['custom']},'FAIL'),
    ({'event_details.url':['example.com']},'NEEDS_REVIEW'),
    ({'event_details':{'url':[]}},'NEEDS_REVIEW'),
    ({'event_details':{'url':'value'}},'NEEDS_REVIEW'),
    ('{"event_details":{"url":["a"],"url":["b"]}}','NEEDS_REVIEW'),
    ('{"event_details":{"url":["${dynamic}"]}}','NEEDS_REVIEW'),
    ('{bad json','NEEDS_REVIEW'),('[]','NEEDS_REVIEW')])
def test_json_path_membership(pattern,want):
    d,r,*_=fixture(pattern);assert verdict(d,r)==want


@pytest.mark.parametrize('keys,want',[
    ({'event_details.url':'URL','metadata.browserName':'Browser'},'FAIL'),
    ({},'NOT_APPLICABLE'),(UNKNOWN,'NEEDS_REVIEW'),
    ({'event_details["url"]':'URL'},'NEEDS_REVIEW'),
    ({'unknown.url':'URL'},'NEEDS_REVIEW')])
def test_dimension_paths(keys,want):
    d,r,*_=fixture(keys=keys);assert verdict(d,r)==want


@pytest.mark.parametrize('namespace,destination,want',[
    ('AWS/RUM','CloudWatch','NOT_APPLICABLE'),('Custom','Evidently','NOT_APPLICABLE'),
    (UNKNOWN,'CloudWatch','NEEDS_REVIEW'),('Custom',UNKNOWN,'NEEDS_REVIEW')])
def test_metric_applicability(namespace,destination,want):
    d,r,*_=fixture(namespace=namespace,destination=destination);assert verdict(d,r)==want


def test_nested_custom_field():
    d,r,*_=fixture({'event_details':{'interaction':{'action':['click']}}},{'event_details.interaction.action':'Action'})
    assert verdict(d,r)=='PASS'


def test_unknown_ancestor():
    d,r,*_=fixture();r.fields[0].candidates[0].value=UNKNOWN
    assert verdict(d,r)=='NEEDS_REVIEW'


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    d,r,*_=fixture();root=Path(__file__).resolve().parents[1]
    results=Checker(root/"schemas",root/"profiles/vpc-subnet.json").check(d)["results"]
    assert any(f["rule_id"]=="RUM_CUSTOM_DIMENSION_PATTERN" and f["verdict"]=="PASS" for f in results)
