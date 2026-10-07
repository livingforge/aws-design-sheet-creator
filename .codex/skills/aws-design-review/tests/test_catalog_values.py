from pathlib import Path
import pytest
from aws_design_sheet.checks.servicecatalog.cloud_formation_product import evaluate_servicecatalog_cloud_formation_product
from aws_design_sheet.checks.pinpoint.apns_voip_sandbox_channel import evaluate_pinpoint_apns_voip_sandbox_channel
from aws_design_sheet.checks.registry import combine
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN
catalog_values_checks = combine(evaluate_servicecatalog_cloud_formation_product, evaluate_pinpoint_apns_voip_sandbox_channel)


def resource(kind,raw):
 if kind=='catalog':return target('main','AWS::ServiceCatalog::CloudFormationProduct',SourceConnection={'Type':raw})
 return target('main','AWS::Pinpoint::APNSVoipSandboxChannel',DefaultAuthenticationMethod=raw)


@pytest.mark.parametrize('kind,raw,expected',[
 ('catalog','CODESTAR','PASS'),('catalog','Codestar','FAIL'),('catalog','CodeStar','FAIL'),('catalog','OTHER','FAIL'),
 ('apns','key','PASS'),('apns','certificate','PASS'),('apns','KEY','FAIL'),('apns','token','FAIL')])
def test_values(kind,raw,expected):
 r=resource(kind,raw);assert catalog_values_checks(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('kind',['catalog','apns'])
@pytest.mark.parametrize('raw',[UNKNOWN,'${parameter}',{'Ref':'Param'},None,False],ids=['unknown','dynamic','ref','null','bool'])
def test_unknown(kind,raw):
 r=resource(kind,raw);assert catalog_values_checks(linked_design(r),r)[0]['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('kind',['AWS::ServiceCatalog::CloudFormationProduct','AWS::Pinpoint::APNSVoipSandboxChannel'])
def test_absent(kind):
 r=target('main',kind);assert not catalog_values_checks(linked_design(r),r)


@pytest.mark.parametrize('kind,key',[('AWS::ServiceCatalog::CloudFormationProduct','SourceConnection')])
def test_unknown_parent(kind,key):
 r=target('main',kind,**{key:UNKNOWN});assert catalog_values_checks(linked_design(r),r)[0]['verdict']=='NEEDS_REVIEW'


def test_checker():
 r=resource('catalog','OTHER');root=Path(__file__).resolve().parents[1]
 results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
 assert any(f['rule_id']=='SERVICECATALOG_SOURCE_CONNECTION_TYPE' and f['verdict']=='FAIL' for f in results)
