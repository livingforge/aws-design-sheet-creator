from pathlib import Path
import pytest
from aws_design_sheet.checks.mediaconnect.accounts import evaluate_mediaconnect_accounts
from aws_design_sheet.checks.lakeformation.trusted_accounts import evaluate_lakeformation_trusted_accounts
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN
from aws_design_sheet.checks.registry import combine
media_accounts_checks=combine(evaluate_mediaconnect_accounts,evaluate_lakeformation_trusted_accounts)


@pytest.mark.parametrize('kind,key',[('AWS::MediaConnect::FlowEntitlement','Subscribers'),('AWS::LakeFormation::DataLakeSettings','TrustedResourceOwners')])
@pytest.mark.parametrize('raw,verdict',[('012345678901','PASS'),('12345678901','FAIL'),('1234567890123','FAIL'),('12345678901a','FAIL'),('１２３４５６７８９０１２','FAIL'),(' 123456789012','FAIL'),(UNKNOWN,'NEEDS_REVIEW'),('${account}','NEEDS_REVIEW'),(123456789012,'NEEDS_REVIEW'),('', 'NEEDS_REVIEW')])
def test_accounts(kind,key,raw,verdict):
    r=target('main',kind,**{key:[raw]})
    assert media_accounts_checks(linked_design(r),r)[0]['verdict']==verdict


@pytest.mark.parametrize('mode',['same','different','unknown','omitted','az_id','local_zone','external','conditional','ambiguous','account','region','template','subnet_template','unknown_scope'])
def test_az(mode):
    r=target('main','AWS::MediaConnect::Flow',VpcInterfaces=[{'SubnetId':'subnet'}],**({} if mode=='omitted' else {'AvailabilityZone':UNKNOWN if mode=='unknown' else 'ap-northeast-1a'}))
    s=target('subnet','AWS::EC2::Subnet',**({'AvailabilityZoneId':'apne1-az1'} if mode=='az_id' else {'AvailabilityZone':'ap-northeast-1b' if mode=='different' else 'ap-northeast-1-tpe-1a' if mode=='local_zone' else 'ap-northeast-1a'}))
    d=linked_design(r,[s],[] if mode=='external' else [('VpcInterfaces/0/SubnetId','subnet')])
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='ambiguous':d.relations.append(d.relations[0].model_copy(update={'id':'duplicate'}))
    if mode=='account':s.scope.account='222222222222'
    if mode=='region':s.scope.region='us-east-1'
    if mode=='unknown_scope':r.scope.account=s.scope.account='unknown'
    if mode=='template':r.template=TemplateContext(state='UNRESOLVED')
    if mode=='subnet_template':s.template=TemplateContext(state='UNRESOLVED')
    assert media_accounts_checks(d,r)[0]['verdict']==('PASS' if mode=='same' else 'FAIL' if mode=='different' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('kind',['AWS::MediaConnect::Flow','AWS::MediaConnect::FlowEntitlement','AWS::LakeFormation::DataLakeSettings'])
def test_absent(kind):
    r=target('main',kind)
    assert not media_accounts_checks(linked_design(r),r)


def test_unknown_list():
    r=target('main','AWS::MediaConnect::FlowEntitlement',Subscribers=UNKNOWN)
    assert media_accounts_checks(linked_design(r),r)[0]['verdict']=='NEEDS_REVIEW'


def test_checker_accounts():
    r=target('main','AWS::MediaConnect::FlowEntitlement',Subscribers=['invalid'])
    root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    assert any(f['rule_id']=='MEDIACONNECT_SUBSCRIBER_ACCOUNTS' and f['verdict']=='FAIL' for f in results)
