import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.networkfirewall.firewall_association import evaluate_networkfirewall_firewall_association
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_template_dependencies import link


def fixture(az='ap-northeast-1b'):
    r=target('assoc','AWS::NetworkFirewall::VpcEndpointAssociation',SubnetMapping={})
    fw=target('fw','AWS::NetworkFirewall::Firewall',SubnetMappings=[{},{}])
    own=target('own','AWS::EC2::Subnet',VpcId='vpc-11111111',AvailabilityZone=az)
    ss=[target(n,'AWS::EC2::Subnet',VpcId='vpc-22222222',AvailabilityZone='ap-northeast-1'+z) for n,z in [('a','a'),('b','b')]]
    d=linked_design(r,[fw,own]+ss);link(d,r,'FirewallArn',fw);link(d,r,'SubnetMapping/SubnetId',own)
    for i,s in enumerate(ss):link(d,fw,f'SubnetMappings/{i}/SubnetId',s)
    return d,r,fw,own,ss


def verdict(d,r):return evaluate_networkfirewall_firewall_association(d,r)[0]['verdict']


@pytest.mark.parametrize('az,want',[('ap-northeast-1a','PASS'),('ap-northeast-1b','PASS'),('ap-northeast-1c','FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_coverage_across_different_vpcs(az,want):
    d,r,*_=fixture(az);assert verdict(d,r)==want


@pytest.mark.parametrize('mode',['literal','conditional','missing','duplicate','cross_account','region','template','unknown_list','empty_list','missing_subnet','unknown_zone'])
def test_unresolved_evidence(mode):
    d,r,fw,own,ss=fixture('ap-northeast-1c')
    if mode=='literal':r.fields+=target('dummy',r.type,FirewallArn='arn:aws:network-firewall:ap-northeast-1:111111111111:firewall/fw').fields
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='missing':d.resources.remove(fw)
    if mode=='duplicate':link(d,r,'FirewallArn',fw)
    if mode=='cross_account':fw.scope.account='222222222222'
    if mode=='region':fw.scope.region='us-east-1'
    if mode=='template':fw.template=TemplateContext(state='UNRESOLVED')
    if mode=='unknown_list':fw.fields[0].candidates[0].value=UNKNOWN
    if mode=='empty_list':fw.fields[0].candidates[0].value=[]
    if mode=='missing_subnet':d.resources.remove(ss[0])
    if mode=='unknown_zone':ss[0].fields[1].candidates[0].value=UNKNOWN
    assert verdict(d,r)=='NEEDS_REVIEW'


def test_one_known_match_suffices():
    d,r,fw,own,ss=fixture();d.resources.remove(ss[0])
    assert verdict(d,r)=='PASS'


def test_contradictory_name_and_id():
    d,r,fw,own,ss=fixture()
    own.fields+=target('dummy',own.type,AvailabilityZoneId='apne1-az3').fields
    ss[1].fields+=target('dummy',own.type,AvailabilityZoneId='apne1-az2').fields
    assert verdict(d,r)=='NEEDS_REVIEW'


def test_az_ids_without_names():
    d,r,fw,own,ss=fixture()
    for s in [own]+ss:s.fields=target('dummy',s.type,AvailabilityZoneId='apne1-az2').fields
    assert verdict(d,r)=='PASS'


def test_same_subnet_reference():
    d,r,fw,own,ss=fixture();d.relations[1].target_resource_id=ss[0].id
    assert verdict(d,r)=='PASS'


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    d,r,*_=fixture();root=Path(__file__).resolve().parents[1]
    results=Checker(root/"schemas",root/"profiles/vpc-subnet.json").check(d)["results"]
    assert any(f["rule_id"]=="NETWORK_FIREWALL_ASSOCIATION_AZ" and f["verdict"]=="PASS" for f in results)
