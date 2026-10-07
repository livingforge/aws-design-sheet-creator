import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.directconnect.relations import evaluate_directconnect_relations
from test_autoscaling_group_and_scaling_policy import target,linked_design
from test_template_dependencies import link


@pytest.mark.parametrize('speed,location,expected',[('10Gbps','EqSY3','PASS'),('10000Mbps','EqSY3','PASS'),('1Gbps','EqSY3','FAIL'),('10Gbps','Other','FAIL'),({'$state':'UNRESOLVED'},'EqSY3','NEEDS_REVIEW')])
@pytest.mark.parametrize('mode',['known','conditional','template','region'])
def test_lag_settings(speed,location,expected,mode):
    r=target('lag','AWS::DirectConnect::Lag',ConnectionsBandwidth='10Gbps',Location='EqSY3')
    member=target('member','AWS::DirectConnect::Connection',Bandwidth=speed,Location=location,LagId='lag')
    d=linked_design(r,[member],[]);link(d,member,'LagId',r,'maybe' if mode=='conditional' else None)
    if mode=='template':member.template=TemplateContext(state='UNRESOLVED')
    if mode=='region':member.scope.region='us-east-1'
    assert evaluate_directconnect_relations(d,r)[0]['verdict']==(expected if mode=='known' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('dc,tg,expected',[('64512',64512,'FAIL'),('64512',65000,'PASS'),('missing','missing','FAIL'),('missing',65000,'PASS'),({'$state':'UNRESOLVED'},65000,'NEEDS_REVIEW'),('64512',{'$state':'UNRESOLVED'},'NEEDS_REVIEW'),('4200000000',4200000001,'PASS')])
@pytest.mark.parametrize('mode',['known','conditional','template','cross_region','cross_account'])
def test_gateway_asns(dc,tg,expected,mode):
    r=target('vif','AWS::DirectConnect::TransitVirtualInterface',DirectConnectGatewayId='gateway')
    gateway=target('gateway','AWS::DirectConnect::DirectConnectGateway',**({} if dc=='missing' else {'AmazonSideAsn':dc}))
    peer=target('peer','AWS::EC2::TransitGateway',**({} if tg=='missing' else {'AmazonSideAsn':tg}))
    association=target('association','AWS::DirectConnect::DirectConnectGatewayAssociation',DirectConnectGatewayId='gateway',AssociatedGatewayId='peer')
    d=linked_design(r,[gateway,peer,association],[('DirectConnectGatewayId','gateway')])
    link(d,association,'DirectConnectGatewayId',gateway);link(d,association,'AssociatedGatewayId',peer,'maybe' if mode=='conditional' else None)
    if mode=='template':peer.template=TemplateContext(state='UNRESOLVED')
    if mode=='cross_region':gateway.scope.region='us-east-1';peer.scope.region='eu-west-1'
    if mode=='cross_account':gateway.scope.account='222222222222'
    assert evaluate_directconnect_relations(d,r)[0]['verdict']==(expected if mode in ('known','cross_region','cross_account') else 'NEEDS_REVIEW')


@pytest.mark.parametrize('mode',['source_template','gateway_template','association_template','contradictory_arn','duplicate_reference'])
def test_gateway_unknown_chain(mode):
    r=target('vif','AWS::DirectConnect::TransitVirtualInterface',DirectConnectGatewayId='gateway')
    gateway=target('gateway','AWS::DirectConnect::DirectConnectGateway')
    peer=target('peer','AWS::EC2::TransitGateway')
    association=target('association','AWS::DirectConnect::DirectConnectGatewayAssociation',DirectConnectGatewayId='gateway',AssociatedGatewayId='peer')
    d=linked_design(r,[gateway,peer,association],[('DirectConnectGatewayId','gateway')]);link(d,association,'DirectConnectGatewayId',gateway);link(d,association,'AssociatedGatewayId',peer)
    if mode=='source_template':r.template=TemplateContext(state='UNRESOLVED')
    if mode=='gateway_template':gateway.template=TemplateContext(state='UNRESOLVED')
    if mode=='association_template':association.template=TemplateContext(state='UNRESOLVED')
    if mode=='contradictory_arn':r.fields[0].candidates[0].value='arn:aws:directconnect::222222222222:dx-gateway/12345678-1234-1234-1234-123456789abc'
    if mode=='duplicate_reference':d.relations.append(d.relations[0].model_copy(update={'id':'duplicate'}))
    assert evaluate_directconnect_relations(d,r)[0]['verdict']=='NEEDS_REVIEW'


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('lag','AWS::DirectConnect::Lag',ConnectionsBandwidth='10Gbps',Location='EqSY3')
    member=target('member','AWS::DirectConnect::Connection',Bandwidth='1Gbps',Location='EqSY3',LagId='lag')
    d=linked_design(r,[member],[]);link(d,member,'LagId',r)
    assert any(f['rule_id']=='DIRECTCONNECT_LAG_MEMBER_SETTINGS' and f['verdict']=='FAIL' for f in Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results'])
