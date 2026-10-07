import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.networkmanager.transport import evaluate_networkmanager_transport
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_template_dependencies import link


def fixture(kind='AWS::NetworkManager::VpcAttachment'):
    r=target('connect','AWS::NetworkManager::ConnectAttachment')
    vpc=target('transport',kind)
    d=linked_design(r,[vpc]);link(d,r,'TransportAttachmentId',vpc)
    return d,r,vpc


@pytest.mark.parametrize('kind,expected',[
    ('AWS::NetworkManager::VpcAttachment','PASS'),
    ('AWS::NetworkManager::ConnectAttachment','FAIL'),
    ('AWS::NetworkManager::SiteToSiteVpnAttachment','FAIL'),
    ('AWS::EC2::TransitGatewayVpcAttachment','FAIL'),('AWS::EC2::VPC','FAIL')])
def test_transport_resource_type(kind,expected):
    d,r,*_=fixture(kind)
    assert evaluate_networkmanager_transport(d,r)[0]['verdict']==expected


@pytest.mark.parametrize('mode',['literal','unknown','conditional','missing','duplicate','scope','template'])
def test_identity_uncertainty(mode):
    d,r,t=fixture()
    if mode in ('literal','unknown'):r.fields+=target('dummy',r.type,TransportAttachmentId='attachment-12345678' if mode=='literal' else UNKNOWN).fields
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='missing':d.resources.remove(t)
    if mode=='duplicate':link(d,r,'TransportAttachmentId',t)
    if mode=='scope':t.scope.region='us-east-1'
    if mode=='template':t.template=TemplateContext(state='UNRESOLVED')
    assert evaluate_networkmanager_transport(d,r)[0]['verdict']=='NEEDS_REVIEW'


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    d,r,*_=fixture();root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results']
    assert any(f['rule_id']=='NETWORK_MANAGER_CONNECT_TRANSPORT_TYPE' and f['verdict']=='PASS' for f in results)
