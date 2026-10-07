import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.internetmonitor.monitor_gateway import evaluate_internetmonitor_monitor_gateway
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_template_dependencies import link

ARN='arn:aws:ec2:ap-northeast-1:111111111111:vpc/vpc-12345678'


def fixture(**props):
    r=target('main','AWS::InternetMonitor::Monitor',ResourcesToAdd=[ARN],**props)
    v=target('vpc','AWS::EC2::VPC');a=target('attachment','AWS::EC2::VPCGatewayAttachment',InternetGatewayId='igw-12345678')
    d=linked_design(r,[v,a],[('ResourcesToAdd/0','vpc')]);link(d,a,'VpcId',v)
    return d,r,v,a


@pytest.mark.parametrize('mode,expected',[(x,'PASS' if x in ('known','gateway_ref','one_of_two') else 'NEEDS_REVIEW') for x in ('known','gateway_ref','one_of_two','missing','condition','wrong_scope','unknown_template','wrong_arn_scope','unknown_arn','vpn','unknown_gateway')])
def test_gateway_evidence(mode,expected):
    d,r,v,a=fixture()
    if mode=='gateway_ref':g=target('gateway','AWS::EC2::InternetGateway');d.resources.append(g);link(d,a,'InternetGatewayId',g)
    if mode=='one_of_two':
        other=target('other','AWS::EC2::VPC');d.resources.append(other);r.fields[0].candidates[0].value.append(ARN.replace('12345678','87654321'));link(d,r,'ResourcesToAdd/1',other)
    if mode=='missing':d.resources.remove(a)
    if mode=='condition':d.relations[-1].condition='Maybe'
    if mode=='wrong_scope':a.scope.region='us-east-1'
    if mode=='unknown_template':a.template=TemplateContext(state='UNRESOLVED')
    if mode=='wrong_arn_scope':r.fields[0].candidates[0].value=[ARN.replace('ap-northeast-1','us-east-1')]
    if mode=='unknown_arn':r.fields[0].candidates[0].value=[UNKNOWN]
    if mode=='vpn':a.fields=target('x',a.type,VpnGatewayId='vgw-12345678').fields
    if mode=='unknown_gateway':a.fields[0].candidates[0].value=UNKNOWN
    assert evaluate_internetmonitor_monitor_gateway(d,r)[0]['verdict']==expected


@pytest.mark.parametrize('props',[{'Resources':[ARN]},{'ResourcesToRemove':[ARN]},{'IncludeLinkedAccounts':True},{'LinkedAccountId':'111122223333'}])
def test_external_monitor_context(props):
    d,r,*_=fixture(**props)
    assert evaluate_internetmonitor_monitor_gateway(d,r)[0]['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('arn',['arn:aws:cloudfront::123456789012:distribution/E123ABC','arn:aws:workspaces:ap-northeast-1:123456789012:directory/d-12345678','arn:aws:elasticloadbalancing:ap-northeast-1:123456789012:loadbalancer/net/name/123abc'])
def test_non_vpc_not_applicable(arn):
    d,r,*_=fixture();r.fields[0].candidates[0].value=[arn]
    assert evaluate_internetmonitor_monitor_gateway(d,r)[0]['verdict']=='NOT_APPLICABLE'


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    d,r,*_=fixture();root=Path(__file__).resolve().parents[1]
    actual=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results']
    assert any(f['rule_id']=='INTERNET_MONITOR_VPC_GATEWAY' and f['verdict']=='PASS' for f in actual)
