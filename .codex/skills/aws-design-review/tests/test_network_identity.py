import pytest
from aws_design_sheet.checks.neptune.subnet_group_azs import evaluate_neptune_subnet_group_azs
from aws_design_sheet.checks.networkfirewall.logging_name import evaluate_networkfirewall_logging_name
from aws_design_sheet.checks.registry import combine
network_identity_checks = combine(evaluate_neptune_subnet_group_azs, evaluate_networkfirewall_logging_name)
from aws_design_sheet.models import TemplateContext
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('mode',['distinct','same','missing_link','conditional','ambiguous','unknown_az','az_id','local_zone','scope','unknown_scope','template','subnet_template','unknown_list','empty'])
def test_zones(mode):
    r=target('main','AWS::Neptune::DBSubnetGroup',SubnetIds=UNKNOWN if mode=='unknown_list' else [] if mode=='empty' else ['one','two'])
    one=target('one','AWS::EC2::Subnet',AvailabilityZone='ap-northeast-1a')
    two=target('two','AWS::EC2::Subnet',**({'AvailabilityZoneId':'apne1-az2'} if mode=='az_id' else {'AvailabilityZone':UNKNOWN if mode=='unknown_az' else 'ap-northeast-1-tpe-1a' if mode=='local_zone' else 'ap-northeast-1a' if mode=='same' else 'ap-northeast-1b'}))
    d=linked_design(r,[one,two],[('SubnetIds/0','one')]+([] if mode=='missing_link' else [('SubnetIds/1','two')]))
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='ambiguous':d.relations.append(d.relations[0].model_copy(update={'id':'duplicate'}))
    if mode=='scope':two.scope.region='us-east-1'
    if mode=='unknown_scope':r.scope.account=one.scope.account=two.scope.account='unknown'
    if mode=='template':r.template=TemplateContext(state='UNRESOLVED')
    if mode=='subnet_template':two.template=TemplateContext(state='UNRESOLVED')
    assert network_identity_checks(d,r)[0]['verdict']==('PASS' if mode=='distinct' else 'FAIL' if mode=='same' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('mode',['same','different','unknown_name','unknown_target','external','conditional','ambiguous','scope','template','target_template'])
def test_firewall(mode):
    r=target('main','AWS::NetworkFirewall::LoggingConfiguration',FirewallArn='firewall',FirewallName=UNKNOWN if mode=='unknown_name' else 'name')
    f=target('firewall','AWS::NetworkFirewall::Firewall',FirewallName=UNKNOWN if mode=='unknown_target' else 'different' if mode=='different' else 'name')
    d=linked_design(r,[f],[] if mode=='external' else [('FirewallArn','firewall')])
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='ambiguous':d.relations.append(d.relations[0].model_copy(update={'id':'duplicate'}))
    if mode=='scope':f.scope.account='222222222222'
    if mode=='template':r.template=TemplateContext(state='UNRESOLVED')
    if mode=='target_template':f.template=TemplateContext(state='UNRESOLVED')
    assert network_identity_checks(d,r)[0]['verdict']==('PASS' if mode=='same' else 'FAIL' if mode=='different' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('kind',['AWS::Neptune::DBSubnetGroup','AWS::NetworkFirewall::LoggingConfiguration'])
def test_absent(kind):
    r=target('main',kind)
    assert not network_identity_checks(linked_design(r),r)
