import pytest
from aws_design_sheet.checks.dax.network import evaluate_dax_network
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN
from test_template_dependencies import link


@pytest.mark.parametrize('case',['same','different','external_group','external_subnet','external_vpc','conditional','scope','empty','unknown','oversized','mixed_unknown','duplicate'])
@pytest.mark.parametrize('reverse',[False,True])
def test_subnet_group_identity(case,reverse):
    r=target('main','AWS::DAX::Cluster',SubnetGroupName='group')
    g=target('group','AWS::DAX::SubnetGroup',SubnetIds=[] if case=='empty' else UNKNOWN if case=='unknown' else ['s']*1001 if case=='oversized' else ['s','t','u'] if case=='mixed_unknown' else ['s','t'])
    s=target('s','AWS::EC2::Subnet',VpcId='v1');t=target('t','AWS::EC2::Subnet',VpcId='v2')
    v1=target('v1','AWS::EC2::VPC');v2=target('v2','AWS::EC2::VPC')
    d=linked_design(r,[g,s,t,v1,v2])
    if case!='external_group':link(d,r,'SubnetGroupName',g)
    link(d,g,'SubnetIds/0',s)
    if case!='external_subnet':link(d,g,'SubnetIds/1',t)
    link(d,s,'VpcId',v1)
    if case!='external_vpc':link(d,t,'VpcId',v2 if case in ('different','mixed_unknown') else v1)
    if case=='conditional':d.relations[-1].condition='maybe'
    if case=='scope':t.scope.account='222222222222'
    if case=='duplicate':link(d,g,'SubnetIds/1',s)
    if reverse:d.resources.reverse();d.relations.reverse()
    expected='PASS' if case=='same' else 'FAIL' if case in ('different','mixed_unknown') else 'NEEDS_REVIEW'
    assert evaluate_dax_network(d,r)[0]['verdict']==expected


def test_unrelated_type():
    r=target('other','AWS::DAX::SubnetGroup')
    assert evaluate_dax_network(linked_design(r),r)==[]
