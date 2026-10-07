import pytest
from aws_design_sheet.models import Relation
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


def check(gateway='igw-123', linked_ids=False, missing_association=False, cross_scope=False, conditional=False):
    main=target('profile','AWS::EKS::FargateProfile',Subnets=[{'Ref':'subnet'}] if linked_ids else ['subnet-123'])
    subnet=target('subnet','AWS::EC2::Subnet')
    table=target('table','AWS::EC2::RouteTable')
    igw=target('gateway','AWS::EC2::InternetGateway')
    association=target('association','AWS::EC2::SubnetRouteTableAssociation',
        SubnetId={'Ref':'subnet'} if linked_ids else 'subnet-123',RouteTableId={'Ref':'table'} if linked_ids else 'rtb-123')
    route=target('route','AWS::EC2::Route',RouteTableId={'Ref':'table'} if linked_ids else 'rtb-123',
        GatewayId={'Ref':'gateway'} if linked_ids else gateway,DestinationCidrBlock='0.0.0.0/0')
    if cross_scope:
        route.scope.region='us-west-2'
    data=linked_design(main,[subnet,table,igw,route]+([] if missing_association else [association]))
    if linked_ids:
        for owner,path,dest in [(main,'Subnets/0','subnet'),(association,'SubnetId','subnet'),(association,'RouteTableId','table'),(route,'RouteTableId','table'),(route,'GatewayId','gateway')]:
            data.relations.append(Relation(id=owner.id+path,source_resource_id=owner.id,source_path='/properties/'+path,target_resource_id=dest,evidence_ids=['e1'],condition='condition' if conditional and owner==route else None))
    findings={r['rule_id']:r['verdict'] for r in run_resource_checks(data,main)}
    return findings['EKS_FARGATE_PRIVATE_SUBNET']


@pytest.mark.parametrize('linked_ids',[False,True])
def test_explicit_igw_route(linked_ids):
    assert check(linked_ids=linked_ids)=='FAIL'


@pytest.mark.parametrize('gateway',['vgw-123',UNKNOWN])
def test_non_igw_or_unknown_routes(gateway):
    assert check(gateway=gateway)=='NEEDS_REVIEW'


def test_missing_cross_scope_and_conditional_evidence():
    assert check(missing_association=True)=='NEEDS_REVIEW'
    assert check(cross_scope=True)=='NEEDS_REVIEW'
    assert check(linked_ids=True,conditional=True)=='NEEDS_REVIEW'
