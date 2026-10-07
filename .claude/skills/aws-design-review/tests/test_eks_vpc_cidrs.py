import pytest
from aws_design_sheet.models import Relation
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


def check(primary='10.0.0.0/16', secondary=None, link_subnet=True, link_association=True):
    cluster=target('cluster','AWS::EKS::Cluster',KubernetesNetworkConfig={'ServiceIpv4Cidr':'172.20.0.0/16'},ResourcesVpcConfig={'SubnetIds':[{'Ref':'subnet'}]})
    subnet=target('subnet','AWS::EC2::Subnet',VpcId={'Ref':'vpc'})
    vpc=target('vpc','AWS::EC2::VPC',CidrBlock=primary)
    data=linked_design(cluster,[subnet,vpc],[('ResourcesVpcConfig/SubnetIds/0','subnet')] if link_subnet else [])
    data.relations.append(Relation(id='subnet-vpc',source_resource_id='subnet',source_path='/properties/VpcId',target_resource_id='vpc',evidence_ids=['e1']))
    if secondary is not None:
        association=target('secondary','AWS::EC2::VPCCidrBlock',VpcId={'Ref':'vpc'},CidrBlock=secondary)
        data.resources.append(association)
        if link_association:
            data.relations.append(Relation(id='secondary-vpc',source_resource_id='secondary',source_path='/properties/VpcId',target_resource_id='vpc',evidence_ids=['e1']))
    findings={r['rule_id']:r['verdict'] for r in run_resource_checks(data,cluster)}
    return findings['EKS_SERVICE_VPC_CIDR_OVERLAP']


@pytest.mark.parametrize('primary,expected',[
    ('10.0.0.0/16','PASS'),('172.20.0.0/16','FAIL'),('172.16.0.0/12','FAIL'),
    ('172.20.1.0/24','FAIL'),('172.21.0.0/16','PASS'),(UNKNOWN,'NEEDS_REVIEW'),
])
def test_primary_range(primary,expected):
    assert check(primary)==expected


def test_secondary_ranges_and_unknowns():
    assert check(secondary='172.20.0.0/20')=='FAIL'
    assert check(secondary='192.168.0.0/16')=='PASS'
    assert check(secondary=UNKNOWN)=='NEEDS_REVIEW'
    assert check(secondary='172.20.0.0/20',link_association=False)=='NEEDS_REVIEW'
    assert check(link_subnet=False)=='NEEDS_REVIEW'


def test_proven_overlap_wins_over_unknown_primary():
    assert check(primary=UNKNOWN,secondary='172.20.0.0/20')=='FAIL'
