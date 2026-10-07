"""Boundaries, unresolved references and Checker integration for T1 follow-up."""
import base64
from pathlib import Path

import pytest

from aws_design_sheet.checker import Checker
from aws_design_sheet.models import Relation
from aws_design_sheet.checks.registry import combine
from aws_design_sheet.checks.rds.parameter_groups import rds_parameter_groups
from aws_design_sheet.checks.ec2.volumes_peering_and_templates import peering_role, vpn_address_type, enclave_roles, ebs_ranges, template_placement, template_consumers
pending_checks = combine(rds_parameter_groups, peering_role, vpn_address_type, enclave_roles, ebs_ranges, template_placement, template_consumers)
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN
from test_autoscaling_group_nested_constraints import design


ROOT = Path(__file__).resolve().parents[1]


def rows(resource, data=None):
    return {r['rule_id']: r for r in pending_checks(data or design(resource), resource)}


@pytest.mark.parametrize('properties,expected', [
    ({}, 'NOT_APPLICABLE'), ({'PeerOwnerId': '111111111111'}, 'NOT_APPLICABLE'),
    ({'PeerOwnerId': '222222222222'}, 'FAIL'),
    ({'PeerOwnerId': '222222222222', 'PeerRoleArn': 'arn:aws:iam::222222222222:role/peer'}, 'PASS'),
    ({'PeerOwnerId': UNKNOWN}, 'NEEDS_REVIEW'),
    ({'PeerOwnerId': '222222222222', 'PeerRoleArn': UNKNOWN}, 'NEEDS_REVIEW'),
])
def test_peering_account_role(properties, expected):
    resource = target('peer', 'AWS::EC2::VPCPeeringConnection', **properties)
    assert rows(resource)['EC2_PEERING_CROSS_ACCOUNT_ROLE']['verdict'] == expected


def test_peering_role_reference_is_not_absent():
    resource = target('peer', 'AWS::EC2::VPCPeeringConnection', PeerOwnerId='222222222222')
    role = target('role', 'AWS::IAM::Role')
    assert rows(resource, linked_design(resource, [role], [('PeerRoleArn', 'role')]))[
        'EC2_PEERING_CROSS_ACCOUNT_ROLE']['verdict'] == 'NEEDS_REVIEW'


@pytest.mark.parametrize('address,mode,expected', [
    ('10.0.0.1', 'PrivateIpv4', 'PASS'), ('10.0.0.1', 'PublicIpv4', 'FAIL'),
    ('100.64.0.1', 'PublicIpv4', 'FAIL'), ('172.16.0.1', 'PrivateIpv4', 'PASS'),
    ('192.168.0.1', 'Ipv6', 'FAIL'), ('8.8.8.8', 'PublicIpv4', 'PASS'),
    ('2001:db8::1', 'Ipv6', 'PASS'), ('2001:db8::1', 'PublicIpv4', 'FAIL'),
    ('8.8.8.8', 'Ipv6', 'FAIL'), (UNKNOWN, 'PrivateIpv4', 'NEEDS_REVIEW'),
    ('10.0.0.1', UNKNOWN, 'NEEDS_REVIEW'),
])
def test_customer_gateway_address_type(address, mode, expected):
    vpn = target('vpn', 'AWS::EC2::VPNConnection', CustomerGatewayId='gateway', OutsideIpAddressType=mode)
    gateway = target('gateway', 'AWS::EC2::CustomerGateway', IpAddress=address)
    data = linked_design(vpn, [gateway], [('CustomerGatewayId', 'gateway')])
    assert rows(vpn, data)['EC2_VPN_CUSTOMER_GATEWAY_ADDRESS_TYPE']['verdict'] == expected
    assert rows(vpn)['EC2_VPN_CUSTOMER_GATEWAY_ADDRESS_TYPE']['verdict'] == 'NEEDS_REVIEW'


def test_vpn_default_and_unresolved_link():
    vpn = target('vpn', 'AWS::EC2::VPNConnection', CustomerGatewayId=UNKNOWN)
    gateway = target('gateway', 'AWS::EC2::CustomerGateway', IpAddress='10.0.0.1')
    data = linked_design(vpn, [gateway], [('CustomerGatewayId', 'gateway')])
    assert rows(vpn, data)['EC2_VPN_CUSTOMER_GATEWAY_ADDRESS_TYPE']['verdict'] == 'NEEDS_REVIEW'
    vpn.fields.clear()  # relation-only reference is valid; default outside mode is PublicIpv4.
    assert rows(vpn, data)['EC2_VPN_CUSTOMER_GATEWAY_ADDRESS_TYPE']['verdict'] == 'FAIL'


@pytest.mark.parametrize('count,unknown,expected', [(16, False, 'PASS'), (17, False, 'FAIL'),
                                                  (16, True, 'NEEDS_REVIEW'), (17, True, 'FAIL')])
def test_certificate_distinct_roles_limit(count, unknown, expected):
    cert = 'arn:aws:acm:ap-northeast-1:111111111111:certificate/example'
    resources = [target(str(i), 'AWS::EC2::EnclaveCertificateIamRoleAssociation',
                        CertificateArn=cert, RoleArn=f'arn:aws:iam::111111111111:role/r{i}') for i in range(count)]
    resources.append(target('repeat', resources[0].type, CertificateArn=cert,
                            RoleArn='arn:aws:iam::111111111111:role/r0'))
    if unknown:
        resources.append(target('unknown', resources[0].type, CertificateArn=cert, RoleArn=UNKNOWN))
    data = design(resources[0])
    data.resources = resources
    assert rows(resources[0], data)['EC2_ENCLAVE_CERTIFICATE_ROLE_LIMIT']['verdict'] == expected


def test_certificate_different_and_alias_identities():
    cert = 'arn:aws:acm:ap-northeast-1:111111111111:certificate/example'
    main = target('main', 'AWS::EC2::EnclaveCertificateIamRoleAssociation',
                  CertificateArn=cert, RoleArn='arn:aws:iam::111111111111:role/main')
    others = [target(str(i), main.type, CertificateArn=cert, RoleArn=f'role-{i}') for i in range(16)]
    data = linked_design(main, others)
    for i, other in enumerate(others):
        role = target(f'role-{i}', 'AWS::IAM::Role')
        data.resources.append(role)
        data.relations.append(Relation(id=str(i), source_resource_id=other.id,
                                       source_path='/properties/RoleArn', target_resource_id=role.id, evidence_ids=['e1']))
    # The literal role ARN could be one of the linked roles.
    assert rows(main, data)['EC2_ENCLAVE_CERTIFICATE_ROLE_LIMIT']['verdict'] == 'NEEDS_REVIEW'
    for other in others:
        other.fields[0].selected().value = cert + '-different'
    assert rows(main, data)['EC2_ENCLAVE_CERTIFICATE_ROLE_LIMIT']['verdict'] == 'PASS'


def volume(kind, volume_type, size, iops=None):
    props = {'VolumeType': volume_type, 'Size' if kind == 'Volume' else 'VolumeSize': size}
    if iops is not None:
        props['Iops'] = iops
    if kind == 'EC2Fleet':
        props = {'LaunchTemplateConfigs': [{'Overrides': [{'BlockDeviceMappings': [{'Ebs': props}]}]}]}
    elif kind == 'SpotFleet':
        props = {'SpotFleetRequestConfigData': {'LaunchSpecifications': [{'BlockDeviceMappings': [{'Ebs': props}]}]}}
    return target('volume', 'AWS::EC2::' + kind, **props)


@pytest.mark.parametrize('kind', ['Volume', 'EC2Fleet', 'SpotFleet'])
@pytest.mark.parametrize('volume_type,size,expected', [
    ('gp2', 1, 'PASS'), ('gp2', 16385, 'FAIL'), ('gp3', 65536, 'PASS'), ('gp3', 65537, 'FAIL'),
    ('io1', 3, 'FAIL'), ('io1', 4, 'PASS'), ('io1', 16385, 'FAIL'),
    ('io2', 65536, 'PASS'), ('io2', 65537, 'FAIL'),
    ('st1', 124, 'FAIL'), ('sc1', 125, 'PASS'), ('standard', 1025, 'FAIL'),
    (UNKNOWN, 100, 'NEEDS_REVIEW'), ('gp3', UNKNOWN, 'NEEDS_REVIEW'),
])
def test_ebs_size_boundaries(kind, volume_type, size, expected):
    assert rows(volume(kind, volume_type, size))['EC2_EBS_SIZE_BY_TYPE']['verdict'] == expected


@pytest.mark.parametrize('kind', ['Volume', 'EC2Fleet', 'SpotFleet'])
@pytest.mark.parametrize('volume_type,iops,expected', [
    ('gp3', 2999, 'FAIL'), ('gp3', 3000, 'PASS'), ('gp3', 80000, 'PASS'), ('gp3', 80001, 'FAIL'),
    ('io1', 99, 'FAIL'), ('io1', 64000, 'PASS'), ('io1', 64001, 'FAIL'),
    ('io2', 256000, 'PASS'), ('io2', 256001, 'FAIL'), ('io2', UNKNOWN, 'NEEDS_REVIEW'),
])
def test_ebs_iops_boundaries(kind, volume_type, iops, expected):
    assert rows(volume(kind, volume_type, 100, iops))['EC2_EBS_IOPS_BY_TYPE']['verdict'] == expected


def test_ebs_absent_and_unresolved_collections():
    resource = target('fleet', 'AWS::EC2::EC2Fleet', LaunchTemplateConfigs=UNKNOWN)
    assert all(row['verdict'] == 'NEEDS_REVIEW' for row in rows(resource).values())
    resource = target('fleet', 'AWS::EC2::EC2Fleet', LaunchTemplateConfigs=[])
    assert not rows(resource)
    resource = target('vol', 'AWS::EC2::Volume', Size=16385)
    assert rows(resource)['EC2_EBS_SIZE_BY_TYPE']['verdict'] == 'FAIL'  # documented gp2 default
    resource = target('vol', 'AWS::EC2::Volume', Size=16385, SourceVolumeId='vol-source')
    assert rows(resource)['EC2_EBS_SIZE_BY_TYPE']['verdict'] == 'NEEDS_REVIEW'
    resource = target('vol', 'AWS::EC2::Volume', VolumeType='gp3', SnapshotId='snap-1')
    assert not rows(resource)  # inherited size is not zero


@pytest.mark.parametrize('strategy,expected', [('partition', 'PASS'), ('cluster', 'FAIL'),
                                              ('spread', 'FAIL'), (UNKNOWN, 'NEEDS_REVIEW')])
def test_template_partition_group(strategy, expected):
    template = target('lt', 'AWS::EC2::LaunchTemplate', LaunchTemplateData={
        'Placement': {'PartitionNumber': 1, 'GroupName': 'placement'}})
    group = target('placement', 'AWS::EC2::PlacementGroup', Strategy=strategy)
    data = linked_design(template, [group], [('LaunchTemplateData/Placement/GroupName', 'placement')])
    assert rows(template, data)['EC2_TEMPLATE_PARTITION_PLACEMENT']['verdict'] == expected


@pytest.mark.parametrize('profile,version,expected', [
    ({'Name': 'profile'}, '1', 'PASS'), ({'Name': 'profile', 'Arn': 'arn:profile'}, '1', 'FAIL'),
    ({'Name': UNKNOWN, 'Arn': 'arn:profile'}, '1', 'NEEDS_REVIEW'),
    ({'Name': 'profile'}, '2', 'NEEDS_REVIEW'),
])
def test_asg_template_profile(profile, version, expected):
    template = target('lt', 'AWS::EC2::LaunchTemplate', LaunchTemplateData={'IamInstanceProfile': profile})
    asg = target('asg', 'AWS::AutoScaling::AutoScalingGroup', LaunchTemplate={'LaunchTemplateId': 'lt', 'Version': version})
    data = linked_design(asg, [template], [('LaunchTemplate/LaunchTemplateId', 'lt')])
    assert rows(template, data)['EC2_TEMPLATE_ASG_PROFILE_EXCLUSIVE']['verdict'] == expected
    assert 'EC2_TEMPLATE_ASG_PROFILE_EXCLUSIVE' not in rows(template)


@pytest.mark.parametrize('contents,expected', [
    ('#!/bin/bash\necho hello', 'FAIL'),
    ('MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary="x"\n\n--x\nContent-Type: text/x-shellscript\n\n#!/bin/sh\n--x--\n', 'PASS'),
    ('MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary="x"\n\nbroken', 'FAIL'),
])
def test_batch_template_mime(contents, expected):
    template = target('lt', 'AWS::EC2::LaunchTemplate', LaunchTemplateData={
        'UserData': base64.b64encode(contents.encode()).decode()})
    batch = target('batch', 'AWS::Batch::ComputeEnvironment', ComputeResources={
        'LaunchTemplate': {'LaunchTemplateId': 'lt', 'Version': '1'}})
    data = linked_design(batch, [template], [('ComputeResources/LaunchTemplate/LaunchTemplateId', 'lt')])
    assert rows(template, data)['EC2_TEMPLATE_BATCH_USER_DATA_MIME']['verdict'] == expected


def test_checker_integrates_sources_evidence_and_date():
    resource = volume('Volume', 'io1', 3, 99)
    result = Checker(ROOT / 'schemas', ROOT / 'profiles/vpc-subnet.json').check(design(resource))
    findings = [row for row in result['results'] if row['rule_id'] in ('EC2_EBS_SIZE_BY_TYPE', 'EC2_EBS_IOPS_BY_TYPE')]
    assert len(findings) == 2
    assert all(row['verdict'] == 'FAIL' and row['source_urls'] and row['evidence_ids'] == ['e1'] and
               row['source_checked_at'] == '2026-10-03' for row in findings)


def test_template_placement_ambiguous_selector():
    template = target('lt', 'AWS::EC2::LaunchTemplate', LaunchTemplateData={
        'Placement': {'PartitionNumber': 1, 'GroupName': 'placement', 'GroupId': UNKNOWN}})
    group = target('placement', 'AWS::EC2::PlacementGroup', Strategy='partition')
    data = linked_design(template, [group], [('LaunchTemplateData/Placement/GroupName', 'placement')])
    assert rows(template, data)['EC2_TEMPLATE_PARTITION_PLACEMENT']['verdict'] == 'NEEDS_REVIEW'


def test_batch_unknown_version_without_current_user_data():
    template = target('lt', 'AWS::EC2::LaunchTemplate', LaunchTemplateData={})
    batch = target('batch', 'AWS::Batch::ComputeEnvironment', ComputeResources={
        'LaunchTemplate': {'LaunchTemplateId': 'lt', 'Version': '2'}})
    data = linked_design(batch, [template], [('ComputeResources/LaunchTemplate/LaunchTemplateId', 'lt')])
    assert rows(template, data)['EC2_TEMPLATE_BATCH_USER_DATA_MIME']['verdict'] == 'NEEDS_REVIEW'


@pytest.mark.parametrize('kind,key,group_type', [
    ('DBInstance', 'DBParameterGroupName', 'DBParameterGroup'),
    ('DBCluster', 'DBClusterParameterGroupName', 'DBClusterParameterGroup'),
    ('DBCluster', 'DBInstanceParameterGroupName', 'DBParameterGroup'),
])
@pytest.mark.parametrize('family,engine,expected', [
    ('mysql8.0', 'mysql', 'PASS'), ('mysql8.0', 'postgres', 'FAIL'),
    ('postgres13', 'postgres', 'PASS'), ('postgres13', 'aurora-postgresql', 'FAIL'),
    ('aurora-mysql5.7', 'aurora-mysql', 'PASS'), ('aurora-mysql8.0', 'mysql', 'FAIL'),
    ('aurora-postgresql14', 'aurora-postgresql', 'PASS'),
    ('future-family', 'mysql', 'NEEDS_REVIEW'), (UNKNOWN, 'mysql', 'NEEDS_REVIEW'),
    ('mysql8.0', UNKNOWN, 'NEEDS_REVIEW'),
])
def test_parameter_group_engine(kind, key, group_type, family, engine, expected):
    db = target('db', 'AWS::RDS::' + kind, Engine=engine, **{key: 'group'})
    group = target('group', 'AWS::RDS::' + group_type, Family=family)
    data = linked_design(db, [group], [(key, 'group')])
    assert rows(db, data)['RDS_PARAMETER_GROUP_ENGINE']['verdict'] == expected


@pytest.mark.parametrize('instance_family,cluster_family,expected', [
    ('aurora-mysql8.0', 'aurora-mysql8.0', 'PASS'),
    ('aurora-mysql5.7', 'aurora-mysql8.0', 'FAIL'),
    ('future-family', 'future-family', 'PASS'),
    (UNKNOWN, 'aurora-mysql8.0', 'NEEDS_REVIEW'),
    ('aurora-mysql8.0', UNKNOWN, 'NEEDS_REVIEW'),
    ('', '', 'NEEDS_REVIEW'),
])
def test_cluster_parameter_family_consistency(instance_family, cluster_family, expected):
    db = target('db', 'AWS::RDS::DBCluster', Engine='aurora-mysql',
                DBInstanceParameterGroupName='ig', DBClusterParameterGroupName='cg')
    ig = target('ig', 'AWS::RDS::DBParameterGroup', Family=instance_family)
    cg = target('cg', 'AWS::RDS::DBClusterParameterGroup', Family=cluster_family)
    data = linked_design(db, [ig, cg], [('DBInstanceParameterGroupName', 'ig'),
                                     ('DBClusterParameterGroupName', 'cg')])
    assert rows(db, data)['RDS_CLUSTER_PARAMETER_GROUP_FAMILY']['verdict'] == expected


@pytest.mark.parametrize('mode', ['external', 'scope', 'conditional', 'unresolved', 'duplicate', 'wrong-type'])
def test_parameter_group_unresolved_links(mode):
    db = target('db', 'AWS::RDS::DBInstance', Engine='mysql', DBParameterGroupName='g')
    group = target('g', 'AWS::RDS::DBParameterGroup', Family='mysql8.0')
    data = linked_design(db, [group], [('DBParameterGroupName', 'g')])
    if mode == 'external':
        data.relations.clear()
    elif mode == 'scope':
        group.scope.region = 'us-east-1'
    elif mode == 'conditional':
        data.relations[0].condition = 'optional'
    elif mode == 'unresolved':
        db.fields[-1].selected().value = UNKNOWN
    elif mode == 'duplicate':
        data.relations.append(data.relations[0].model_copy(update={'id': 'duplicate'}))
    elif mode == 'wrong-type':
        group.type = 'AWS::RDS::DBClusterParameterGroup'
    assert rows(db, data)['RDS_PARAMETER_GROUP_ENGINE']['verdict'] == 'NEEDS_REVIEW'


def test_parameter_group_absence_and_default_cluster_family():
    db = target('db', 'AWS::RDS::DBCluster', Engine='aurora-mysql')
    assert not rows(db)
    db = target('db', 'AWS::RDS::DBCluster', Engine='aurora-mysql', DBInstanceParameterGroupName='ig')
    ig = target('ig', 'AWS::RDS::DBParameterGroup', Family='aurora-mysql8.0')
    data = linked_design(db, [ig], [('DBInstanceParameterGroupName', 'ig')])
    assert rows(db, data)['RDS_CLUSTER_PARAMETER_GROUP_FAMILY']['verdict'] == 'NEEDS_REVIEW'


def test_parameter_group_checker_source_and_evidence():
    db = target('db', 'AWS::RDS::DBInstance', Engine='postgres', DBParameterGroupName='g')
    group = target('g', 'AWS::RDS::DBParameterGroup', Family='mysql8.0')
    data = linked_design(db, [group], [('DBParameterGroupName', 'g')])
    result = Checker(ROOT / 'schemas', ROOT / 'profiles/vpc-subnet.json').check(data)
    row = next(r for r in result['results'] if r['rule_id'] == 'RDS_PARAMETER_GROUP_ENGINE')
    assert row['verdict'] == 'FAIL'
    assert row['source_urls'] and row['source_checked_at'] == '2026-10-03'
    assert row['evidence_ids'] == ['e1']
