from pathlib import Path

import pytest

from aws_design_sheet.checker import Checker
from aws_design_sheet.checks.registry import rule_sources
SOURCES = rule_sources()
from aws_design_sheet.checks.registry import combine
from aws_design_sheet.checks.ec2.api_constraints import evaluate_route_endpoint_target_type, evaluate_verified_access_endpoint_options, evaluate_verified_access_trust_options, evaluate_ec2_host_instance_type_family, evaluate_ipam_public_advertisement_source, evaluate_placement_parent_cluster, evaluate_transit_gateway_asn_or_route_server_duration, evaluate_instance_existing_nic_launch_flags
from aws_design_sheet.checks.rds.api_constraints import evaluate_rds_new_instance_master_username, evaluate_rds_custom_engine_version
from aws_design_sheet.checks.iam.identity_statement_structure import evaluate_iam_identity_statement_structure
from aws_design_sheet.checks.lambda_.snapstart_local_compatibility import evaluate_lambda_snapstart_compatibility
api_checks = combine(evaluate_route_endpoint_target_type, evaluate_rds_new_instance_master_username, evaluate_iam_identity_statement_structure, evaluate_lambda_snapstart_compatibility, evaluate_verified_access_endpoint_options, evaluate_verified_access_trust_options, evaluate_rds_custom_engine_version, evaluate_ec2_host_instance_type_family, evaluate_ipam_public_advertisement_source, evaluate_placement_parent_cluster, evaluate_transit_gateway_asn_or_route_server_duration, evaluate_instance_existing_nic_launch_flags)
from aws_design_sheet.checks.ec2.api_constraints import evaluate_instance_accelerator_capabilities, evaluate_launch_template_cpu_capabilities
capability_checks = combine(evaluate_instance_accelerator_capabilities, evaluate_launch_template_cpu_capabilities)
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN
from test_autoscaling_group_nested_constraints import design

ROOT = Path(__file__).resolve().parents[1]


def check(kind, **props):
    resource = target('subject', 'AWS::EC2::' + kind, **props)
    return api_checks(design(resource), resource)


@pytest.mark.parametrize('props,expected', [
    ({}, 'PASS'), ({'InstanceType': 'm5.large'}, 'PASS'),
    ({'InstanceType': 'm5.large', 'InstanceFamily': 'm5'}, 'FAIL'),
    ({'InstanceType': UNKNOWN, 'InstanceFamily': 'm5'}, 'NEEDS_REVIEW'),
    ({'InstanceType': '{{resolve:ssm:type}}', 'InstanceFamily': 'm5'}, 'NEEDS_REVIEW'),
    ({'InstanceType': UNKNOWN}, 'PASS')])
def test_host_exclusivity_without_inventing_requiredness(props, expected):
    assert check('Host', **props)[0]['verdict'] == expected


@pytest.mark.parametrize('flag', [True, False])
@pytest.mark.parametrize('family,source,expected', [
    ('ipv6', 'byoip', 'PASS'), ('ipv6', 'amazon', 'FAIL'),
    ('ipv4', 'byoip', 'FAIL'), (UNKNOWN, 'byoip', 'NEEDS_REVIEW'),
    ('ipv6', UNKNOWN, 'NEEDS_REVIEW')])
def test_ipam_advertisement_presence_includes_false(flag, family, source, expected):
    assert check('IPAMPool', PubliclyAdvertisable=flag, AddressFamily=family,
                 PublicIpSource=source)[0]['verdict'] == expected


def test_ipam_absence_default_and_unknown():
    assert check('IPAMPool', AddressFamily='ipv6') == []
    assert check('IPAMPool', AddressFamily='ipv6', PubliclyAdvertisable=False)[0]['verdict'] == 'PASS'
    assert check('IPAMPool', AddressFamily='ipv4', PubliclyAdvertisable=UNKNOWN)[0]['verdict'] == 'NEEDS_REVIEW'


@pytest.mark.parametrize('strategy,expected', [('cluster', 'PASS'), ('spread', 'FAIL'),
    ('partition', 'FAIL'), ('precision-time', 'FAIL'), (UNKNOWN, 'NEEDS_REVIEW')])
def test_parent_placement_cluster(strategy, expected):
    assert check('PlacementGroup', ParentGroupId='pg-123', Strategy=strategy)[0]['verdict'] == expected


@pytest.mark.parametrize('number,expected', [(64511, 'FAIL'), (64512, 'PASS'), (65534, 'PASS'),
    (65535, 'FAIL'), (4199999999, 'FAIL'), (4200000000, 'PASS'), (4294967294, 'PASS'),
    (4294967295, 'FAIL'), (True, 'NEEDS_REVIEW'), (64512.5, 'NEEDS_REVIEW'), (UNKNOWN, 'NEEDS_REVIEW')])
def test_transit_private_asn_disjoint_ranges(number, expected):
    assert check('TransitGateway', AmazonSideAsn=number)[0]['verdict'] == expected


@pytest.mark.parametrize('duration,expected', [(0, 'FAIL'), (1, 'PASS'), (5, 'PASS'),
    (6, 'FAIL'), (UNKNOWN, 'NEEDS_REVIEW')])
def test_route_server_duration_conflict_is_advisory(duration, expected):
    row = check('RouteServer', PersistRoutesDuration=duration)[0]
    assert row['verdict'] == expected and row['severity'] == 'WARNING'


@pytest.mark.parametrize('key', ['AssociatePublicIpAddress', 'DeleteOnTermination'])
@pytest.mark.parametrize('nic,flag,expected', [('eni-123', True, 'FAIL'), ('eni-123', False, 'NOT_APPLICABLE'),
    (UNKNOWN, True, 'NEEDS_REVIEW'), ('eni-123', UNKNOWN, 'NEEDS_REVIEW')])
def test_existing_nic_flags(key, nic, flag, expected):
    rows = check('Instance', NetworkInterfaces=[{'NetworkInterfaceId': nic, key: flag}])
    assert next(r for r in rows if r['path'].endswith('/' + key))['verdict'] == expected


def test_existing_nic_reference_and_independent_items():
    instance = target('i', 'AWS::EC2::Instance', NetworkInterfaces=[
        {'AssociatePublicIpAddress': True}, UNKNOWN, {'AssociatePublicIpAddress': False}])
    nic = target('nic', 'AWS::EC2::NetworkInterface')
    data = linked_design(instance, [nic], [('NetworkInterfaces/0/NetworkInterfaceId', 'nic')])
    rows = api_checks(data, instance)
    assert [r['verdict'] for r in rows[::2]] == ['FAIL', 'NEEDS_REVIEW', 'NOT_APPLICABLE']
    assert rows[0]['evidence_ids'] and rows[2]['dependencies']


@pytest.mark.parametrize('kind,props,rule,severity', [
    ('Host', {'InstanceType': 'm5.large', 'InstanceFamily': 'm5'}, 'EC2_HOST_INSTANCE_TYPE_FAMILY_EXCLUSIVE', 'ERROR'),
    ('IPAMPool', {'AddressFamily': 'ipv6', 'PubliclyAdvertisable': False, 'PublicIpSource': 'amazon'}, 'EC2_IPAM_PUBLIC_ADVERTISEMENT_SOURCE', 'ERROR'),
    ('PlacementGroup', {'Strategy': 'spread', 'ParentGroupId': 'pg-123'}, 'EC2_PLACEMENT_PARENT_CLUSTER', 'ERROR'),
    ('TransitGateway', {'AmazonSideAsn': 65535}, 'EC2_TRANSIT_GATEWAY_PRIVATE_ASN', 'ERROR'),
    ('RouteServer', {'PersistRoutesDuration': 0}, 'EC2_ROUTE_SERVER_PERSIST_DURATION', 'WARNING'),
    ('Instance', {'NetworkInterfaces': [{'NetworkInterfaceId': 'eni-123', 'DeleteOnTermination': True}]}, 'EC2_EXISTING_NIC_LAUNCH_FLAGS', 'ERROR')])
def test_checker_sources_and_severity(kind, props, rule, severity):
    resource = target('subject', 'AWS::EC2::' + kind, **props)
    result = Checker(ROOT / 'schemas', ROOT / 'profiles/vpc-subnet.json').check(design(resource))
    row = next(r for r in result['results'] if r['rule_id'] == rule and r['verdict'] == 'FAIL')
    assert row['verdict'] == 'FAIL' and row['severity'] == severity
    assert row['source_urls'] == SOURCES[rule] and row['source_checked_at'] == '2026-10-03'


@pytest.mark.parametrize('kind,name', [('load-balancer', 'LoadBalancerOptions'),
    ('network-interface', 'NetworkInterfaceOptions'), ('rds', 'RdsOptions'), ('cidr', 'CidrOptions')])
def test_verified_endpoint_matching_options(kind, name):
    assert check('VerifiedAccessEndpoint', EndpointType=kind)[0]['verdict'] == 'FAIL'
    assert check('VerifiedAccessEndpoint', EndpointType=kind, **{name: {}})[0]['verdict'] == 'PASS'
    assert check('VerifiedAccessEndpoint', EndpointType=kind, **{name: UNKNOWN})[0]['verdict'] == 'NEEDS_REVIEW'


def test_verified_trust_preserves_identity_center_and_other_blocks():
    rows = check('VerifiedAccessTrustProvider', TrustProviderType='device')
    assert [r['verdict'] for r in rows] == ['FAIL', 'FAIL']
    rows = check('VerifiedAccessTrustProvider', TrustProviderType='user', UserTrustProviderType='iam-identity-center')
    assert [r['verdict'] for r in rows] == ['PASS']
    rows = check('VerifiedAccessTrustProvider', TrustProviderType='user', UserTrustProviderType='oidc')
    assert [r['verdict'] for r in rows] == ['PASS', 'FAIL']
    assert check('VerifiedAccessEndpoint', EndpointType=UNKNOWN)[0]['verdict'] == 'NEEDS_REVIEW'


@pytest.mark.parametrize('engine,expected', [('custom-oracle-ee', 'FAIL'), ('custom-oracle-se2-cdb', 'FAIL'),
    ('custom-sqlserver-web', 'FAIL'), ('sqlserver-ee', 'NOT_APPLICABLE'),
    ('custom-future-db', 'NEEDS_REVIEW'), (UNKNOWN, 'NEEDS_REVIEW')])
def test_cev_kms_engine_scope(engine, expected):
    resource = target('cev', 'AWS::RDS::CustomDBEngineVersion', Engine=engine)
    [row] = api_checks(design(resource), resource)
    assert row['verdict'] == expected
    resource = target('cev', resource.type, Engine='custom-oracle-ee', KMSKeyId=UNKNOWN)
    assert api_checks(design(resource), resource)[0]['verdict'] == 'NEEDS_REVIEW'


@pytest.mark.parametrize('props,expected', [
    ({'Engine': 'mysql'}, 'FAIL'), ({'Engine': 'mysql', 'MasterUsername': 'admin'}, 'PASS'),
    ({'Engine': 'postgres', 'MasterUsername': UNKNOWN}, 'NEEDS_REVIEW'),
    ({'Engine': 'mysql', 'DBSnapshotIdentifier': UNKNOWN}, 'NEEDS_REVIEW'),
    ({'Engine': 'future-db'}, 'NEEDS_REVIEW')])
def test_new_rds_instance_username(props, expected):
    resource = target('db', 'AWS::RDS::DBInstance', **props)
    assert api_checks(design(resource), resource)[0]['verdict'] == expected


@pytest.mark.parametrize('props', [{'Engine': 'aurora-mysql'}, {'Engine': 'mysql', 'DBSnapshotIdentifier': 'snapshot'},
    {'Engine': 'mysql', 'SourceDBInstanceIdentifier': 'source'}, {'Engine': 'mysql', 'DBClusterIdentifier': 'cluster'}])
def test_inherited_username_is_not_required(props):
    resource = target('db', 'AWS::RDS::DBInstance', **props)
    assert api_checks(design(resource), resource) == []


@pytest.mark.parametrize('statement,expected', [
    ({'Effect': 'Allow', 'Action': 's3:GetObject', 'Resource': '*'}, 'PASS'),
    ({'Effect': 'Deny', 'NotAction': ['iam:*'], 'NotResource': ['arn:example']}, 'PASS'),
    ({'Effect': 'Allow', 'Action': '*', 'NotAction': '*', 'Resource': '*'}, 'FAIL'),
    ({'Effect': 'Allow', 'Action': '*'}, 'FAIL'),
    ({'Action': '*', 'Resource': '*'}, 'FAIL'),
    ({'Effect': UNKNOWN, 'Action': '*', 'Resource': '*'}, 'NEEDS_REVIEW'),
    ({'Effect': 'Allow', 'Action': UNKNOWN, 'Resource': '*'}, 'NEEDS_REVIEW'),
    (UNKNOWN, 'NEEDS_REVIEW')])
def test_identity_statement_structure(statement, expected):
    resource = target('policy', 'AWS::IAM::Policy', PolicyDocument={'Statement': [statement]})
    assert api_checks(design(resource), resource)[0]['verdict'] == expected


@pytest.mark.parametrize('runtime,expected', [('java11', 'PASS'), ('python3.12', 'PASS'),
    ('dotnet8', 'PASS'), ('java8.al2', 'FAIL'), ('python3.11', 'FAIL'), ('nodejs22.x', 'FAIL'),
    (UNKNOWN, 'NEEDS_REVIEW')])
def test_snapstart_runtime_support_is_advisory(runtime, expected):
    resource = target('fn', 'AWS::Lambda::Function', Runtime=runtime, SnapStart={'ApplyOn': 'PublishedVersions'})
    rows = api_checks(design(resource), resource)
    assert rows[0]['verdict'] == expected
    assert all(r['severity'] == 'WARNING' for r in rows)


def test_snapstart_image_does_not_get_a_blanket_prohibition():
    resource = target('fn', 'AWS::Lambda::Function', PackageType='Image', SnapStart={'ApplyOn': 'PublishedVersions'},
                      EphemeralStorage={'Size': 513}, FileSystemConfigs=[{'Arn': 'arn:example'}])
    rows = api_checks(design(resource), resource)
    assert [r['verdict'] for r in rows] == ['NEEDS_REVIEW', 'FAIL', 'FAIL']
    resource = target('fn', resource.type, SnapStart={'ApplyOn': UNKNOWN}, EphemeralStorage={'Size': 1024})
    assert all(r['verdict'] == 'NEEDS_REVIEW' for r in api_checks(design(resource), resource))


@pytest.mark.parametrize('kind,props,rule', [
    ('AWS::EC2::VerifiedAccessEndpoint', {'EndpointType': 'cidr'}, 'EC2_VERIFIED_ACCESS_ENDPOINT_OPTIONS'),
    ('AWS::EC2::VerifiedAccessTrustProvider', {'TrustProviderType': 'device'}, 'EC2_VERIFIED_ACCESS_TRUST_OPTIONS'),
    ('AWS::RDS::CustomDBEngineVersion', {'Engine': 'custom-oracle-ee'}, 'RDS_CUSTOM_ENGINE_KMS_REQUIRED'),
    ('AWS::RDS::DBInstance', {'Engine': 'mysql'}, 'RDS_NEW_INSTANCE_MASTER_USERNAME'),
    ('AWS::IAM::Policy', {'PolicyDocument': {'Statement': []}}, 'IAM_IDENTITY_STATEMENT_STRUCTURE'),
    ('AWS::Lambda::Function', {'SnapStart': {'ApplyOn': 'PublishedVersions'}, 'Runtime': 'nodejs22.x'}, 'LAMBDA_SNAPSTART_LOCAL_COMPATIBILITY')])
def test_additional_checker_sources(kind, props, rule):
    resource = target('subject', kind, **props)
    result = Checker(ROOT / 'schemas', ROOT / 'profiles/vpc-subnet.json').check(design(resource))
    row = next(r for r in result['results'] if r['rule_id'] == rule and r['verdict'] == 'FAIL')
    assert row['source_urls'] == SOURCES[rule]


@pytest.mark.parametrize('kind,expected', [('GatewayLoadBalancer', 'PASS'), ('Interface', 'FAIL'),
    ('Gateway', 'FAIL'), ('Resource', 'FAIL'), (UNKNOWN, 'NEEDS_REVIEW')])
def test_route_endpoint_type(kind, expected):
    route = target('route', 'AWS::EC2::Route')
    endpoint = target('endpoint', 'AWS::EC2::VPCEndpoint', VpcEndpointType=kind)
    data = linked_design(route, [endpoint], [('VpcEndpointId', 'endpoint')])
    row = api_checks(data, route)[0]
    assert row['verdict'] == expected
    assert row['evidence_ids']


def test_route_endpoint_external_and_scope():
    assert check('Route', VpcEndpointId='vpce-123')[0]['verdict'] == 'NEEDS_REVIEW'
    route = target('route', 'AWS::EC2::Route')
    endpoint = target('endpoint', 'AWS::EC2::VPCEndpoint', VpcEndpointType='GatewayLoadBalancer')
    data = linked_design(route, [endpoint], [('VpcEndpointId', 'endpoint')])
    endpoint.scope = endpoint.scope.model_copy(update={'region': 'us-east-1'})
    assert api_checks(data, route)[0]['verdict'] == 'NEEDS_REVIEW'


@pytest.mark.parametrize('credits,expected', [('standard', 'PASS'), ('unlimited', 'FAIL'), (UNKNOWN, 'NEEDS_REVIEW')])
def test_explicit_t3_host_credits(credits, expected):
    resource = target('i', 'AWS::EC2::Instance', InstanceType='t3.large', Tenancy='host', CreditSpecification={'CPUCredits': credits})
    [row] = capability_checks(design(resource), resource)
    assert row['verdict'] == expected and row['severity'] == 'WARNING'
    resource.fields[0].selected().value = 't3a.large'
    assert capability_checks(design(resource), resource) == []


@pytest.mark.parametrize('feature,instance_type,value,expected', [
    ('CreditSpecification', 't3.large', {'CpuCredits': 'standard'}, 'PASS'),
    ('CreditSpecification', 'm5.large', {'CpuCredits': 'standard'}, 'FAIL'),
    ('CreditSpecification', UNKNOWN, {'CpuCredits': 'standard'}, 'NEEDS_REVIEW'),
    ('AmdSevSnp', 'm6a.large', 'enabled', 'PASS'),
    ('AmdSevSnp', 'm5.large', 'enabled', 'FAIL'),
    ('AmdSevSnp', 'm5.large', UNKNOWN, 'NEEDS_REVIEW')])
def test_template_capability_snapshot(feature, instance_type, value, expected):
    data = {'InstanceType': instance_type}
    data.update({'CpuOptions': {feature: value}} if feature == 'AmdSevSnp' else {feature: value})
    resource = target('t', 'AWS::EC2::LaunchTemplate', LaunchTemplateData=data)
    [row] = capability_checks(design(resource), resource)
    assert row['verdict'] == expected and row['severity'] == 'WARNING'


def test_retired_accelerators_are_advisory_and_unknown_is_not_failed():
    resource = target('i', 'AWS::EC2::Instance', ElasticGpuSpecifications=[{'Type': 'eg1.medium'}], ElasticInferenceAccelerators=UNKNOWN)
    rows = capability_checks(design(resource), resource)
    assert [r['verdict'] for r in rows] == ['FAIL', 'NEEDS_REVIEW']
    checked = Checker(ROOT / 'schemas', ROOT / 'profiles/vpc-subnet.json').check(design(resource))
    row = next(r for r in checked['results'] if r['rule_id'] == 'EC2_RETIRED_ACCELERATORS')
    assert row['severity'] == 'WARNING' and row['source_urls']
