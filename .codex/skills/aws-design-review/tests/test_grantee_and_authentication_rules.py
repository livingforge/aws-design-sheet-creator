"""Second-source findings retain uncertainty about external API behavior."""
from pathlib import Path

import pytest

from aws_design_sheet.checker import Checker
from aws_design_sheet.checks.registry import combine
from aws_design_sheet.checks.ec2.client_vpn_federated_authentication_required import evaluate_client_vpn_federated_authentication
from aws_design_sheet.checks.s3.directory_grantee_id_format import evaluate_s3_directory_grantee_id
from aws_design_sheet.checks.lambda_.layer_organization_principal import evaluate_lambda_layer_organization_principal
from aws_design_sheet.checks.rds.security_group_authorization_source import evaluate_rds_security_group_authorization_source
research_checks = combine(evaluate_client_vpn_federated_authentication, evaluate_s3_directory_grantee_id, evaluate_lambda_layer_organization_principal, evaluate_rds_security_group_authorization_source)
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN
from test_autoscaling_group_nested_constraints import design

ROOT = Path(__file__).resolve().parents[1]
UUID = '12345678-1234-ABCD-abcd-1234567890ab'


def result(resource, data=None):
    return research_checks(data or design(resource), resource)


@pytest.mark.parametrize('option,expected', [
    ({'Type': 'federated-authentication'}, 'FAIL'),
    ({'Type': 'federated-authentication', 'FederatedAuthentication': {'SAMLProviderArn': 'arn:aws:iam::111111111111:saml-provider/example'}}, 'PASS'),
    ({'Type': 'federated-authentication', 'FederatedAuthentication': {}}, 'PASS'),
    ({'Type': 'federated-authentication', 'FederatedAuthentication': UNKNOWN}, 'NEEDS_REVIEW'),
    ({'Type': 'federated-authentication', 'FederatedAuthentication': None}, 'NEEDS_REVIEW'),
    ({'Type': 'certificate-authentication'}, 'NOT_APPLICABLE'),
    ({'Type': 'directory-service-authentication'}, 'NOT_APPLICABLE'),
    ({'Type': UNKNOWN}, 'NEEDS_REVIEW'), ({}, 'NEEDS_REVIEW'),
    (UNKNOWN, 'NEEDS_REVIEW'),
])
def test_vpn_federated_authentication_presence(option, expected):
    resource = target('vpn', 'AWS::EC2::ClientVpnEndpoint', AuthenticationOptions=[option])
    [row] = result(resource)
    assert row['verdict'] == expected
    assert row['path'] == '/properties/AuthenticationOptions/0/FederatedAuthentication'


def test_vpn_authentication_collection_and_independent_entries():
    resource = target('vpn', 'AWS::EC2::ClientVpnEndpoint')
    assert result(resource) == []
    resource = target('vpn', resource.type, AuthenticationOptions=UNKNOWN)
    assert result(resource)[0]['verdict'] == 'NEEDS_REVIEW'
    resource = target('vpn', resource.type, AuthenticationOptions=[
        {'Type': 'federated-authentication'}, UNKNOWN,
        {'Type': 'certificate-authentication'}])
    assert [row['verdict'] for row in result(resource)] == ['FAIL', 'NEEDS_REVIEW', 'NOT_APPLICABLE']


def test_vpn_authentication_reference_retains_uncertainty():
    resource = target('vpn', 'AWS::EC2::ClientVpnEndpoint', AuthenticationOptions=[{'Type': 'federated-authentication'}])
    provider = target('provider', 'AWS::IAM::SAMLProvider')
    data = linked_design(resource, [provider], [('AuthenticationOptions/0/FederatedAuthentication', 'provider')])
    [row] = result(resource, data)
    assert row['verdict'] == 'NEEDS_REVIEW'
    assert row['evidence_ids'] and row['dependencies']


@pytest.mark.parametrize('kind', ['DIRECTORY_USER', 'DIRECTORY_GROUP'])
@pytest.mark.parametrize('identifier,expected', [(UUID, 'PASS'), ('123456789a-' + UUID, 'PASS'),
    ('123456789A-' + UUID, 'FAIL'), ('not-a-uuid', 'FAIL'), ('x' + UUID, 'FAIL'),
    (UUID + '\n', 'FAIL'), ('', 'FAIL'), (UNKNOWN, 'NEEDS_REVIEW'),
    ('{{resolve:secretsmanager:example}}', 'NEEDS_REVIEW')])
def test_directory_id_api_pattern(kind, identifier, expected):
    resource = target('grant', 'AWS::S3::AccessGrant', Grantee={'GranteeType': kind, 'GranteeIdentifier': identifier})
    [row] = result(resource)
    assert row['verdict'] == expected and row['severity'] == 'WARNING'
    assert row['evidence_ids']


def test_directory_unknown_type_and_reference_are_reviewed():
    resource = target('grant', 'AWS::S3::AccessGrant', Grantee={'GranteeType': UNKNOWN, 'GranteeIdentifier': UUID})
    assert result(resource)[0]['verdict'] == 'NEEDS_REVIEW'
    resource.fields[0].selected().value['GranteeType'] = 'DIRECTORY_USER'
    user = target('user', 'AWS::IdentityStore::User')
    data = linked_design(resource, [user], [('Grantee/GranteeIdentifier', 'user')])
    assert result(resource, data)[0]['verdict'] == 'NEEDS_REVIEW'
    resource.fields[0].selected().value['GranteeType'] = 'IAM'
    assert result(resource) == []


@pytest.mark.parametrize('principal,expected', [('*', 'PASS'), ('111111111111', 'FAIL'),
    ('arn:aws:iam::111111111111:root', 'FAIL'), (UNKNOWN, 'NEEDS_REVIEW'),
    ('{{resolve:ssm:principal}}', 'NEEDS_REVIEW')])
def test_layer_organization_sharing_is_advisory(principal, expected):
    resource = target('layer', 'AWS::Lambda::LayerVersionPermission', OrganizationId='o-1234567890', Principal=principal)
    [row] = result(resource)
    assert row['verdict'] == expected and row['severity'] == 'WARNING'
    assert 'not established' in row['reason']


def test_layer_absent_and_unknown_organization():
    resource = target('layer', 'AWS::Lambda::LayerVersionPermission', Principal='111111111111')
    assert result(resource) == []
    resource = target('layer', resource.type, Principal='111111111111', OrganizationId=UNKNOWN)
    assert result(resource)[0]['verdict'] == 'NEEDS_REVIEW'


@pytest.mark.parametrize('props,expected', [({}, 'FAIL'), ({'EC2SecurityGroupOwnerId': '111111111111'}, 'FAIL'),
    ({'CIDRIP': '10.0.0.0/8'}, 'PASS'), ({'EC2SecurityGroupId': 'sg-123'}, 'PASS'),
    ({'EC2SecurityGroupName': 'group'}, 'PASS'), ({'CIDRIP': UNKNOWN}, 'NEEDS_REVIEW'),
    ({'CIDRIP': '10.0.0.0/8', 'EC2SecurityGroupId': UNKNOWN}, 'PASS'),
    ({'CIDRIP': '10.0.0.0/8', 'EC2SecurityGroupId': 'sg-123'}, 'PASS')])
@pytest.mark.parametrize('embedded', [False, True])
def test_rds_at_least_one_source_without_inventing_exclusivity(props, expected, embedded):
    resource = (target('db', 'AWS::RDS::DBSecurityGroup', DBSecurityGroupIngress=[props]) if embedded else
                target('ingress', 'AWS::RDS::DBSecurityGroupIngress', **props))
    [row] = result(resource)
    assert row['verdict'] == expected


def test_rds_unresolved_collection_entry_and_relation():
    resource = target('db', 'AWS::RDS::DBSecurityGroup', DBSecurityGroupIngress=[UNKNOWN])
    assert result(resource)[0]['verdict'] == 'NEEDS_REVIEW'
    ingress = target('ingress', 'AWS::RDS::DBSecurityGroupIngress')
    group = target('group', 'AWS::EC2::SecurityGroup')
    data = linked_design(ingress, [group], [('EC2SecurityGroupId', 'group')])
    assert result(ingress, data)[0]['verdict'] == 'NEEDS_REVIEW'


@pytest.mark.parametrize('kind,props,rule,severity', [
    ('EC2::ClientVpnEndpoint', {'AuthenticationOptions': [{'Type': 'federated-authentication'}]}, 'EC2_CLIENT_VPN_FEDERATED_AUTHENTICATION_REQUIRED', 'ERROR'),
    ('S3::AccessGrant', {'Grantee': {'GranteeType': 'DIRECTORY_USER', 'GranteeIdentifier': 'bad'}}, 'S3_DIRECTORY_GRANTEE_ID_FORMAT', 'WARNING'),
    ('Lambda::LayerVersionPermission', {'OrganizationId': 'o-1234567890', 'Principal': '111111111111'}, 'LAMBDA_LAYER_ORGANIZATION_PRINCIPAL', 'WARNING'),
    ('RDS::DBSecurityGroupIngress', {}, 'RDS_SECURITY_GROUP_AUTHORIZATION_SOURCE', 'ERROR')])
def test_checker_connection(kind, props, rule, severity):
    resource = target('main', 'AWS::' + kind, **props)
    checked = Checker(ROOT / 'schemas', ROOT / 'profiles/vpc-subnet.json').check(design(resource))
    row = next(r for r in checked['results'] if r['rule_id'] == rule)
    assert row['verdict'] == 'FAIL' and row['severity'] == severity
    assert row['source_checked_at'] == '2026-10-03' and row['source_urls']


@pytest.mark.parametrize('kind,properties', [
    ('EC2::SecurityGroupIngress', {'IpProtocol': 'icmpv6', 'GroupId': 'sg-123', 'CidrIpv6': '::/0'}),
    ('EC2::SecurityGroupEgress', {'IpProtocol': '58', 'GroupId': 'sg-123', 'CidrIpv6': '::/0'}),
    ('EC2::SecurityGroup', {'GroupDescription': 'test', 'SecurityGroupIngress': [{'IpProtocol': 'icmpv6', 'CidrIpv6': '::/0'}]}),
    ('Lambda::Url', {'TargetFunctionArn': 'my-function', 'AuthType': 'AWS_IAM'})])
def test_optional_icmpv6_ports_and_url_qualifier_do_not_gain_false_failures(kind, properties):
    resource = target('main', 'AWS::' + kind, **properties)
    checked = Checker(ROOT / 'schemas', ROOT / 'profiles/vpc-subnet.json').check(design(resource))
    assert not [r for r in checked['results'] if r['verdict'] == 'FAIL']
