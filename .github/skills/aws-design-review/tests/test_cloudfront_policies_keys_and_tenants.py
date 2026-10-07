import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


def verdicts(resource, design=None):
    return {r['rule_id']: r['verdict'] for r in run_resource_checks(design or linked_design(resource), resource)}


@pytest.mark.parametrize('arn,expected', [
    ('arn:aws:acm:us-east-1:111111111111:certificate/id', 'PASS'),
    ('arn:aws:acm:us-west-2:111111111111:certificate/id', 'FAIL'),
    (UNKNOWN, 'NEEDS_REVIEW'), ('{{certificate}}', 'NEEDS_REVIEW'),
])
def test_viewer_certificate_region(arn, expected):
    resource = target('cf', 'AWS::CloudFront::Distribution', DistributionConfig={'ViewerCertificate': {'AcmCertificateArn': arn}})
    assert verdicts(resource)['CLOUDFRONT_ACM_REGION'] == expected


@pytest.mark.parametrize('forward,origins,expected', [
    ('all', [{'Id': 's3', 'S3OriginConfig': {}}], 'FAIL'),
    ('none', [{'Id': 's3', 'S3OriginConfig': {}}], 'PASS'),
    ('whitelist', [{'Id': 's3', 'S3OriginConfig': UNKNOWN}], 'NEEDS_REVIEW'),
    ('all', [{'Id': 's3', 'CustomOriginConfig': {}}], 'NEEDS_REVIEW'),
    ('all', [{'Id': 's3', 'S3OriginConfig': {}}, {'Id': 's3', 'CustomOriginConfig': {}}], 'NEEDS_REVIEW'),
    ('all', UNKNOWN, 'NEEDS_REVIEW'),
])
def test_s3_cookie_forwarding(forward, origins, expected):
    behavior = {'TargetOriginId': 's3', 'ForwardedValues': {'Cookies': {'Forward': forward}}}
    resource = target('cf', 'AWS::CloudFront::Distribution', DistributionConfig={'Origins': origins, 'CacheBehaviors': [behavior]})
    assert verdicts(resource)['CLOUDFRONT_S3_COOKIE_FORWARDING'] == expected


@pytest.mark.parametrize('parameters,schema,expected', [
    ([{'Name': 'tenant', 'Value': 'one'}], {'Required': True}, 'PASS'),
    ([], {'Required': True}, 'FAIL'), ([], {'Required': False}, 'PASS'),
    ([], {'Required': True, 'DefaultValue': 'one'}, 'NEEDS_REVIEW'),
    ([{'Name': UNKNOWN, 'Value': 'one'}], {'Required': True}, 'NEEDS_REVIEW'),
    ([{'Name': 'tenant', 'Value': UNKNOWN}], {'Required': True}, 'NEEDS_REVIEW'),
    ([], {'Required': UNKNOWN}, 'NEEDS_REVIEW'),
])
def test_required_tenant_parameters(parameters, schema, expected):
    resource = target('tenant', 'AWS::CloudFront::DistributionTenant', DistributionId={'Ref': 'cf'}, Parameters=parameters)
    cf = target('cf', 'AWS::CloudFront::Distribution', DistributionConfig={'TenantConfig': {'ParameterDefinitions': [
        {'Name': 'tenant', 'Definition': {'StringSchema': schema}}]}})
    design = linked_design(resource, [cf], [('DistributionId', 'cf')])
    assert verdicts(resource, design)['CLOUDFRONT_TENANT_REQUIRED_PARAMETERS'] == expected


@pytest.mark.parametrize('kind,expected', [('rsa2048', 'PASS'), ('rsa1024', 'FAIL'),
    ('p256', 'PASS'), ('p384', 'FAIL'), ('ed25519', 'FAIL')])
def test_public_key_algorithm_and_size(kind, expected):
    if kind.startswith('rsa'):
        key = rsa.generate_private_key(public_exponent=65537, key_size=int(kind[3:]))
    elif kind == 'ed25519':
        key = ed25519.Ed25519PrivateKey.generate()
    else:
        key = ec.generate_private_key(ec.SECP256R1() if kind == 'p256' else ec.SECP384R1())
    pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode('ascii')
    resource = target('key', 'AWS::CloudFront::PublicKey', PublicKeyConfig={'EncodedKey': pem})
    assert verdicts(resource)['CLOUDFRONT_PUBLIC_KEY_MATERIAL'] == expected


@pytest.mark.parametrize('raw,expected', [('not a public key', 'FAIL'), (UNKNOWN, 'NEEDS_REVIEW'),
    ('{{resolve:ssm:key}}', 'NEEDS_REVIEW'), ('a' * 65537, 'NEEDS_REVIEW')],
    ids=['malformed', 'unresolved', 'dynamic', 'parser-budget'])
def test_public_key_unknown_or_malformed(raw, expected):
    resource = target('key', 'AWS::CloudFront::PublicKey', PublicKeyConfig={'EncodedKey': raw})
    result = run_resource_checks(linked_design(resource), resource)[0]
    assert result['verdict'] == expected
    assert 'not a public key' not in result['reason']


@pytest.mark.parametrize('staging,expected', [(True, 'PASS'), (False, 'FAIL'), (UNKNOWN, 'NEEDS_REVIEW')])
def test_linked_staging_distribution(staging, expected):
    resource = target('policy', 'AWS::CloudFront::ContinuousDeploymentPolicy',
        ContinuousDeploymentPolicyConfig={'StagingDistributionDnsNames': [{'Fn::GetAtt': ['cf', 'DomainName']}]})
    cf = target('cf', 'AWS::CloudFront::Distribution', DistributionConfig={'Staging': staging})
    design = linked_design(resource, [cf], [('ContinuousDeploymentPolicyConfig/StagingDistributionDnsNames/0', 'cf')])
    assert verdicts(resource, design)['CLOUDFRONT_STAGING_DISTRIBUTION'] == expected


def test_unlinked_staging_dns_name_is_not_inferred():
    resource = target('policy', 'AWS::CloudFront::ContinuousDeploymentPolicy',
        ContinuousDeploymentPolicyConfig={'StagingDistributionDnsNames': ['d123.cloudfront.net']})
    assert verdicts(resource)['CLOUDFRONT_STAGING_DISTRIBUTION'] == 'NEEDS_REVIEW'
