"""Artifact checks use generated test material, never real credentials."""
import base64
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from aws_design_sheet.checker import Checker
from aws_design_sheet.checks.rds.event_category_snapshot import event_category_snapshot
from aws_design_sheet.checks.registry import combine
from aws_design_sheet.checks.iam.artifacts import server_material, saml_artifacts
from aws_design_sheet.checks.cloudfront.iam_cloudfront_certificate_path import cloudfront_certificate
from aws_design_sheet.checks.lambda_.inline_zip_estimate import inline_zip
from aws_design_sheet.checks.ec2.ipam_public_source_scope import ipam_scope
from aws_design_sheet.checks.rds.event_category_snapshot import event_categories
artifact_checks = combine(server_material, cloudfront_certificate, saml_artifacts, inline_zip, ipam_scope, event_categories)
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN
from test_autoscaling_group_nested_constraints import design

ROOT = Path(__file__).resolve().parents[1]


def rows(resource, data=None):
    return {r['rule_id']: r for r in artifact_checks(data or design(resource), resource)}


def make_cert(key, issuer_key=None, issuer_name='leaf'):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'leaf')])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)])
    return (x509.CertificateBuilder().subject_name(name).issuer_name(issuer)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(datetime(2020, 1, 1, tzinfo=timezone.utc))
            .not_valid_after(datetime(2021, 1, 1, tzinfo=timezone.utc))
            .sign(issuer_key or key, hashes.SHA256()))


@pytest.fixture(scope='module')
def material():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = make_cert(key)
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()).decode()
    wrong = other.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()).decode()
    return key, other, cert, pem, private, wrong


@pytest.mark.parametrize('mode,expected', [('match', 'PASS'), ('mismatch', 'FAIL'),
    ('body', 'FAIL'), ('key', 'FAIL'), ('chain', 'FAIL'), ('two', 'FAIL'),
    ('unknown-body', 'NEEDS_REVIEW'), ('unknown-key', 'NEEDS_REVIEW'),
    ('unknown-chain', 'NEEDS_REVIEW'), ('encrypted', 'FAIL')])
def test_server_certificate_material(material, mode, expected):
    key, _, cert, pem, private, wrong = material
    props = {'CertificateBody': pem, 'PrivateKey': private}
    if mode == 'mismatch':
        props['PrivateKey'] = wrong
    elif mode in ('body', 'key', 'chain'):
        props[{'body': 'CertificateBody', 'key': 'PrivateKey', 'chain': 'CertificateChain'}[mode]] = 'not PEM'
    elif mode == 'two':
        props['CertificateBody'] = pem + pem
    elif mode.startswith('unknown-'):
        props[{'unknown-body': 'CertificateBody', 'unknown-key': 'PrivateKey', 'unknown-chain': 'CertificateChain'}[mode]] = UNKNOWN
    elif mode == 'encrypted':
        props['PrivateKey'] = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.BestAvailableEncryption(b'test')).decode()
    resource = target('cert', 'AWS::IAM::ServerCertificate', **props)
    row = rows(resource)['IAM_SERVER_CERTIFICATE_MATERIAL']
    assert row['verdict'] == expected
    assert private not in str(row) and pem not in str(row)


def test_chain_signature_and_order(material):
    key, issuer, _, _, private, _ = material
    cert = make_cert(key, issuer)
    root = make_cert(issuer)
    resource = target('cert', 'AWS::IAM::ServerCertificate',
        CertificateBody=cert.public_bytes(serialization.Encoding.PEM).decode(), PrivateKey=private,
        CertificateChain=root.public_bytes(serialization.Encoding.PEM).decode())
    assert rows(resource)['IAM_SERVER_CERTIFICATE_MATERIAL']['verdict'] == 'PASS'
    resource.field('/properties/CertificateChain').selected().value = make_cert(key).public_bytes(serialization.Encoding.PEM).decode()
    assert rows(resource)['IAM_SERVER_CERTIFICATE_MATERIAL']['verdict'] == 'FAIL'


@pytest.mark.parametrize('path,expected', [('/cloudfront/', 'PASS'), ('/cloudfront/test/', 'PASS'),
    ('/cloudfront', 'FAIL'), ('/', 'FAIL'), (None, 'FAIL'), (UNKNOWN, 'NEEDS_REVIEW')])
def test_cloudfront_certificate_path(path, expected):
    main = target('cdn', 'AWS::CloudFront::Distribution', DistributionConfig={'ViewerCertificate': {'IamCertificateId': 'cert'}})
    cert = target('cert', 'AWS::IAM::ServerCertificate', **({'Path': path} if path is not None else {}))
    data = linked_design(main, [cert], [('DistributionConfig/ViewerCertificate/IamCertificateId', 'cert')])
    assert rows(main, data)['IAM_CLOUDFRONT_CERTIFICATE_PATH']['verdict'] == expected
    data.relations[0].condition = 'maybe'
    assert rows(main, data)['IAM_CLOUDFRONT_CERTIFICATE_PATH']['verdict'] == 'NEEDS_REVIEW'


def metadata(cert):
    encoded = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
    return ('<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="test">'
        '<IDPSSODescriptor><KeyDescriptor><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">'
        '<X509Data><X509Certificate>' + encoded + '</X509Certificate></X509Data></KeyInfo>'
        '</KeyDescriptor></IDPSSODescriptor></EntityDescriptor>')


@pytest.mark.parametrize('mode,expected', [('valid', 'PASS'), ('bom', 'FAIL'), ('malformed', 'FAIL'),
    ('dtd', 'FAIL'), ('bad-cert', 'FAIL'), ('missing-issuer', 'NEEDS_REVIEW'),
    ('no-cert', 'NEEDS_REVIEW'), ('unknown', 'NEEDS_REVIEW')])
def test_saml_metadata(material, mode, expected):
    xml = metadata(material[2])  # Expired certificate must not cause an IAM error.
    if mode == 'bom':
        xml = '\ufeff' + xml
    elif mode == 'malformed':
        xml = '<xml'
    elif mode == 'dtd':
        xml = '<!DOCTYPE x [<!ENTITY x SYSTEM "file:///never-read">]><x>&x;</x>'
    elif mode == 'bad-cert':
        xml = xml.replace('<X509Certificate>', '<X509Certificate>!')
    elif mode == 'missing-issuer':
        xml = xml.replace(' entityID="test"', '')
    elif mode == 'no-cert':
        xml = '<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="test"/>'
    elif mode == 'unknown':
        xml = UNKNOWN
    resource = target('saml', 'AWS::IAM::SAMLProvider', SamlMetadataDocument=xml)
    assert rows(resource)['IAM_SAML_METADATA_CONTENT']['verdict'] == expected


@pytest.mark.parametrize('mode,expected', [('pem', 'PASS'), ('bad', 'FAIL'), ('unknown', 'NEEDS_REVIEW'), ('encrypted', 'NEEDS_REVIEW')])
def test_saml_private_key(material, mode, expected):
    key = material[4]
    if mode == 'bad':
        key = 'not a private key'
    elif mode == 'unknown':
        key = UNKNOWN
    elif mode == 'encrypted':
        key = material[0].private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.BestAvailableEncryption(b'test')).decode()
    resource = target('saml', 'AWS::IAM::SAMLProvider', AddPrivateKey=key)
    assert rows(resource)['IAM_SAML_PRIVATE_KEY_PEM']['verdict'] == expected


@pytest.mark.parametrize('content,expected', [('def handler(event, ctx): return 1', 'PASS'),
    ('#' * (5 * 1024 * 1024), 'PASS'), (UNKNOWN, 'NEEDS_REVIEW')], ids=['small', 'compressible', 'unknown'])
def test_inline_zip_measures_compressed_not_source_size(content, expected):
    resource = target('fn', 'AWS::Lambda::Function', Code={'ZipFile': content})
    row = rows(resource)['LAMBDA_INLINE_ZIP_ESTIMATE']
    assert row['severity'] == 'WARNING' and row['verdict'] == expected


def test_large_incompressible_zip_is_advisory():
    import random
    content = base64.b64encode(random.Random(1).randbytes(5 * 1024 * 1024)).decode()
    resource = target('fn', 'AWS::Lambda::Function', Code={'ZipFile': content})
    row = rows(resource)['LAMBDA_INLINE_ZIP_ESTIMATE']
    assert row['verdict'] == 'FAIL' and row['severity'] == 'WARNING'


@pytest.mark.parametrize('source,items,expected', [('db-instance', ['creation'], 'PASS'),
    ('db-cluster', ['global failover'], 'PASS'), ('db-instance', ['new-category'], 'NEEDS_REVIEW'),
    ('new-source', ['creation'], 'NEEDS_REVIEW'), (UNKNOWN, ['creation'], 'NEEDS_REVIEW'),
    ('db-instance', [UNKNOWN], 'NEEDS_REVIEW'), ('db-instance', UNKNOWN, 'NEEDS_REVIEW')])
def test_event_category_snapshot(source, items, expected):
    resource = target('subscription', 'AWS::RDS::EventSubscription', SourceType=source, EventCategories=items)
    assert rows(resource)['RDS_EVENT_CATEGORY_SNAPSHOT']['verdict'] == expected


def test_snapshot_provenance_and_no_messages_in_categories():
    snapshot = event_category_snapshot()
    assert len(snapshot['sources']) == 2
    assert all(len(s['sha256']) == 64 for s in snapshot['sources'])
    assert all(c.islower() and len(c) < 40 for values in snapshot['categories'].values() for c in values)


def test_private_ipam_scope_is_advisory_and_external_remains_unknown():
    pool = target('pool', 'AWS::EC2::IPAMPool', PublicIpSource='amazon')
    scope = target('scope', 'AWS::EC2::IPAMScope')
    data = linked_design(pool, [scope], [('IpamScopeId', 'scope')])
    row = rows(pool, data)['EC2_IPAM_PUBLIC_SOURCE_SCOPE']
    assert row['verdict'] == 'FAIL' and row['severity'] == 'WARNING'
    data.relations[0].target_resource_id = 'outside'
    assert rows(pool, data)['EC2_IPAM_PUBLIC_SOURCE_SCOPE']['verdict'] == 'NEEDS_REVIEW'


def test_checker_artifact_sources_and_absent_properties(material):
    resource = target('cert', 'AWS::IAM::ServerCertificate', CertificateBody=material[3], PrivateKey=material[5])
    result = Checker(ROOT / 'schemas', ROOT / 'profiles/vpc-subnet.json').check(design(resource))
    row = next(r for r in result['results'] if r['rule_id'] == 'IAM_SERVER_CERTIFICATE_MATERIAL')
    assert row['verdict'] == 'FAIL' and row['source_checked_at'] == '2026-10-03'
    assert row['source_urls'] and row['evidence_ids']
    for kind in ['IAM::ServerCertificate', 'IAM::SAMLProvider', 'Lambda::Function', 'EC2::IPAMPool', 'RDS::EventSubscription']:
        assert rows(target('empty', 'AWS::' + kind)) == {}


@pytest.mark.parametrize('kind,prop,rule', [
    ('IAM::ServerCertificate', 'PrivateKey', 'IAM_SERVER_CERTIFICATE_MATERIAL'),
    ('IAM::SAMLProvider', 'AddPrivateKey', 'IAM_SAML_PRIVATE_KEY_PEM'),
    ('IAM::SAMLProvider', 'SamlMetadataDocument', 'IAM_SAML_METADATA_CONTENT')])
def test_dynamic_secret_references_are_never_parsed_as_material(kind, prop, rule):
    resource = target('dynamic', 'AWS::' + kind, **{prop: '{{resolve:secretsmanager:example:SecretString:value}}'})
    assert rows(resource)[rule]['verdict'] == 'NEEDS_REVIEW'
