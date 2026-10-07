from datetime import datetime, timezone, timedelta
from pathlib import Path
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from aws_design_sheet.checks.acmpca.pem import csr_subject, parse_pem, evaluate_acmpca_pem
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.fixture(scope='module')
def material():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'example.test')])
    def csr(subject, san=None):
        builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
        if san is not None:
            builder = builder.add_extension(x509.SubjectAlternativeName(san), False)
        return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1).not_valid_before(now)
            .not_valid_after(now+timedelta(days=1)).sign(key, hashes.SHA256()))
    return dict(subject=csr(name), san=csr(x509.Name([]), [x509.DNSName('example.test')]),
                empty=csr(x509.Name([])), empty_san=csr(x509.Name([]), []),
                certificate=cert.public_bytes(serialization.Encoding.PEM).decode())


@pytest.mark.parametrize('case,expected', [('subject','PASS'), ('san','PASS'), ('empty','FAIL'), ('empty_san','FAIL')])
def test_csr_subject(material, case, expected):
    assert csr_subject(material[case]) == expected


@pytest.mark.parametrize('case', ['unknown','dynamic','oversized','wrong_wrapper','multiple','invalid_der'])
@pytest.mark.parametrize('csr', [True, False])
def test_conservative_parser(material, case, csr):
    label = 'CERTIFICATE REQUEST' if csr else 'CERTIFICATE'
    original = material['subject' if csr else 'certificate']
    raw = {'unknown': UNKNOWN, 'dynamic': '${value}', 'oversized': 'x'*65537,
           'wrong_wrapper': 'not pem', 'multiple': original*2,
           'invalid_der': '-----BEGIN '+label+'-----\nAAAA\n-----END '+label+'-----'}[case]
    assert parse_pem(raw, csr)[0] == ('FAIL' if case=='invalid_der' else 'NEEDS_REVIEW')


def test_certificate(material):
    assert parse_pem(material['certificate'])[0] == 'PASS'


@pytest.mark.parametrize('kind,key', [('Certificate','CertificateSigningRequest'), ('CertificateAuthorityActivation','Certificate')])
def test_integration(material, kind, key):
    raw = material['empty'] if kind=='Certificate' else material['certificate']
    r = target('main','AWS::ACMPCA::'+kind, **{key:raw})
    design = linked_design(r)
    direct = evaluate_acmpca_pem(design,r)
    root = Path(__file__).resolve().parents[1]
    found = Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(design)['results']
    assert any(f['rule_id']==direct[0]['rule_id'] and f['verdict']==direct[0]['verdict'] for f in found)


@pytest.mark.parametrize('kind', ['Certificate','CertificateAuthorityActivation'])
def test_absent(kind):
    r=target('main','AWS::ACMPCA::'+kind)
    results=evaluate_acmpca_pem(linked_design(r),r)
    assert all(f['rule_id']=='ACMPCA_ACTIVATION_CHAIN_PRESENCE' and f['verdict']=='NEEDS_REVIEW' for f in results)


@pytest.mark.parametrize('kind',['ROOT','SUBORDINATE'])
@pytest.mark.parametrize('case',['present','absent','unknown','external','conditional','unknown_scope','empty'])
def test_chain_presence(kind,case):
    props={} if case=='absent' else {'CertificateChain': UNKNOWN if case=='unknown' else '' if case=='empty' else 'explicit-chain'}
    r=target('main','AWS::ACMPCA::CertificateAuthorityActivation',CertificateAuthorityArn='ca',**props)
    ca=target('ca','AWS::ACMPCA::CertificateAuthority',Type=kind)
    d=linked_design(r,[ca],[] if case=='external' else [('CertificateAuthorityArn','ca')])
    if case=='conditional':d.relations[0].condition='condition'
    if case=='unknown_scope':ca.scope.account='unknown'
    expected='NEEDS_REVIEW'
    if case in ('present','absent'):
        expected='PASS' if (kind=='ROOT')==(case=='absent') else 'FAIL'
    assert evaluate_acmpca_pem(d,r)[0]['verdict']==expected
