from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from aws_design_sheet.checks.acmpca.extensions import import_extensions, evaluate_acmpca_extensions
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


@pytest.fixture(scope='module')
def certs():
    key=ec.generate_private_key(ec.SECP256R1());name=x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME,'test')]);now=datetime.now(timezone.utc)
    results={}
    for case in ['valid','noncritical','not_ca','missing','unknown_critical','unknown_noncritical','aia','crldp','keyusage']:
        b=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1).not_valid_before(now).not_valid_after(now+timedelta(days=1))
        if case!='missing':b=b.add_extension(x509.BasicConstraints(ca=case!='not_ca',path_length=None),critical=case!='noncritical')
        if case.startswith('unknown'):b=b.add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier('1.2.3.4.5'),b'\x05\x00'),critical=case=='unknown_critical')
        if case=='aia':b=b.add_extension(x509.AuthorityInformationAccess([x509.AccessDescription(x509.AuthorityInformationAccessOID.CA_ISSUERS,x509.UniformResourceIdentifier('https://example.test/ca'))]),critical=True)
        if case=='crldp':b=b.add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(full_name=[x509.UniformResourceIdentifier('https://example.test/crl')],relative_name=None,reasons=None,crl_issuer=None)]),critical=True)
        if case=='keyusage':b=b.add_extension(x509.KeyUsage(False,False,False,False,False,True,True,False,False),critical=True)
        results[case]=b.sign(key,hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()
    return results


@pytest.mark.parametrize('case,expected',[('valid','PASS'),('noncritical','FAIL'),('not_ca','FAIL'),('missing','FAIL'),('unknown_critical','FAIL'),('unknown_noncritical','PASS'),('aia','FAIL'),('crldp','FAIL'),('keyusage','PASS')])
def test_critical_extensions(certs,case,expected):
    assert import_extensions(certs[case])==expected


@pytest.mark.parametrize('raw',[UNKNOWN,'not pem','x'*65537],ids=['unknown','non_pem','oversize'])
def test_unparsed_is_held(raw):
    assert import_extensions(raw)=='NEEDS_REVIEW'


@pytest.mark.parametrize('case',['valid','bad_issuer','oversize','unknown'])
def test_chain_and_checker(certs,case):
    chain=certs['valid'] if case=='valid' else certs['valid']+certs['noncritical'] if case=='bad_issuer' else 'x'*1048577 if case=='oversize' else UNKNOWN
    r=target('main','AWS::ACMPCA::CertificateAuthorityActivation',Certificate=certs['valid'],CertificateChain=chain)
    found=evaluate_acmpca_extensions(linked_design(r),r)
    assert [f['verdict'] for f in found]==['PASS','PASS' if case=='valid' else 'FAIL' if case=='bad_issuer' else 'NEEDS_REVIEW']
    if case=='bad_issuer':
        root=Path(__file__).resolve().parents[1]
        result=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
        assert any(f['rule_id']=='ACMPCA_IMPORT_CRITICAL_EXTENSIONS' and f['verdict']=='FAIL' for f in result)
