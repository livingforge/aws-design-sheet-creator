from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from aws_design_sheet.checks.acmpca.chains import self_signature, chain_signatures, evaluate_acmpca_chains
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.fixture(scope='module')
def chain():
 keys=[ec.generate_private_key(ec.SECP256R1()) for _ in range(4)]
 names=[x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME,n)]) for n in ['root','intermediate','leaf','other']]
 now=datetime.now(timezone.utc)
 def cert(subject,issuer,signer=None):
  c=(x509.CertificateBuilder().subject_name(names[subject]).issuer_name(names[issuer]).serial_number(subject+1)
     .public_key(keys[subject].public_key()).not_valid_before(now).not_valid_after(now+timedelta(days=1))
     .sign(keys[issuer if signer is None else signer],hashes.SHA256()))
  return c.public_bytes(serialization.Encoding.PEM).decode()
 return {'root':cert(0,0),'intermediate':cert(1,0),'leaf':cert(2,1),'other':cert(3,3),'false_self':cert(0,0,3)}


@pytest.mark.parametrize('case,kind,expected',[('root','ROOT','PASS'),('root','SUBORDINATE','FAIL'),('intermediate','ROOT','FAIL'),('intermediate','SUBORDINATE','PASS'),('false_self','ROOT','FAIL'),('false_self','SUBORDINATE','PASS'),('root','UNKNOWN','NEEDS_REVIEW')])
def test_self_signature(chain,case,kind,expected):
 assert self_signature(chain[case],kind)==expected


@pytest.mark.parametrize('case,expected',[('valid','PASS'),('reversed','FAIL'),('includes_leaf','FAIL'),('wrong_issuer','FAIL'),('no_root','FAIL'),('duplicate','FAIL'),('unknown','NEEDS_REVIEW'),('too_many','NEEDS_REVIEW'),('oversize','NEEDS_REVIEW'),('invalid','FAIL')])
def test_chain(chain,case,expected):
 raw={'valid':chain['intermediate']+chain['root'],'reversed':chain['root']+chain['intermediate'],
      'includes_leaf':chain['leaf']+chain['intermediate']+chain['root'],'wrong_issuer':chain['other'],
      'no_root':chain['intermediate'],'duplicate':chain['intermediate']+chain['root']*2,
      'unknown':UNKNOWN,'too_many':chain['root']*33,'oversize':'x'*1048577,
      'invalid':'-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----'}[case]
 assert chain_signatures(chain['leaf'],raw)==expected


@pytest.mark.parametrize('raw,expected',[('crl.example.test','PASS'),('https://crl.example.test','FAIL'),('HTTP://crl.example.test','FAIL'),('${cname}','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_cname(raw,expected):
 r=target('main','AWS::ACMPCA::CertificateAuthority',RevocationConfiguration={'CrlConfiguration':{'CustomCname':raw}})
 assert evaluate_acmpca_chains(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('case',['root','subordinate','conditional','external'])
def test_checker(chain,case):
 r=target('main','AWS::ACMPCA::CertificateAuthorityActivation',Certificate=chain['root'],CertificateAuthorityArn='ca')
 ca=target('ca','AWS::ACMPCA::CertificateAuthority',Type='SUBORDINATE' if case=='subordinate' else 'ROOT')
 d=linked_design(r,[ca],[] if case=='external' else [('CertificateAuthorityArn','ca')])
 if case=='conditional':d.relations[0].condition='condition'
 root=Path(__file__).resolve().parents[1]
 found=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results']
 item=next(f for f in found if f['rule_id']=='ACMPCA_ACTIVATION_SELF_SIGNATURE')
 assert item['verdict']==('PASS' if case=='root' else 'FAIL' if case=='subordinate' else 'NEEDS_REVIEW')
 assert 'BEGIN CERTIFICATE' not in str(item)
