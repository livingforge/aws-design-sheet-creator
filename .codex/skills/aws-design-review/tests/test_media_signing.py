import pytest
from aws_design_sheet.checks.medialive.fec_column_depth import evaluate_medialive_fec_column_depth
from aws_design_sheet.checks.licensemanager.issuer_signing_key import evaluate_licensemanager_issuer_signing_key
from aws_design_sheet.checks.registry import combine
media_signing_checks = combine(evaluate_medialive_fec_column_depth, evaluate_licensemanager_issuer_signing_key)
from aws_design_sheet.models import TemplateContext
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('raw,verdict',[(4,'PASS'),(20,'PASS'),(3,'FAIL'),(21,'FAIL'),(True,'NEEDS_REVIEW'),(4.5,'NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_columns(raw,verdict):
    r=target('main','AWS::MediaLive::Channel',EncoderSettings={'OutputGroups':[{'Outputs':[{'OutputSettings':{'UdpOutputSettings':{'FecOutputSettings':{'ColumnDepth':raw}}}}]}]})
    assert media_signing_checks(linked_design(r),r)[0]['verdict']==verdict


@pytest.mark.parametrize('mode',['rsa2048','rsa3072','rsa4096','ecc','symmetric','hmac','encrypt','agreement','unknown_spec','unknown_usage','omitted_spec','omitted_usage','external','conditional','ambiguous','scope','unknown_scope','template','key_template'])
def test_key(mode):
    r=target('main','AWS::LicenseManager::License',Issuer={'SignKey':'key'})
    props={}
    if mode!='omitted_spec':props['KeySpec']={'rsa2048':'RSA_2048','rsa3072':'RSA_3072','rsa4096':'RSA_4096','ecc':'ECC_NIST_P256','symmetric':'SYMMETRIC_DEFAULT','hmac':'HMAC_256','unknown_spec':UNKNOWN}.get(mode,'RSA_2048')
    if mode!='omitted_usage':props['KeyUsage']={'encrypt':'ENCRYPT_DECRYPT','agreement':'KEY_AGREEMENT','unknown_usage':UNKNOWN}.get(mode,'SIGN_VERIFY')
    k=target('key','AWS::KMS::Key',**props)
    d=linked_design(r,[k],[] if mode=='external' else [('Issuer/SignKey','key')])
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='ambiguous':d.relations.append(d.relations[0].model_copy(update={'id':'duplicate'}))
    if mode=='scope':k.scope.account='222222222222'
    if mode=='unknown_scope':r.scope.account=k.scope.account='unknown'
    if mode=='template':r.template=TemplateContext(state='UNRESOLVED')
    if mode=='key_template':k.template=TemplateContext(state='UNRESOLVED')
    assert media_signing_checks(d,r)[0]['verdict']==('PASS' if mode.startswith('rsa') else 'FAIL' if mode in ('ecc','symmetric','hmac','encrypt','agreement','omitted_spec','omitted_usage') else 'NEEDS_REVIEW')


@pytest.mark.parametrize('kind',['AWS::MediaLive::Channel','AWS::LicenseManager::License'])
def test_absent(kind):
    r=target('main',kind)
    assert not media_signing_checks(linked_design(r),r)
