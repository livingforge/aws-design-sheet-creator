import pytest
from aws_design_sheet.checks.waf.ip_and_action_types import evaluate_waf_ip_and_action_types
from aws_design_sheet.checks.supportauthz.signing_key_settings import evaluate_supportauthz_signing_key_settings
from aws_design_sheet.checks.registry import combine
from aws_design_sheet.checks.medialive.fec_column_depth import evaluate_medialive_fec_column_depth
from aws_design_sheet.checks.licensemanager.issuer_signing_key import evaluate_licensemanager_issuer_signing_key
media_signing_checks = combine(evaluate_medialive_fec_column_depth, evaluate_licensemanager_issuer_signing_key)
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN
from test_template_dependencies import link
from test_config_pipeline import nested
classic_values_checks=combine(evaluate_waf_ip_and_action_types,evaluate_supportauthz_signing_key_settings)


@pytest.mark.parametrize('kind,path,spec,evaluator',[
 ('AWS::SupportAuthZ::SupportPermit','SigningKeyInfo/KmsKey','ECC_NIST_P384',classic_values_checks),
 ('AWS::LicenseManager::License','Issuer/SignKey','RSA_2048',media_signing_checks)])
@pytest.mark.parametrize('case',['valid','wrong_spec','wrong_usage','default','unknown','future','external_primary','conditional_primary','wrong_account','same_region','not_multiregion','alias'])
def test_replica(kind,path,spec,evaluator,case):
    r=target('main',kind,**nested(path.split('/'),'replica'))
    replica=target('replica','AWS::KMS::Alias' if case=='alias' else 'AWS::KMS::ReplicaKey',PrimaryKeyArn='arn:aws:kms:us-east-1:111111111111:key/mrk-'+'a'*32)
    props={} if case=='default' else {'KeySpec':'SYMMETRIC_DEFAULT' if case=='wrong_spec' else UNKNOWN if case=='unknown' else 'FUTURE_SPEC' if case=='future' else spec,'KeyUsage':'ENCRYPT_DECRYPT' if case=='wrong_usage' else 'SIGN_VERIFY'}
    primary=target('primary','AWS::KMS::Key',MultiRegion=case!='not_multiregion',**props);primary.scope.region='us-east-1'
    d=linked_design(r,[replica,primary],[(path,'replica')])
    if case!='external_primary':link(d,replica,'PrimaryKeyArn',primary)
    if case=='conditional_primary':d.relations[-1].condition='maybe'
    if case=='wrong_account':primary.scope.account='222222222222'
    if case=='same_region':primary.scope.region=replica.scope.region
    expected='PASS' if case=='valid' else 'FAIL' if case in ('wrong_spec','wrong_usage','default') else 'NEEDS_REVIEW'
    assert evaluator(d,r)[0]['verdict']==expected
