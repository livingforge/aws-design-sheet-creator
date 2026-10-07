from pathlib import Path
import pytest
from aws_design_sheet.checks.ses.addon_name_values import ADDONS, evaluate_ses_addon_name_values
from aws_design_sheet.checks.smsvoice.text_sent_unsupported import evaluate_smsvoice_text_sent_unsupported
from aws_design_sheet.checks.s3express.encryption_key_type import evaluate_s3express_encryption_key_type
from aws_design_sheet.checks.registry import combine
message_values_checks = combine(evaluate_ses_addon_name_values, evaluate_smsvoice_text_sent_unsupported, evaluate_s3express_encryption_key_type)
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('raw,verdict',[(s,'PASS') for s in ADDONS]+[('OTHER','FAIL'),('spamhaus_dbl','FAIL'),(UNKNOWN,'NEEDS_REVIEW'),('${addon}','NEEDS_REVIEW')])
def test_addon(raw,verdict):
 r=target('main','AWS::SES::MailManagerAddonSubscription',AddonName=raw)
 assert message_values_checks(linked_design(r),r)[0]['verdict']==verdict


@pytest.mark.parametrize('raw,verdict',[('TEXT_SENT','FAIL'),('TEXT_DELIVERED','PASS'),('OTHER','PASS'),(UNKNOWN,'NEEDS_REVIEW'),('${event}','NEEDS_REVIEW')])
def test_event(raw,verdict):
 r=target('main','AWS::SMSVOICE::ConfigurationSet',EventDestinations=[{'MatchingEventTypes':[raw]}])
 assert message_values_checks(linked_design(r),r)[0]['verdict']==verdict


@pytest.mark.parametrize('case',['symmetric','asymmetric','hmac','unknown','default','external','conditional','duplicate','aes'])
def test_key(case):
 path='BucketEncryption/ServerSideEncryptionConfiguration/0/ServerSideEncryptionByDefault/KMSMasterKeyID'
 r=target('main','AWS::S3Express::DirectoryBucket',BucketEncryption={'ServerSideEncryptionConfiguration':[{'ServerSideEncryptionByDefault':{'SSEAlgorithm':'AES256' if case=='aes' else 'aws:kms','KMSMasterKeyID':'key'}}]})
 spec='RSA_2048' if case=='asymmetric' else 'HMAC_256' if case=='hmac' else UNKNOWN if case=='unknown' else 'SYMMETRIC_DEFAULT'
 k=target('key','AWS::KMS::Key',**({} if case=='default' else {'KeySpec':spec}))
 links=[] if case=='external' else [(path,'key')]
 if case=='duplicate':links+=links
 d=linked_design(r,[k],links)
 if case=='conditional':d.relations[0].condition='condition'
 assert message_values_checks(d,r)[0]['verdict']==('PASS' if case=='symmetric' else 'FAIL' if case=='asymmetric' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('raw',[UNKNOWN,[UNKNOWN],[{'MatchingEventTypes':UNKNOWN}]])
def test_unknown_events(raw):
 r=target('main','AWS::SMSVOICE::ConfigurationSet',EventDestinations=raw)
 assert all(f['verdict']=='NEEDS_REVIEW' for f in message_values_checks(linked_design(r),r))


@pytest.mark.parametrize('kind',['AWS::SES::MailManagerAddonSubscription','AWS::SMSVOICE::ConfigurationSet','AWS::S3Express::DirectoryBucket'])
def test_absent(kind):
 r=target('main',kind);assert not message_values_checks(linked_design(r),r)


def test_checker():
 r=target('main','AWS::SMSVOICE::ConfigurationSet',EventDestinations=[{'MatchingEventTypes':['TEXT_SENT']}])
 root=Path(__file__).resolve().parents[1]
 results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
 assert any(f['rule_id']=='SMSVOICE_TEXT_SENT_UNSUPPORTED' and f['verdict']=='FAIL' for f in results)
