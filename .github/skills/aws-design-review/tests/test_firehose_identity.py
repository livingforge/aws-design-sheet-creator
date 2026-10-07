from pathlib import Path
import pytest
from aws_design_sheet.checks.kinesisfirehose.delivery_stream import evaluate_kinesisfirehose_delivery_stream
from aws_design_sheet.checks.kinesisanalytics.input_format import evaluate_kinesisanalytics_input_format
from aws_design_sheet.checks.registry import combine
firehose_identity_checks = combine(evaluate_kinesisfirehose_delivery_stream, evaluate_kinesisanalytics_input_format)
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('mode',['symmetric','asymmetric','hmac','omitted','unknown','external','conditional','ambiguous','scope','template','key_template','aws_owned','unknown_type'])
def test_key(mode):
    r=target('main','AWS::KinesisFirehose::DeliveryStream',DeliveryStreamEncryptionConfigurationInput={'KeyType':UNKNOWN if mode=='unknown_type' else 'AWS_OWNED_CMK' if mode=='aws_owned' else 'CUSTOMER_MANAGED_CMK','KeyARN':'key'})
    k=target('key','AWS::KMS::Key',**({} if mode=='omitted' else {'KeySpec':'SYMMETRIC_DEFAULT' if mode=='symmetric' else UNKNOWN if mode=='unknown' else 'HMAC_256' if mode=='hmac' else 'RSA_2048'}))
    d=linked_design(r,[k],[] if mode=='external' else [('DeliveryStreamEncryptionConfigurationInput/KeyARN','key')])
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='ambiguous':d.relations.append(d.relations[0].model_copy(update={'id':'duplicate'}))
    if mode=='scope':k.scope.region='us-east-1'
    if mode=='template':r.template=TemplateContext(state='UNRESOLVED')
    if mode=='key_template':k.template=TemplateContext(state='UNRESOLVED')
    assert firehose_identity_checks(d,r)[0]['verdict']==('PASS' if mode=='symmetric' else 'FAIL' if mode=='asymmetric' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('mode',['same','different','disabled','omitted_enabled','unknown_enabled','unknown_role','malformed','dynamic','linked','unknown_account','template'])
def test_role(mode):
    role=UNKNOWN if mode=='unknown_role' else '${role}' if mode=='dynamic' else 'not-an-arn' if mode=='malformed' else 'arn:aws:iam::'+('222222222222' if mode=='different' else '111111111111')+':role/path/reader'
    conversion={'SchemaConfiguration':{'RoleARN':role}}
    if mode!='omitted_enabled':conversion['Enabled']=False if mode=='disabled' else UNKNOWN if mode=='unknown_enabled' else True
    r=target('main','AWS::KinesisFirehose::DeliveryStream',ExtendedS3DestinationConfiguration={'DataFormatConversionConfiguration':conversion})
    d=linked_design(r,[target('role','AWS::IAM::Role')],[('ExtendedS3DestinationConfiguration/DataFormatConversionConfiguration/SchemaConfiguration/RoleARN','role')] if mode=='linked' else [])
    if mode=='unknown_account':r.scope.account='unknown'
    if mode=='template':r.template=TemplateContext(state='UNRESOLVED')
    assert firehose_identity_checks(d,r)[0]['verdict']==('PASS' if mode=='same' else 'FAIL' if mode=='different' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('raw,expected',[('JSON','PASS'),('CSV','PASS'),('XML','FAIL'),('json','FAIL'),(UNKNOWN,'NEEDS_REVIEW'),('${format}','NEEDS_REVIEW'),('', 'NEEDS_REVIEW'),(None,'NEEDS_REVIEW')])
def test_format(raw,expected):
    r=target('main','AWS::KinesisAnalytics::Application',Inputs=[{'InputSchema':{'RecordFormat':{'RecordFormatType':raw}}}])
    assert firehose_identity_checks(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('kind',['AWS::KinesisAnalytics::Application','AWS::KinesisFirehose::DeliveryStream'])
def test_absent(kind):
    r=target('main',kind)
    assert not firehose_identity_checks(linked_design(r),r)


def test_unknown_input():
    r=target('main','AWS::KinesisAnalytics::Application',Inputs=[UNKNOWN])
    assert firehose_identity_checks(linked_design(r),r)[0]['verdict']=='NEEDS_REVIEW'


def test_checker_format():
    r=target('main','AWS::KinesisAnalytics::Application',Inputs=[{'InputSchema':{'RecordFormat':{'RecordFormatType':'XML'}}}])
    root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    assert any(f['rule_id']=='KINESIS_ANALYTICS_INPUT_FORMAT' and f['verdict']=='FAIL' for f in results)
