from pathlib import Path
import pytest
from aws_design_sheet.checks.kafkaconnect.worker_base64 import evaluate_kafkaconnect_worker_base64
from aws_design_sheet.checks.amazonmq.configuration_base64 import evaluate_amazonmq_configuration_base64
from aws_design_sheet.checks.kendra.index_kms_key_type import evaluate_kendra_index_kms_key_type
from aws_design_sheet.checks.common.key_types_and_base64 import ASYMMETRIC
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN
from aws_design_sheet.checks.registry import combine
encoded_configs_checks=combine(evaluate_kafkaconnect_worker_base64,evaluate_amazonmq_configuration_base64,evaluate_kendra_index_kms_key_type)


@pytest.mark.parametrize('kind,field',[('AWS::KafkaConnect::WorkerConfiguration','PropertiesFileContent'),('AWS::AmazonMQ::Configuration','Data')])
@pytest.mark.parametrize('raw,expected',[
    ('YQ==','PASS'),('YWI=','PASS'),('YWJj','PASS'),('/w==','PASS'),
    ('!!!!','FAIL'),('AA=A','FAIL'),('====','FAIL'),('a===','FAIL'),
    ('YQ','NEEDS_REVIEW'),('YQ==\n','NEEDS_REVIEW'),('_w==','NEEDS_REVIEW'),('YR==','NEEDS_REVIEW'),
    ('','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW'),({'Fn::Base64':'key=value'},'NEEDS_REVIEW'),('A'*256004,'NEEDS_REVIEW'),
],ids=[f'encoding-{i}' for i in range(16)])
def test_base64(kind,field,raw,expected):
    r=target('main',kind,**{field:raw})
    assert encoded_configs_checks(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('spec',ASYMMETRIC+('SYMMETRIC_DEFAULT','HMAC_256','FUTURE',UNKNOWN))
def test_specs(spec):
    r=target('main','AWS::Kendra::Index',ServerSideEncryptionConfiguration={'KmsKeyId':'key'})
    key=target('key','AWS::KMS::Key',KeySpec=spec)
    d=linked_design(r,[key],[('ServerSideEncryptionConfiguration/KmsKeyId','key')])
    assert encoded_configs_checks(d,r)[0]['verdict']==('FAIL' if spec in ASYMMETRIC else 'PASS' if spec=='SYMMETRIC_DEFAULT' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('mode',['missing','conditional','ambiguous','alias','scope','template','key_template','omitted_spec','unknown_parent'])
def test_key_unknowns(mode):
    r=target('main','AWS::Kendra::Index',ServerSideEncryptionConfiguration=UNKNOWN if mode=='unknown_parent' else {'KmsKeyId':'key'})
    key=target('key','AWS::KMS::Alias' if mode=='alias' else 'AWS::KMS::Key',**({} if mode=='omitted_spec' else {'KeySpec':'RSA_2048'}))
    d=linked_design(r,[key],[] if mode=='missing' else [('ServerSideEncryptionConfiguration/KmsKeyId','key')])
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='ambiguous':d.relations.append(d.relations[0].model_copy(update={'id':'duplicate'}))
    if mode=='scope':key.scope.region='us-east-1'
    if mode=='template':r.template=TemplateContext(state='UNRESOLVED')
    if mode=='key_template':key.template=TemplateContext(state='UNRESOLVED')
    assert encoded_configs_checks(d,r)[0]['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('kind',['AWS::KafkaConnect::WorkerConfiguration','AWS::AmazonMQ::Configuration','AWS::Kendra::Index'])
def test_omitted(kind):
    r=target('main',kind)
    assert not encoded_configs_checks(linked_design(r),r)


def test_checker_content():
    r=target('main','AWS::KafkaConnect::WorkerConfiguration',PropertiesFileContent='!!!!')
    root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    assert any(f['rule_id']=='KAFKACONNECT_WORKER_BASE64' and f['verdict']=='FAIL' for f in results)
