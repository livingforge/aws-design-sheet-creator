from pathlib import Path
import pytest
from aws_design_sheet.checks.stepfunctions.activity_key_type import evaluate_stepfunctions_activity_key_type
from aws_design_sheet.checks.synthetics.artifact_encryption_mode import evaluate_synthetics_artifact_encryption_mode
from aws_design_sheet.checks.pinpoint.segment_recency_values import evaluate_pinpoint_segment_recency_values
from aws_design_sheet.checks.registry import combine
activity_inputs_checks = combine(evaluate_stepfunctions_activity_key_type, evaluate_synthetics_artifact_encryption_mode, evaluate_pinpoint_segment_recency_values)
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('case',['symmetric','asymmetric','hmac','default','unknown','external','conditional','duplicate','mode_unknown','owned'])
def test_key(case):
 mode=UNKNOWN if case=='mode_unknown' else 'AWS_OWNED_KEY' if case=='owned' else 'CUSTOMER_MANAGED_KMS_KEY'
 r=target('main','AWS::StepFunctions::Activity',EncryptionConfiguration={'Type':mode,'KmsKeyId':'key'})
 spec='RSA_2048' if case=='asymmetric' else 'HMAC_256' if case=='hmac' else UNKNOWN if case=='unknown' else 'SYMMETRIC_DEFAULT'
 k=target('key','AWS::KMS::Key',**({} if case=='default' else {'KeySpec':spec}))
 links=[] if case=='external' else [('EncryptionConfiguration/KmsKeyId','key')]*(2 if case=='duplicate' else 1)
 d=linked_design(r,[k],links)
 if case=='conditional':d.relations[0].condition='condition'
 assert activity_inputs_checks(d,r)[0]['verdict']==('PASS' if case=='symmetric' else 'FAIL' if case=='asymmetric' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('raw,expected',[('SSE_S3','PASS'),('SSE_KMS','PASS'),('SSE-KMS','NEEDS_REVIEW'),('OTHER','FAIL'),(UNKNOWN,'NEEDS_REVIEW'),('${mode}','NEEDS_REVIEW')])
def test_canary(raw,expected):
 r=target('main','AWS::Synthetics::Canary',ArtifactConfig={'S3Encryption':{'EncryptionMode':raw}})
 assert activity_inputs_checks(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('nested',[False,True])
@pytest.mark.parametrize('key,raw,expected',[('Duration','HR_24','PASS'),('Duration','DAY_7','PASS'),('Duration','DAY_14','PASS'),('Duration','DAY_30','PASS'),('Duration','DAY_1','FAIL'),('RecencyType','ACTIVE','PASS'),('RecencyType','INACTIVE','PASS'),('RecencyType','active','FAIL'),('RecencyType',UNKNOWN,'NEEDS_REVIEW')])
def test_recency(nested,key,raw,expected):
 dims={'Behavior':{'Recency':{key:raw}}}
 props={'SegmentGroups':{'Groups':[{'Dimensions':[dims]}]}} if nested else {'Dimensions':dims}
 r=target('main','AWS::Pinpoint::Segment',**props)
 found=activity_inputs_checks(linked_design(r),r)
 assert len(found)==1 and found[0]['verdict']==expected


def test_unknown_groups_deduplicated():
 r=target('main','AWS::Pinpoint::Segment',SegmentGroups={'Groups':UNKNOWN})
 found=activity_inputs_checks(linked_design(r),r)
 assert len(found)==1 and found[0]['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('kind',['AWS::StepFunctions::Activity','AWS::Synthetics::Canary','AWS::Pinpoint::Segment'])
def test_absent(kind):
 r=target('main',kind);assert not activity_inputs_checks(linked_design(r),r)


def test_checker():
 r=target('main','AWS::Pinpoint::Segment',Dimensions={'Behavior':{'Recency':{'Duration':'DAY_1','RecencyType':'ACTIVE'}}})
 root=Path(__file__).resolve().parents[1]
 found=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
 assert any(f['rule_id']=='PINPOINT_SEGMENT_RECENCY_VALUES' and f['verdict']=='FAIL' for f in found)
