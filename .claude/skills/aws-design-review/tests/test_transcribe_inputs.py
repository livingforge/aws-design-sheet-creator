from pathlib import Path
import pytest
from aws_design_sheet.checks.transcribe.analytics_and_filters import evaluate_transcribe_analytics_and_filters
from aws_design_sheet.checks.pipes.timestream_version_minimum import evaluate_pipes_timestream_version_minimum
from aws_design_sheet.checks.registry import combine
transcribe_inputs_checks = combine(evaluate_transcribe_analytics_and_filters, evaluate_pipes_timestream_version_minimum)
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('fields,expected',[
 ({'StartTime':0,'EndTime':100},'PASS'),({'StartTime':0},'FAIL'),({'EndTime':100},'FAIL'),
 ({'First':100},'PASS'),({'StartTime':UNKNOWN,'EndTime':100},'NEEDS_REVIEW'),
 ({'StartTime':None},'NEEDS_REVIEW'),({'StartTime':False},'NEEDS_REVIEW'),
 ({'StartTime':-1},'NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')],ids=['pair','start','end','first','unknown','null','bool','invalid','unknown_parent'])
def test_pair(fields,expected):
 r=target('main','AWS::Transcribe::CallAnalyticsCategory',Rules=[{'NonTalkTimeFilter':{'AbsoluteTimeRange':fields}}])
 assert transcribe_inputs_checks(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('kind',['InterruptionFilter','TranscriptFilter','SentimentFilter'])
def test_other_filters(kind):
 r=target('main','AWS::Transcribe::CallAnalyticsCategory',Rules=[{kind:{'AbsoluteTimeRange':{'StartTime':100}}}])
 assert transcribe_inputs_checks(linked_design(r),r)[0]['verdict']=='FAIL'


def test_unknown_rules():
 r=target('main','AWS::Transcribe::CallAnalyticsCategory',Rules=UNKNOWN)
 found=transcribe_inputs_checks(linked_design(r),r)
 assert len(found)==1 and found[0]['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('props,expected',[
 ({'Words':['term']},'PASS'),({'VocabularyFilterFileUri':'s3://bucket/file'},'PASS'),
 ({'Words':['term'],'VocabularyFilterFileUri':'s3://bucket/file'},'FAIL'),
 ({'Words':UNKNOWN,'VocabularyFilterFileUri':'s3://bucket/file'},'NEEDS_REVIEW'),
 ({'Words':['term'],'VocabularyFilterFileUri':UNKNOWN},'NEEDS_REVIEW'),
 ({'Words':None},'NEEDS_REVIEW')],ids=['words','uri','both','unknown_words','unknown_uri','null'])
def test_sources(props,expected):
 r=target('main','AWS::Transcribe::VocabularyFilter',**props)
 assert transcribe_inputs_checks(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('raw,expected',[('1','PASS'),('0001','PASS'),('0','FAIL'),('-1','FAIL'),('9'*256,'PASS'),('9'*257,'NEEDS_REVIEW'),('$.version','NEEDS_REVIEW'),('1.5','NEEDS_REVIEW'),('1e2','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW'),(1,'NEEDS_REVIEW')],ids=['one','zeros','zero','negative','large','oversized','dynamic','float','exponent','unknown','wrong_type'])
def test_version(raw,expected):
 r=target('main','AWS::Pipes::Pipe',TargetParameters={'TimestreamParameters':{'VersionValue':raw}})
 assert transcribe_inputs_checks(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('kind',['AWS::Transcribe::CallAnalyticsCategory','AWS::Transcribe::VocabularyFilter','AWS::Pipes::Pipe'])
def test_absent(kind):
 r=target('main',kind);assert not transcribe_inputs_checks(linked_design(r),r)


def test_checker():
 r=target('main','AWS::Pipes::Pipe',TargetParameters={'TimestreamParameters':{'VersionValue':'0'}})
 root=Path(__file__).resolve().parents[1]
 found=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
 assert any(f['rule_id']=='PIPES_TIMESTREAM_VERSION_MINIMUM' and f['verdict']=='FAIL' for f in found)
