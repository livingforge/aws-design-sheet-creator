from pathlib import Path
import pytest
from aws_design_sheet.checks.location.tracker_consumer_account import evaluate_location_tracker_consumer_account
from aws_design_sheet.checks.managedblockchain.voting_bounds import evaluate_managedblockchain_voting_bounds
from aws_design_sheet.checks.kinesisanalytics.reference_format import evaluate_kinesisanalytics_reference_format
from aws_design_sheet.checks.registry import combine
member_limits_checks = combine(evaluate_location_tracker_consumer_account, evaluate_managedblockchain_voting_bounds, evaluate_kinesisanalytics_reference_format)
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('mode',['same','different','unknown','dynamic','malformed','wildcard','unknown_account','linked','template'])
def test_consumer(mode):
    raw=UNKNOWN if mode=='unknown' else '${arn}' if mode=='dynamic' else 'bad' if mode=='malformed' else 'arn:aws:geo:ap-northeast-1:'+('222222222222' if mode=='different' else '111111111111')+':geofence-collection/'+('*' if mode=='wildcard' else 'collection')
    r=target('main','AWS::Location::TrackerConsumer',ConsumerArn=raw)
    d=linked_design(r,[target('collection','AWS::Location::GeofenceCollection')],[('ConsumerArn','collection')] if mode=='linked' else [])
    if mode=='unknown_account':r.scope.account='unknown'
    if mode=='template':r.template=TemplateContext(state='UNRESOLVED')
    assert member_limits_checks(d,r)[0]['verdict']==('PASS' if mode=='same' else 'FAIL' if mode=='different' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('key,low,high',[('ThresholdPercentage',0,100),('ProposalDurationInHours',1,168)])
@pytest.mark.parametrize('case',['low','high','below','above','unknown','boolean','fractional','framework','unknown_framework'])
def test_voting(key,low,high,case):
    raw=low if case=='low' else high if case=='high' else low-1 if case=='below' else UNKNOWN if case=='unknown' else True if case=='boolean' else 1.5 if case=='fractional' else high+1
    r=target('main','AWS::ManagedBlockchain::Member',NetworkConfiguration={'Framework':'ETHEREUM' if case=='framework' else UNKNOWN if case=='unknown_framework' else 'HYPERLEDGER_FABRIC','VotingPolicy':{'ApprovalThresholdPolicy':{key:raw}}})
    assert member_limits_checks(linked_design(r),r)[0]['verdict']==('PASS' if case in ('low','high') else 'FAIL' if case in ('below','above') else 'NEEDS_REVIEW')


@pytest.mark.parametrize('raw,verdict',[('JSON','PASS'),('CSV','PASS'),('XML','FAIL'),('json','FAIL'),(UNKNOWN,'NEEDS_REVIEW'),('${format}','NEEDS_REVIEW')])
def test_format(raw,verdict):
    r=target('main','AWS::KinesisAnalytics::ApplicationReferenceDataSource',ReferenceDataSource={'ReferenceSchema':{'RecordFormat':{'RecordFormatType':raw}}})
    assert member_limits_checks(linked_design(r),r)[0]['verdict']==verdict


@pytest.mark.parametrize('kind',['AWS::Location::TrackerConsumer','AWS::ManagedBlockchain::Member','AWS::KinesisAnalytics::ApplicationReferenceDataSource'])
def test_absent(kind):
    r=target('main',kind)
    assert not member_limits_checks(linked_design(r),r)


def test_checker_voting():
    r=target('main','AWS::ManagedBlockchain::Member',NetworkConfiguration={'Framework':'HYPERLEDGER_FABRIC','VotingPolicy':{'ApprovalThresholdPolicy':{'ThresholdPercentage':101}}})
    root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    assert any(f['rule_id']=='MANAGEDBLOCKCHAIN_VOTING_BOUNDS' and f['verdict']=='FAIL' for f in results)
