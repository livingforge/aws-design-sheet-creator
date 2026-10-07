import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.msk.reverse_replicator import evaluate_msk_reverse_replicator
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN

A='arn:aws:kafka:ap-northeast-1:123456789012:cluster/source/12345678-abcd'
B='arn:aws:kafka:us-east-1:123456789012:cluster/target/87654321-abcd'
C='arn:aws:kafka:us-east-1:123456789012:cluster/other/87654321-abcd'


def info(a,b,mode='ENHANCED'):
    return {'SourceKafkaClusterArn':a,'TargetKafkaClusterArn':b,'ConsumerGroupReplication':{'ConsumerGroupOffsetSyncMode':mode}}


@pytest.mark.parametrize('mode,expected',[
    ('reverse','PASS'),('different_region','PASS'),('same_direction','NEEDS_REVIEW'),('wrong_source','NEEDS_REVIEW'),
    ('missing','NEEDS_REVIEW'),('other_account','NEEDS_REVIEW'),('other_env','NEEDS_REVIEW'),('unknown_template','NEEDS_REVIEW'),
    ('unknown_arn','NEEDS_REVIEW'),('id_and_arn','NEEDS_REVIEW'),('malformed','NEEDS_REVIEW'),('same_cluster','NEEDS_REVIEW'),
    ('legacy','NOT_APPLICABLE'),('unknown_mode','NEEDS_REVIEW'),('unknown_rows','NEEDS_REVIEW'),('two_rows','NEEDS_REVIEW')])
def test_reverse_pair(mode,expected):
    own=info(A,B);rev=info(B,A)
    if mode=='same_direction':rev=info(A,B)
    if mode=='wrong_source':rev=info(C,A)
    if mode=='unknown_arn':rev=info(UNKNOWN,A)
    if mode=='id_and_arn':rev['SourceKafkaClusterId']='cluster-id'
    if mode=='malformed':rev['SourceKafkaClusterArn']='arn:aws:kafka:placeholder'
    if mode=='same_cluster':own=info(A,A);rev=info(A,A)
    if mode=='legacy':own=info(A,B,'LEGACY')
    if mode=='unknown_mode':own=info(A,B,UNKNOWN)
    main=target('main','AWS::MSK::Replicator',ReplicationInfoList=UNKNOWN if mode=='unknown_rows' else [own,own] if mode=='two_rows' else [own])
    other=target('other','AWS::MSK::Replicator',ReplicationInfoList=[rev])
    if mode=='different_region':other.scope.region='us-east-1'
    if mode=='other_account':other.scope.account='111122223333'
    if mode=='other_env':other.scope.environment='other'
    if mode=='unknown_template':other.template=TemplateContext(state='UNRESOLVED')
    d=linked_design(main,[] if mode=='missing' else [other])
    assert evaluate_msk_reverse_replicator(d,main)[0]['verdict']==expected


def test_known_reverse_can_coexist_with_unknown_inventory():
    main=target('main','AWS::MSK::Replicator',ReplicationInfoList=[info(A,B)])
    other=target('other','AWS::MSK::Replicator',ReplicationInfoList=[info(B,A)])
    unknown=target('unknown','AWS::MSK::Replicator',ReplicationInfoList=UNKNOWN)
    d=linked_design(main,[other,unknown])
    assert evaluate_msk_reverse_replicator(d,main)[0]['verdict']=='PASS'


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    main=target('main','AWS::MSK::Replicator',ReplicationInfoList=[info(A,B)])
    other=target('other','AWS::MSK::Replicator',ReplicationInfoList=[info(B,A)])
    d=linked_design(main,[other]);root=Path(__file__).resolve().parents[1]
    rows=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results']
    assert any(f['rule_id']=='MSK_ENHANCED_REVERSE_REPLICATOR' and f['verdict']=='PASS' for f in rows)
