import pytest
from aws_design_sheet.checks.workspaces.volume_key_type import evaluate_workspaces_volume_key_type
from aws_design_sheet.checks.workspacesweb.subnet_az_diversity import evaluate_workspacesweb_subnet_az_diversity
from aws_design_sheet.checks.xray.policy_utf8_size import evaluate_xray_policy_utf8_size
from aws_design_sheet.checks.waf.byte_position_and_sql import evaluate_waf_byte_position_and_sql, evaluate_wafregional_byte_position_and_sql
from aws_design_sheet.checks.registry import combine
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN
queue_inputs_checks = combine(evaluate_workspaces_volume_key_type, evaluate_workspacesweb_subnet_az_diversity, evaluate_xray_policy_utf8_size, evaluate_waf_byte_position_and_sql, evaluate_wafregional_byte_position_and_sql)


@pytest.mark.parametrize('case',['different_ids','same_ids','mixed','both_consistent','contradict_name','contradict_id','unknown_third','conditional','wrong_scope'])
def test_az_id_evidence(case):
    aprops={'AvailabilityZoneId':'apne1-az1'};bprops={'AvailabilityZoneId':'apne1-az1' if case=='same_ids' else 'apne1-az2'}
    if case=='mixed':aprops={'AvailabilityZone':'ap-northeast-1a'}
    if case in ('both_consistent','contradict_name','contradict_id'):
        aprops['AvailabilityZone']='ap-northeast-1a';bprops['AvailabilityZone']='ap-northeast-1a' if case=='contradict_name' else 'ap-northeast-1c'
        if case=='contradict_id':bprops['AvailabilityZoneId']='apne1-az1'
    r=target('main','AWS::WorkSpacesWeb::NetworkSettings',SubnetIds=['a','b','unknown'] if case=='unknown_third' else ['a','b'])
    a=target('a','AWS::EC2::Subnet',**aprops);b=target('b','AWS::EC2::Subnet',**bprops)
    d=linked_design(r,[a,b],[('SubnetIds/0','a'),('SubnetIds/1','b')])
    if case=='conditional':d.relations[-1].condition='maybe'
    if case=='wrong_scope':b.scope.account='222222222222'
    expected='PASS' if case in ('different_ids','both_consistent','unknown_third') else 'FAIL' if case=='same_ids' else 'NEEDS_REVIEW'
    assert queue_inputs_checks(d,r)[0]['verdict']==expected


def test_mixed_names_resolved_by_explicit_mapping():
    r=target('main','AWS::WorkSpacesWeb::NetworkSettings',SubnetIds=['a','b','c'])
    a=target('a','AWS::EC2::Subnet',AvailabilityZone='ap-northeast-1a')
    b=target('b','AWS::EC2::Subnet',AvailabilityZoneId='apne1-az1')
    c=target('c','AWS::EC2::Subnet',AvailabilityZone='ap-northeast-1a',AvailabilityZoneId='apne1-az1')
    d=linked_design(r,[a,b,c],[('SubnetIds/0','a'),('SubnetIds/1','b'),('SubnetIds/2','c')])
    assert queue_inputs_checks(d,r)[0]['verdict']=='FAIL'
