from pathlib import Path
import pytest
from aws_design_sheet.checks.mediapackagev2.endpoint_timestamp_locking import evaluate_mediapackagev2_endpoint_timestamp_locking
from aws_design_sheet.checks.mediaconnect.interface_flow_az import evaluate_mediaconnect_interface_flow_az
from aws_design_sheet.checks.registry import combine
media_channel_links_checks = combine(evaluate_mediapackagev2_endpoint_timestamp_locking, evaluate_mediaconnect_interface_flow_az)
from aws_design_sheet.models import TemplateContext
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN
from aws_design_sheet.checker import Checker


@pytest.mark.parametrize('mode',['non_epoch','epoch','unknown_mode','omitted_mode','unknown_timestamp','unknown_group','different_group','different_name','external','conditional','ambiguous','scope','template','channel_template'])
def test_locking(mode):
    r=target('main','AWS::MediaPackageV2::OriginEndpoint',ChannelName='channel',ChannelGroupName=UNKNOWN if mode=='unknown_group' else 'group',Segment={'OutputTimestampMode':UNKNOWN if mode=='unknown_timestamp' else 'PASSTHROUGH'})
    c=target('channel','AWS::MediaPackageV2::Channel',ChannelName='other' if mode=='different_name' else 'channel',ChannelGroupName='other' if mode=='different_group' else 'group',**({} if mode=='omitted_mode' else {'OutputLockingMode':UNKNOWN if mode=='unknown_mode' else 'EPOCH_LOCKED' if mode=='epoch' else 'NON_EPOCH_LOCKED'}))
    d=linked_design(r,[c],[] if mode=='external' else [('ChannelName','channel')])
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='ambiguous':d.relations.append(d.relations[0].model_copy(update={'id':'duplicate'}))
    if mode=='scope':c.scope.account='222222222222'
    if mode=='template':r.template=TemplateContext(state='UNRESOLVED')
    if mode=='channel_template':c.template=TemplateContext(state='UNRESOLVED')
    assert media_channel_links_checks(d,r)[0]['verdict']==('PASS' if mode=='non_epoch' else 'FAIL' if mode=='epoch' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('mode',['same','different','flow_unknown','subnet_unknown','omitted','az_id','local_zone','external_flow','external_subnet','conditional','ambiguous','scope','unknown_scope','template','flow_template','subnet_template'])
def test_interface(mode):
    r=target('main','AWS::MediaConnect::FlowVpcInterface',FlowArn='flow',SubnetId='subnet')
    f=target('flow','AWS::MediaConnect::Flow',AvailabilityZone=UNKNOWN if mode=='flow_unknown' else 'ap-northeast-1a')
    s=target('subnet','AWS::EC2::Subnet',**({} if mode=='omitted' else {'AvailabilityZoneId':'apne1-az1'} if mode=='az_id' else {'AvailabilityZone':UNKNOWN if mode=='subnet_unknown' else 'ap-northeast-1b' if mode=='different' else 'ap-northeast-1-tpe-1a' if mode=='local_zone' else 'ap-northeast-1a'}))
    d=linked_design(r,[f,s],([] if mode=='external_flow' else [('FlowArn','flow')])+([] if mode=='external_subnet' else [('SubnetId','subnet')]))
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='ambiguous':d.relations.append(d.relations[0].model_copy(update={'id':'duplicate'}))
    if mode=='scope':s.scope.account='222222222222'
    if mode=='unknown_scope':r.scope.account=f.scope.account=s.scope.account='unknown'
    if mode=='template':r.template=TemplateContext(state='UNRESOLVED')
    if mode=='flow_template':f.template=TemplateContext(state='UNRESOLVED')
    if mode=='subnet_template':s.template=TemplateContext(state='UNRESOLVED')
    assert media_channel_links_checks(d,r)[0]['verdict']==('PASS' if mode=='same' else 'FAIL' if mode=='different' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('kind',['AWS::MediaPackageV2::OriginEndpoint','AWS::MediaConnect::FlowVpcInterface'])
def test_absent(kind):
    r=target('main',kind)
    assert not media_channel_links_checks(linked_design(r),r)


def test_checker_locking():
    r=target('main','AWS::MediaPackageV2::OriginEndpoint',ChannelName='channel',ChannelGroupName='group',Segment={'OutputTimestampMode':'REBASED_TO_CHANNEL_START'})
    c=target('channel','AWS::MediaPackageV2::Channel',ChannelName='channel',ChannelGroupName='group',OutputLockingMode='EPOCH_LOCKED')
    root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r,[c],[('ChannelName','channel')]))['results']
    assert any(f['rule_id']=='MEDIAPACKAGE_ENDPOINT_TIMESTAMP_LOCKING' and f['verdict']=='FAIL' for f in results)
