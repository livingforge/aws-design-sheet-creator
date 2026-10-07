import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.mediapackagev2.multiview_sources import evaluate_mediapackagev2_multiview_sources
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_template_dependencies import link


def fixture():
    r=target('multiview','AWS::MediaPackageV2::Channel',InputType='MULTIVIEW',ChannelGroupName='group',MultiviewConfiguration={'AvailableSources':['source']})
    source=target('source','AWS::MediaPackageV2::Channel',InputType='CMAF',ChannelGroupName='group',ChannelName='source')
    d=linked_design(r,[source]);link(d,r,'MultiviewConfiguration/AvailableSources/0',source)
    return d,r,source


@pytest.mark.parametrize('mode,expected',[
    ('same','PASS'),('different_group','FAIL'),('hls','FAIL'),('multiview','FAIL'),
    ('unknown_input','NEEDS_REVIEW'),('unknown_group','NEEDS_REVIEW'),
    ('conditional','NEEDS_REVIEW'),('scope','NEEDS_REVIEW'),('template','NEEDS_REVIEW'),
    ('no_reference','NEEDS_REVIEW'),('name_mismatch','NEEDS_REVIEW'),
    ('unknown_sources','NEEDS_REVIEW'),('empty_sources','NEEDS_REVIEW'),
    ('no_multiview','NOT_APPLICABLE')])
def test_multiview_source_conditions(mode,expected):
    d,r,s=fixture()
    if mode=='different_group':s.fields[1].candidates[0].value='other'
    if mode=='hls':s.fields[0].candidates[0].value='HLS'
    if mode=='multiview':s.fields[0].candidates[0].value='MULTIVIEW'
    if mode=='unknown_input':s.fields[0].candidates[0].value=UNKNOWN
    if mode=='unknown_group':s.fields[1].candidates[0].value=UNKNOWN
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='scope':s.scope.region='us-east-1'
    if mode=='template':s.template=TemplateContext(state='UNRESOLVED')
    if mode=='no_reference':d.relations.clear()
    if mode=='name_mismatch':s.fields[-1].candidates[0].value='other'
    if mode=='unknown_sources':r.fields[-1].candidates[0].value['AvailableSources']=UNKNOWN
    if mode=='empty_sources':r.fields[-1].candidates[0].value['AvailableSources']=[]
    if mode=='no_multiview':r.fields.pop();d.relations.clear()
    assert evaluate_mediapackagev2_multiview_sources(d,r)[0]['verdict']==expected


def test_explicit_channel_group_references():
    d,r,s=fixture();group=target('group','AWS::MediaPackageV2::ChannelGroup',ChannelGroupName='group')
    d.resources.append(group)
    for node in (r,s):
        node.fields=[f for f in node.fields if f.path!='/properties/ChannelGroupName'];link(d,node,'ChannelGroupName',group)
    assert evaluate_mediapackagev2_multiview_sources(d,r)[0]['verdict']=='PASS'
    d.relations[-1].condition='Maybe'
    assert evaluate_mediapackagev2_multiview_sources(d,r)[0]['verdict']=='NEEDS_REVIEW'


def test_all_source_entries_are_checked():
    d,r,s=fixture();other=target('other',s.type,InputType='HLS',ChannelGroupName='group',ChannelName='other')
    d.resources.append(other);r.fields[-1].candidates[0].value['AvailableSources'].append('other')
    link(d,r,'MultiviewConfiguration/AvailableSources/1',other)
    assert evaluate_mediapackagev2_multiview_sources(d,r)[0]['verdict']=='FAIL'


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    d,r,*_=fixture();root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results']
    assert any(f['rule_id']=='MEDIAPACKAGE_MULTIVIEW_SOURCES' and f['verdict']=='PASS' for f in results)
