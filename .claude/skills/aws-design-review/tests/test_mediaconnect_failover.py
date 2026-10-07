import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.mediaconnect.failover import evaluate_mediaconnect_failover
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_template_dependencies import link


def fixture(protocol='srt-caller',existing='srt-caller',state='ENABLED',mode='FAILOVER'):
    source=target('additional','AWS::MediaConnect::FlowSource',Name='backup',Protocol=protocol)
    parent=target('flow','AWS::MediaConnect::Flow',Source={'Name':'primary','Protocol':existing},SourceFailoverConfig={'State':state,'FailoverMode':mode,'SourcePriority':{'PrimarySource':'primary'}})
    d=linked_design(source,[parent]);link(d,source,'FlowArn',parent)
    return d,source,parent


@pytest.mark.parametrize('protocol,existing,state,mode,expected',[
    ('srt-caller','srt-caller','ENABLED','FAILOVER','PASS'),
    ('srt-listener','srt-listener','ENABLED','FAILOVER','PASS'),
    ('srt-caller','srt-caller','ENABLED','MERGE','FAIL'),
    ('rtp','rtp','ENABLED','MERGE','PASS'),
    ('rtp','rtp-fec','ENABLED','MERGE','FAIL'),
    ('rist','rist','DISABLED','FAILOVER','FAIL'),
    ('rist','rist',UNKNOWN,'FAILOVER','NEEDS_REVIEW'),
    ('srt-caller','srt-caller','ENABLED',UNKNOWN,'NEEDS_REVIEW'),
    (UNKNOWN,'rtp','ENABLED','MERGE','NEEDS_REVIEW'),
    ('rtp',UNKNOWN,'ENABLED','MERGE','NEEDS_REVIEW')])
def test_failover_requirements(protocol,existing,state,mode,expected):
    d,r,p=fixture(protocol,existing,state,mode)
    assert evaluate_mediaconnect_failover(d,r)[0]['verdict']==expected


@pytest.mark.parametrize('count,state,expected',[(0,'ENABLED','NEEDS_REVIEW'),(1,'ENABLED','NEEDS_REVIEW'),(2,'ENABLED','FAIL'),(1,'DISABLED','FAIL')])
def test_known_source_count_violations(count,state,expected):
    d,r,p=fixture(state=state);d.resources.remove(r);d.relations.clear()
    for i in range(count):
        source=target('extra'+str(i),r.type,Name='backup'+str(i),Protocol='rtp')
        d.resources.append(source);link(d,source,'FlowArn',p)
    findings=evaluate_mediaconnect_failover(d,p)
    assert findings[0]['verdict']==expected
    assert findings[1]['verdict']=='PASS'


def test_external_primary_is_held():
    d,r,p=fixture();p.fields[1].candidates[0].value['SourcePriority']['PrimarySource']='external'
    assert evaluate_mediaconnect_failover(d,p)[1]['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('mode,expected',[('matching','FAIL'),('different_name','NEEDS_REVIEW'),('non_ndi','NEEDS_REVIEW'),('conditional','NEEDS_REVIEW')])
def test_ndi_cannot_use_standalone_interface(mode,expected):
    d,source,p=fixture()
    interface=target('interface','AWS::MediaConnect::FlowVpcInterface',Name='vpc')
    output=target('output','AWS::MediaConnect::FlowOutput',Protocol='ndi-speed-hq',VpcInterfaceAttachment={'VpcInterfaceName':'vpc'})
    d.resources.extend([interface,output]);link(d,interface,'FlowArn',p);link(d,output,'FlowArn',p)
    if mode=='different_name':output.fields[1].candidates[0].value['VpcInterfaceName']='other'
    if mode=='non_ndi':output.fields[0].candidates[0].value='rtp'
    if mode=='conditional':d.relations[-1].condition='Maybe'
    assert evaluate_mediaconnect_failover(d,interface)[0]['verdict']==expected


def test_unknown_parent_template_is_held():
    d,r,p=fixture();p.template=TemplateContext(state='UNRESOLVED')
    assert evaluate_mediaconnect_failover(d,r)[0]['verdict']=='NEEDS_REVIEW'


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    d,r,*_=fixture();root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results']
    assert any(f['rule_id']=='MEDIACONNECT_ADDITIONAL_SOURCE_FAILOVER' and f['verdict']=='PASS' for f in results)
