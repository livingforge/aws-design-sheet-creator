from pathlib import Path
import pytest
from aws_design_sheet.checks.lightsail.tcp_udp_ports import evaluate_lightsail_tcp_udp_ports
from aws_design_sheet.checks.location.key_resource_scope import evaluate_location_key_resource_scope
from aws_design_sheet.checks.kinesisanalytics.output_format import evaluate_kinesisanalytics_output_format
from aws_design_sheet.checks.registry import combine
location_ports_checks = combine(evaluate_lightsail_tcp_udp_ports, evaluate_location_key_resource_scope, evaluate_kinesisanalytics_output_format)
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('protocol',['tcp','udp'])
@pytest.mark.parametrize('ports,verdict',[({'FromPort':0,'ToPort':65535},'PASS'),({'FromPort':-1,'ToPort':80},'FAIL'),({'FromPort':80,'ToPort':65536},'FAIL'),({'FromPort':UNKNOWN,'ToPort':65536},'FAIL'),({'FromPort':UNKNOWN,'ToPort':80},'NEEDS_REVIEW'),({'FromPort':True,'ToPort':80},'NEEDS_REVIEW'),({'FromPort':1.5,'ToPort':80},'NEEDS_REVIEW'),({},'NEEDS_REVIEW')])
def test_ports(protocol,ports,verdict):
    r=target('main','AWS::Lightsail::Instance',Networking={'Ports':[dict(Protocol=protocol,**ports)]})
    assert location_ports_checks(linked_design(r),r)[0]['verdict']==verdict


@pytest.mark.parametrize('protocol',['icmp','icmpv6','all','TCP',UNKNOWN])
def test_other_protocol(protocol):
    r=target('main','AWS::Lightsail::Instance',Networking={'Ports':[dict(Protocol=protocol,FromPort=-1,ToPort=-1)]})
    assert location_ports_checks(linked_design(r),r)[0]['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('mode',['same','wildcard','account','region','enhanced','dynamic','malformed','unknown','unknown_account','unknown_region','template','linked'])
def test_scope(mode):
    raw=UNKNOWN if mode=='unknown' else '${arn}' if mode=='dynamic' else 'arn:aws:geo-maps:ap-northeast-1::provider/default' if mode=='enhanced' else 'bad' if mode=='malformed' else 'arn:aws:geo:'+('us-east-1' if mode=='region' else 'ap-northeast-1')+':'+('222222222222' if mode=='account' else '111111111111')+':map/'+('map*' if mode=='wildcard' else 'map')
    r=target('main','AWS::Location::APIKey',Restrictions={'AllowResources':[raw]})
    d=linked_design(r,[target('map','AWS::Location::Map')],[('Restrictions/AllowResources/0','map')] if mode=='linked' else [])
    if mode=='unknown_account':r.scope.account='unknown'
    if mode=='unknown_region':r.scope.region='unknown'
    if mode=='template':r.template=TemplateContext(state='UNRESOLVED')
    assert location_ports_checks(d,r)[0]['verdict']==('PASS' if mode in ('same','wildcard') else 'FAIL' if mode in ('account','region') else 'NEEDS_REVIEW')


@pytest.mark.parametrize('raw,verdict',[('JSON','PASS'),('CSV','PASS'),('XML','FAIL'),('json','FAIL'),(UNKNOWN,'NEEDS_REVIEW'),('${format}','NEEDS_REVIEW')])
def test_format(raw,verdict):
    r=target('main','AWS::KinesisAnalytics::ApplicationOutput',Output={'DestinationSchema':{'RecordFormatType':raw}})
    assert location_ports_checks(linked_design(r),r)[0]['verdict']==verdict


@pytest.mark.parametrize('kind',['AWS::Lightsail::Instance','AWS::Location::APIKey','AWS::KinesisAnalytics::ApplicationOutput'])
def test_absent(kind):
    r=target('main',kind)
    assert not location_ports_checks(linked_design(r),r)


def test_checker_ports():
    r=target('main','AWS::Lightsail::Instance',Networking={'Ports':[dict(Protocol='tcp',FromPort=0,ToPort=65536)]})
    root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    assert any(f['rule_id']=='LIGHTSAIL_TCP_UDP_PORTS' and f['verdict']=='FAIL' for f in results)
