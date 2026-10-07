import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.mediaconnect.output_context import evaluate_mediaconnect_output_context
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_template_dependencies import link


def fixture(protocol='ndi-speed-hq',kind='video',fmt='jxsv'):
    r=target('output','AWS::MediaConnect::FlowOutput',Protocol=protocol,MediaStreamOutputConfigurations=[{'MediaStreamName':'media','EncodingName':fmt,'EncodingParameters':{}}])
    parent=target('flow','AWS::MediaConnect::Flow',NdiConfig={'NdiState':'ENABLED'},Source={'Protocol':'cdi'},MediaStreams=[{'MediaStreamName':'media','MediaStreamType':kind}])
    d=linked_design(r,[parent]);link(d,r,'FlowArn',parent)
    return d,r,parent


def result(d,r):return {f['rule_id']:f['verdict'] for f in evaluate_mediaconnect_output_context(d,r)}


@pytest.mark.parametrize('kind,fmt,expected',[
    ('video','jxsv','PASS'),('video','raw','PASS'),('audio','pcm','PASS'),
    ('ancillary-data','smpte291','PASS'),('audio','jxsv','FAIL'),
    ('video','pcm','FAIL'),('ancillary-data','raw','FAIL'),
    ('unknown','pcm','NEEDS_REVIEW')])
def test_media_type_encoding(kind,fmt,expected):
    d,r,p=fixture(kind=kind,fmt=fmt)
    assert result(d,r)['MEDIACONNECT_OUTPUT_ENCODING_MEDIA_TYPE']==expected


@pytest.mark.parametrize('state,expected',[('ENABLED','PASS'),('DISABLED','FAIL'),(None,'FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_ndi_default_and_explicit_state(state,expected):
    d,r,p=fixture()
    p.fields[0].candidates[0].value={} if state is None else {'NdiState':state}
    assert result(d,r)['MEDIACONNECT_OUTPUT_NDI_ENABLED']==expected


def test_non_ndi_output_does_not_require_ndi():
    d,r,p=fixture(protocol='srt-caller');p.fields[0].candidates[0].value={'NdiState':'DISABLED'}
    assert result(d,r)['MEDIACONNECT_OUTPUT_NDI_ENABLED']=='NOT_APPLICABLE'


def test_unsupported_additional_cdi_source_is_not_positive_evidence():
    d,r,p=fixture();p.fields[1].candidates[0].value={'Protocol':'rtp'}
    assert result(d,r)['MEDIACONNECT_OUTPUT_CDI_ENCODING_CONTEXT']=='NEEDS_REVIEW'
    source=target('source','AWS::MediaConnect::FlowSource',Protocol='cdi')
    d.resources.append(source);link(d,source,'FlowArn',p)
    assert result(d,r)['MEDIACONNECT_OUTPUT_CDI_ENCODING_CONTEXT']=='NEEDS_REVIEW'
    d.relations[-1].condition='Maybe'
    assert result(d,r)['MEDIACONNECT_OUTPUT_CDI_ENCODING_CONTEXT']=='NEEDS_REVIEW'


@pytest.mark.parametrize('mode',['conditional','scope','template','literal_flow'])
def test_unresolved_flow(mode):
    d,r,p=fixture()
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='scope':p.scope.region='us-east-1'
    if mode=='template':p.template=TemplateContext(state='UNRESOLVED')
    if mode=='literal_flow':r.fields+=target('dummy',r.type,FlowArn='arn:aws:mediaconnect:ap-northeast-1:111111111111:flow:123:flow').fields
    assert set(result(d,r).values())=={'NEEDS_REVIEW'}


@pytest.mark.parametrize('mode',['missing','duplicate','unknown_name','unknown_type'])
def test_stream_identity_uncertainty(mode):
    d,r,p=fixture();rows=p.fields[2].candidates[0].value
    if mode=='missing':rows.clear()
    if mode=='duplicate':rows.append(rows[0].copy())
    if mode=='unknown_name':rows.append({'MediaStreamName':UNKNOWN})
    if mode=='unknown_type':rows[0]['MediaStreamType']=UNKNOWN
    assert result(d,r)['MEDIACONNECT_OUTPUT_ENCODING_MEDIA_TYPE']=='NEEDS_REVIEW'


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    d,r,*_=fixture();root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results']
    assert any(f['rule_id']=='MEDIACONNECT_OUTPUT_NDI_ENABLED' and f['verdict']=='PASS' for f in results)
