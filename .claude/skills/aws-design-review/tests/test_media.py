from pathlib import Path
import pytest
from aws_design_sheet.checks.medialive.channel_geometry import evaluate_medialive_channel_geometry
from aws_design_sheet.checks.mediapackagev2.manifest_names import evaluate_mediapackagev2_manifest_names
from aws_design_sheet.checks.memorydb.snapshot_object_commas import evaluate_memorydb_snapshot_object_commas
from aws_design_sheet.checks.neptune.cluster_values import evaluate_neptune_cluster_values
from aws_design_sheet.checks.registry import combine
media_checks = combine(evaluate_medialive_channel_geometry, evaluate_mediapackagev2_manifest_names, evaluate_memorydb_snapshot_object_commas, evaluate_neptune_cluster_values)
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


def check(kind,rule,**props):
    r=target('subject','AWS::'+kind,**props)
    return [x for x in media_checks(linked_design(r),r) if x['rule_id']==rule]


@pytest.mark.parametrize('owner',['','CropRectangle','OutputPositionRectangle'])
@pytest.mark.parametrize('key',['Width','Height'])
@pytest.mark.parametrize('n,expected',[(100,'PASS'),(101,'FAIL'),(True,'NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_video_even(owner,key,n,expected):
    fields={owner:{key:n}} if owner else {key:n}
    assert check('MediaLive::Channel','MEDIALIVE_VIDEO_EVEN',EncoderSettings={'VideoDescriptions':[fields]})[0]['verdict']==expected


@pytest.mark.parametrize('owner',['CropRectangle','OutputPositionRectangle'])
@pytest.mark.parametrize('key',['X','Y'])
def test_rectangle_offsets(owner,key):
    assert check('MediaLive::Channel','MEDIALIVE_VIDEO_EVEN',EncoderSettings={'VideoDescriptions':[{owner:{key:1}}]})[0]['verdict']=='FAIL'


@pytest.mark.parametrize('border,width,height,expected',[
    (100,202,202,'PASS'),(100,200,202,'FAIL'),(100,202,200,'FAIL'),(101,1000,1000,'FAIL'),
    (3,100,100,'FAIL'),(-2,100,100,'FAIL'),(0,100,100,'PASS'),(2,UNKNOWN,100,'NEEDS_REVIEW'),
    (2,4,UNKNOWN,'FAIL'),(UNKNOWN,100,100,'NEEDS_REVIEW')])
def test_border(border,width,height,expected):
    assert check('MediaLive::Channel','MEDIALIVE_VIDEO_BORDER',EncoderSettings={'VideoDescriptions':[{'Border':border,'Width':width,'Height':height}]})[0]['verdict']==expected


@pytest.mark.parametrize('destination',['TtmlDestinationSettings','EbuTtDDestinationSettings'])
@pytest.mark.parametrize('offset,size,mode,expected',[
    (0.1,99.9,'normal','PASS'),(0.1,100,'normal','FAIL'),(UNKNOWN,50,'normal','NEEDS_REVIEW'),
    (1,100,'other_output','NEEDS_REVIEW'),(1,100,'duplicate','NEEDS_REVIEW'),(1,100,'wrong_name','NEEDS_REVIEW')])
def test_caption_rectangle(destination,offset,size,mode,expected):
    selector={'Name':'captions','SelectorSettings':{'TeletextSourceSettings':{'OutputRectangle':{'LeftOffset':offset,'Width':size,'TopOffset':offset,'Height':size}}}}
    selectors=[selector,selector] if mode=='duplicate' else [selector]
    description={'CaptionSelectorName':'different' if mode=='wrong_name' else 'captions','DestinationSettings':{destination if mode!='other_output' else 'DvbSubDestinationSettings':{}}}
    rows=check('MediaLive::Channel','MEDIALIVE_CAPTION_RECTANGLE',InputAttachments=[{'InputSettings':{'CaptionSelectors':selectors}}],EncoderSettings={'CaptionDescriptions':[description]})
    assert rows and all(x['verdict']==expected for x in rows)


@pytest.mark.parametrize('hls,low,expected',[
    (['index'],['index'],'FAIL'),(['index'],['live'],'PASS'),(['index',UNKNOWN],['index'],'FAIL'),
    ([UNKNOWN],['live'],'NEEDS_REVIEW'),(['index'],[UNKNOWN],'NEEDS_REVIEW'),([],['index'],'PASS')])
def test_manifest_names(hls,low,expected):
    assert check('MediaPackageV2::OriginEndpoint','MEDIAPACKAGE_MANIFEST_NAMES',HlsManifests=[{'ManifestName':n} for n in hls],LowLatencyHlsManifests=[{'ManifestName':n} for n in low])[0]['verdict']==expected


@pytest.mark.parametrize('arn,expected',[
    ('arn:aws:s3:::bucket/path/snapshot.rdb','PASS'),('arn:aws:s3:::bucket/path,snapshot.rdb','FAIL'),
    ('arn:aws-cn:s3:::bucket/path/a,b','FAIL'),('arn:aws:s3:::bucket/path/a%2Cb','PASS'),
    ('arn:aws:s3:::bucket','NEEDS_REVIEW'),('arn:aws:s3:::bad,bucket/a','NEEDS_REVIEW'),
    ('s3://bucket/a,b','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_snapshot_names(arn,expected):
    assert check('MemoryDB::Cluster','MEMORYDB_SNAPSHOT_OBJECT_COMMAS',SnapshotArns=[arn])[0]['verdict']==expected


@pytest.mark.parametrize('name,expected',[
    ('DB-123','PASS'),('db--123','FAIL'),('db-','FAIL'),('1db','FAIL'),('db_name','FAIL'),
    ('名前','FAIL'),('${Source}','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_neptune_source_ids(name,expected):
    assert check('Neptune::EventSubscription','NEPTUNE_EVENT_SOURCE_IDS',SourceIds=[name])[0]['verdict']==expected


@pytest.mark.parametrize('version,expected',[
    ('1.1.9.9','FAIL'),('1.2.0.0','PASS'),('1.10.0.0','PASS'),('2.0.0.0','PASS'),
    ('1.2','NEEDS_REVIEW'),('1.2.0.0.R1','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_neptune_version(version,expected):
    assert check('Neptune::GlobalCluster','NEPTUNE_GLOBAL_MIN_VERSION',EngineVersion=version)[0]['verdict']==expected


def test_checker_integration():
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('subject','AWS::MediaLive::Channel',EncoderSettings={'VideoDescriptions':[{'Width':101}]})
    result=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))
    row=next(x for x in result['results'] if x['rule_id']=='MEDIALIVE_VIDEO_EVEN')
    assert row['verdict']=='FAIL' and row['source_urls'] and row['evidence_ids']
