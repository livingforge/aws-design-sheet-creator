import pytest
from aws_design_sheet.checks.budgets.recursive_match_options import evaluate_budgets_recursive_match_options
from aws_design_sheet.checks.cloudformation.guardhook_input_file_suffix import evaluate_cloudformation_guardhook_input_file_suffix
from aws_design_sheet.checks.codebuild.filter_event_required import evaluate_codebuild_filter_event_required
from aws_design_sheet.checks.dlm.deprecation_same_unit import evaluate_dlm_deprecation_same_unit
from aws_design_sheet.checks.medialive.high_res_h265 import evaluate_medialive_high_res_h265
from aws_design_sheet.checks.mediapackagev2.start_offset import evaluate_mediapackagev2_start_offset
from aws_design_sheet.checks.pricingplanmanager.cloudfront_resources import evaluate_pricingplanmanager_cloudfront_resources
from aws_design_sheet.checks.registry import combine
remaining_values_checks = combine(evaluate_budgets_recursive_match_options, evaluate_cloudformation_guardhook_input_file_suffix, evaluate_codebuild_filter_event_required, evaluate_dlm_deprecation_same_unit, evaluate_medialive_high_res_h265, evaluate_mediapackagev2_start_offset, evaluate_pricingplanmanager_cloudfront_resources)
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


def check(kind,rule,props):
    r=target('one','AWS::'+kind,**props)
    return [x for x in remaining_values_checks(linked_design(r),r) if x['rule_id']==rule]


@pytest.mark.parametrize('depth',[0,1,25])
@pytest.mark.parametrize('options,expected',[(['EQUALS'],'PASS'),(['EQUALS','CASE_SENSITIVE'],'FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_recursive_budget(depth,options,expected):
    expr={'Dimensions':{'MatchOptions':options}}
    for i in range(depth):expr={'Not':{'And':[{'Or':[expr]}]}}
    assert check('Budgets::Budget','BUDGETS_RECURSIVE_MATCH_OPTIONS',{'Budget':{'FilterExpression':expr}})[0]['verdict']==expected


@pytest.mark.parametrize('array',[False,True])
@pytest.mark.parametrize('uri,expected',[('s3://bucket/a.yaml','PASS'),('s3://bucket/a.tar.gz','PASS'),('s3://bucket/a.txt','FAIL'),('s3://bucket/a.JSON','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_guard_input_shape(array,uri,expected):
    item={'Uri':uri}
    assert check('CloudFormation::GuardHook','GUARDHOOK_INPUT_FILE_SUFFIX',{'Options':{'InputParams':[item] if array else item}})[0]['verdict']==expected


@pytest.mark.parametrize('groups,expected',[([[{'Type':'EVENT'}]],'PASS'),([[{'Type':'HEAD_REF'}]],'FAIL'),([[{'Type':UNKNOWN}]],'NEEDS_REVIEW'),([[{'Type':'EVENT'}],[{'Type':'HEAD_REF'}]],'NEEDS_REVIEW'),([[{'Type':'EVENT'},UNKNOWN]],'PASS')])
def test_filter_event(groups,expected):
    assert check('CodeBuild::Project','CODEBUILD_FILTER_EVENT_REQUIRED',{'Triggers':{'FilterGroups':groups}})[0]['verdict']==expected


@pytest.mark.parametrize('cross',[False,True])
@pytest.mark.parametrize('interval,unit,expected',[(3,'DAYS','PASS'),(4,'DAYS','FAIL'),(3,'MONTHS','NEEDS_REVIEW'),(UNKNOWN,'DAYS','NEEDS_REVIEW')])
def test_deprecation(cross,interval,unit,expected):
    rule={'DeprecateRule':{'Interval':interval,'IntervalUnit':unit},'RetainRule':{'Interval':3,'IntervalUnit':'DAYS'}}
    assert check('DLM::LifecyclePolicy','DLM_DEPRECATION_SAME_UNIT',{'PolicyDetails':{'Schedules':[{'CrossRegionCopyRules':[rule]} if cross else rule]}})[0]['verdict']==expected


@pytest.mark.parametrize('height,raw,expected',[(2160,'DISABLED','PASS'),(2160,'ENABLED','FAIL'),(1080,'ENABLED','NEEDS_REVIEW'),(UNKNOWN,'DISABLED','NEEDS_REVIEW')])
def test_h265_resolution(height,raw,expected):
    props={'EncoderSettings':{'VideoDescriptions':[{'Width':3840,'Height':height,'CodecSettings':{'H265Settings':{'GopBReference':raw,'SubgopLength':'FIXED','GopNumBFrames':2}}}]}}
    assert check('MediaLive::Channel','MEDIALIVE_HIGH_RES_H265',props)[0]['verdict']==expected


@pytest.mark.parametrize('kind',['HlsManifests','LowLatencyHlsManifests'])
@pytest.mark.parametrize('offset,expected',[(41.9,'PASS'),(42,'FAIL'),(-18,'FAIL'),(-18.1,'PASS'),(-60,'FAIL'),(0,'NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_manifest_strict_bounds(kind,offset,expected):
    assert check('MediaPackageV2::OriginEndpoint','MEDIAPACKAGE_START_OFFSET',{'Segment':{'SegmentDurationSeconds':6},kind:[{'ManifestWindowSeconds':60,'StartTag':{'TimeOffset':offset}}]})[0]['verdict']==expected


CF='arn:aws:cloudfront::111111111111:distribution/ABC'
WAF='arn:aws:wafv2:us-east-1:111111111111:global/webacl/name/id'
@pytest.mark.parametrize('arns,expected',[([CF,WAF],'PASS'),([CF],'FAIL'),([WAF],'FAIL'),([CF,UNKNOWN],'NEEDS_REVIEW'),([CF,WAF,UNKNOWN],'PASS')])
def test_required_resource_families(arns,expected):
    assert check('PricingPlanManager::Subscription','PRICINGPLAN_CLOUDFRONT_RESOURCES',{'PlanFamily':'CloudFront','ResourceArns':arns})[0]['verdict']==expected
