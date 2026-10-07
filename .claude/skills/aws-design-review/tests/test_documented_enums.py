import pytest
from pathlib import Path
from aws_design_sheet.checker import Checker
from aws_design_sheet.checks.waf.match_set_enums import evaluate_waf_match_set_enums, evaluate_wafregional_match_set_enums
from aws_design_sheet.checks.pinpoint.segment import evaluate_pinpoint_segment
from aws_design_sheet.checks.common.enum_findings import SPECS, DIMENSIONS, FIELDS
from aws_design_sheet.checks.registry import combine
from aws_design_sheet.checks.redshift.port_and_wlm_json import evaluate_redshift_port_and_wlm_json
from aws_design_sheet.checks.pinpoint.campaign_hook_mode import evaluate_pinpoint_campaign_hook_mode
redshift_inputs_checks = combine(evaluate_redshift_port_and_wlm_json, evaluate_pinpoint_campaign_hook_mode)
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN
from test_config_pipeline import nested
enum_residuals_checks=combine(evaluate_waf_match_set_enums,evaluate_wafregional_match_set_enums,evaluate_pinpoint_segment)


@pytest.mark.parametrize('kind',list(SPECS))
@pytest.mark.parametrize('raw,expected',[(v,'PASS') for v in FIELDS]+[('unknown','FAIL'),(UNKNOWN,'NEEDS_REVIEW'),('${field}','NEEDS_REVIEW')])
def test_classic_fields(kind,raw,expected):
    r=target('main',kind,**{SPECS[kind][1]:[{'FieldToMatch':{'Type':raw}}]})
    assert enum_residuals_checks(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('key',DIMENSIONS)
@pytest.mark.parametrize('grouped',[False,True])
@pytest.mark.parametrize('raw,expected',[('INCLUSIVE','PASS'),('EXCLUSIVE','PASS'),('invalid','FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_set_dimensions(key,grouped,raw,expected):
    props=nested((key+'/DimensionType').split('/'),raw)
    r=target('main','AWS::Pinpoint::Segment',**({'SegmentGroups':{'Groups':[{'Dimensions':[props]}]}} if grouped else {'Dimensions':props}))
    results=enum_residuals_checks(linked_design(r),r)
    assert len(results)==1 and results[0]['verdict']==expected


@pytest.mark.parametrize('kind,key',[('AWS::Pinpoint::Campaign','Hook'),('AWS::Pinpoint::ApplicationSettings','CampaignHook')])
@pytest.mark.parametrize('raw,expected',[('FILTER','PASS'),('DELIVERY','NEEDS_REVIEW'),('invalid','FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_hook_correct_resource_path(kind,key,raw,expected):
    r=target('main',kind,**{key:{'Mode':raw}})
    results=redshift_inputs_checks(linked_design(r),r)
    assert len(results)==1 and results[0]['verdict']==expected
    assert results[0]['rule_id']=='PINPOINT_CAMPAIGN_HOOK_MODE'


@pytest.mark.parametrize('kind,key,rule',[(kind,key,rule) for kind,(rule,key,_) in SPECS.items()]+[('AWS::Pinpoint::ApplicationSettings','CampaignHook','PINPOINT_CAMPAIGN_HOOK_MODE'),('AWS::Pinpoint::Segment','Dimensions','PINPOINT_SEGMENT_SET_DIMENSION')])
def test_checker_integration(kind,key,rule):
    raw=[{'FieldToMatch':{'Type':'invalid'}}] if kind in SPECS else {'Mode':'invalid'} if key=='CampaignHook' else {'Location':{'Country':{'DimensionType':'invalid'}}}
    r=target('main',kind,**{key:raw});root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    assert any(f['rule_id']==rule and f['verdict']=='FAIL' for f in results)


@pytest.mark.parametrize('kind',list(SPECS))
def test_unknown_collection(kind):
    r=target('main',kind,**{SPECS[kind][1]:UNKNOWN})
    results=enum_residuals_checks(linked_design(r),r)
    assert len(results)==1 and results[0]['verdict']=='NEEDS_REVIEW'
