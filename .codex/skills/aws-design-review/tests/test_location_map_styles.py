import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.location.map_styles import evaluate_location_map_styles
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


def fixture(style,region='ap-southeast-1'):
    r=target('map','AWS::Location::Map',Configuration={'Style':style})
    r.scope.region=region
    return linked_design(r),r


@pytest.mark.parametrize('style',[
    'VectorEsriDarkGrayCanvas','RasterEsriImagery','VectorEsriLightGrayCanvas',
    'VectorEsriTopographic','VectorEsriStreets','VectorEsriNavigation',
    'VectorHereContrast','VectorHereBerlin','VectorHereExplore','VectorHereExploreTruck',
    'RasterHereExploreSatellite','HybridHereExploreSatellite',
    'VectorGrabStandardLight','VectorGrabStandardDark',
    'VectorOpenDataStandardLight','VectorOpenDataStandardDark',
    'VectorOpenDataVisualizationLight','VectorOpenDataVisualizationDark'])
def test_documented_names_including_deprecated_alias(style):
    d,r=fixture(style)
    findings=evaluate_location_map_styles(d,r)
    assert findings[0]['verdict']=='PASS'
    assert findings[1]['verdict']==('PASS' if style.startswith('VectorGrab') else 'NOT_APPLICABLE')


@pytest.mark.parametrize('style',['VectorGrabStandardLight','VectorGrabStandardDark'])
@pytest.mark.parametrize('region',['ap-northeast-1','us-east-1','ap-southeast-2'])
def test_grab_is_singapore_only(style,region):
    d,r=fixture(style,region)
    assert evaluate_location_map_styles(d,r)[1]['verdict']=='FAIL'


@pytest.mark.parametrize('style,expected',[
    ('VectorHereBerlinn','FAIL'),('vectorgrabstandardlight','FAIL'),
    ('VectorUnknownStyle','FAIL'),(UNKNOWN,'NEEDS_REVIEW'),
    ({'Ref':'StyleParameter'},'NEEDS_REVIEW'),('', 'NEEDS_REVIEW'),
    (None,'NEEDS_REVIEW')])
def test_invalid_and_unresolved_styles(style,expected):
    d,r=fixture(style)
    assert evaluate_location_map_styles(d,r)[0]['verdict']==expected
    assert evaluate_location_map_styles(d,r)[1]['verdict']=='NEEDS_REVIEW'


def test_conditional_template_is_not_decided():
    d,r=fixture('VectorGrabStandardDark','us-east-1')
    r.template=TemplateContext(state='UNRESOLVED')
    assert all(f['verdict']=='NEEDS_REVIEW' for f in evaluate_location_map_styles(d,r))


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    d,r=fixture('VectorGrabStandardLight','ap-northeast-1');root=Path(__file__).resolve().parents[1]
    findings=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results']
    assert any(f['rule_id']=='LOCATION_GRAB_MAP_REGION' and f['verdict']=='FAIL' for f in findings)
