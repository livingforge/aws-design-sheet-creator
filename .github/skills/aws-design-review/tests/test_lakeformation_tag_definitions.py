import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.lakeformation.tag_definitions import evaluate_lakeformation_tag_definitions
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_template_dependencies import template,link


def fixture(wanted=None,allowed=None,key='MODULE'):
    main=template(target('main','AWS::LakeFormation::TagAssociation',LFTags=[{'CatalogId':'111111111111','TagKey':key,'TagValues':['Orders'] if wanted is None else wanted}]))
    tag=template(target('tag','AWS::LakeFormation::Tag',TagKey='module',TagValues=['orders','customers'] if allowed is None else allowed))
    return linked_design(main,[tag],[('LFTags/0/TagKey','tag')]),main,tag


@pytest.mark.parametrize('wanted,allowed,expected',[
    (['orders'],['orders','customers'],'PASS'),(['Orders'],['ORDERS'],'PASS'),
    (['absent'],['orders'],'FAIL'),(['orders',UNKNOWN],['orders'],'NEEDS_REVIEW'),
    (['absent',UNKNOWN],['orders'],'FAIL'),(['orders'],['orders',UNKNOWN],'PASS'),
    (['absent'],['orders',UNKNOWN],'NEEDS_REVIEW'),(['é'],['é'],'NEEDS_REVIEW'),
])
def test_declared_values(wanted,allowed,expected):
    d,r,_=fixture(wanted,allowed)
    assert evaluate_lakeformation_tag_definitions(d,r)[0]['verdict']==expected


@pytest.mark.parametrize('mode',['catalog','key','missing_catalog','scope','condition','missing','template','other_stack','no_membership','unknown_key'])
def test_unresolved_identity(mode):
    d,r,t=fixture();row=r.fields[0].candidates[0].value[0]
    if mode=='catalog':row['CatalogId']='222222222222'
    if mode=='key':row['TagKey']='different'
    if mode=='missing_catalog':del row['CatalogId']
    if mode=='scope':t.scope.region='us-east-1'
    if mode=='condition':d.relations[0].condition='Maybe'
    if mode=='missing':d.relations=[]
    if mode=='template':t.template=TemplateContext(state='UNRESOLVED')
    if mode=='other_stack':t.template.id='other'
    if mode=='no_membership':r.template=None;t.template=None
    if mode=='unknown_key':row['TagKey']=UNKNOWN
    assert evaluate_lakeformation_tag_definitions(d,r)[0]['verdict']=='NEEDS_REVIEW'


def test_cyclic_template_order():
    d,r,t=fixture();t.template.depends_on=['main']
    assert evaluate_lakeformation_tag_definitions(d,r)[0]['verdict']=='FAIL'


def test_multiple_tags_all_must_be_defined():
    d,r,t=fixture();r.fields[0].candidates[0].value.append({'CatalogId':'111111111111','TagKey':'region','TagValues':['north']})
    other=template(target('region','AWS::LakeFormation::Tag',TagKey='region',TagValues=['north']))
    d.resources.append(other);link(d,r,'LFTags/1/TagKey',other)
    assert evaluate_lakeformation_tag_definitions(d,r)[0]['verdict']=='PASS'
    other.fields[1].candidates[0].value=['south']
    assert evaluate_lakeformation_tag_definitions(d,r)[0]['verdict']=='FAIL'


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    d,r,*_=fixture();root=Path(__file__).resolve().parents[1]
    actual=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results']
    assert any(f['rule_id']=='LAKEFORMATION_ASSOCIATION_TAG_DEFINITIONS' and f['verdict']=='PASS' for f in actual)
