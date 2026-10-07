from pathlib import Path
import pytest
from aws_design_sheet.checks.multi_service.duplicate_names import SPECS, evaluate_multi_service_duplicate_names
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


def setup(kind,mode):
    spec=SPECS[kind];raw=['tool','client'] if spec['mode']=='ordered_array' else 123 if spec['mode']=='integer' else 'example'
    props={key:raw for key in spec['paths']};otherprops=dict(props)
    if mode=='different':otherprops[spec['paths'][0]]=['other'] if isinstance(raw,list) else 456 if type(raw) is int else 'different'
    if mode=='unknown':otherprops[spec['paths'][0]]=UNKNOWN
    if mode=='missing':otherprops.pop(spec['paths'][0])
    r=target('one',kind,**props);other=target('two',kind,**otherprops);parents=[];links=[]
    if spec['parent']:
        key,expected=spec['parent'];parents=[target('parent',expected),target('parent2',expected)];links=[(key,'parent')]
    d=linked_design(r,[other]+parents,links)
    if links:
        rel=d.relations[0].model_copy(deep=True);rel.id='second';rel.source_resource_id='two';d.relations.append(rel)
        if mode=='conditional':rel.condition='Maybe'
        if mode=='different_parent':rel.target_resource_id='parent2'
        if mode=='literal_parent':d.relations.clear()
    if mode=='other_account':other.scope.account='222222222222'
    if mode=='other_region':other.scope.region='us-east-1'
    if mode=='unknown_scope':r.scope.region=other.scope.region='unknown'
    return d,r


@pytest.mark.parametrize('kind',list(SPECS))
@pytest.mark.parametrize('mode',['same','different','unknown','missing','other_account','other_region','unknown_scope'])
def test_proven_duplicate_or_hold(kind,mode):
    d,r=setup(kind,mode);row=evaluate_multi_service_duplicate_names(d,r)[0]
    assert row['verdict']==('FAIL' if mode=='same' else 'NEEDS_REVIEW')
    assert row['rule_id']==SPECS[kind]['rule_id']


@pytest.mark.parametrize('kind',[k for k,s in SPECS.items() if s['parent']])
@pytest.mark.parametrize('mode',['conditional','different_parent','literal_parent'])
def test_parent_identity(kind,mode):
    d,r=setup(kind,mode)
    assert evaluate_multi_service_duplicate_names(d,r)[0]['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('kind',['AWS::BedrockAgentCore::Dataset','AWS::SageMaker::TrialComponent'])
def test_documented_case_insensitivity(kind):
    key=SPECS[kind]['paths'][0];r=target('one',kind,**{key:'Example'});other=target('two',kind,**{key:'example'})
    assert evaluate_multi_service_duplicate_names(linked_design(r,[other]),r)[0]['verdict']=='FAIL'


def test_composite_version_distinguishes_models():
    kind='AWS::Comprehend::DocumentClassifier'
    r=target('one',kind,DocumentClassifierName='same',VersionName='one');other=target('two',kind,DocumentClassifierName='same',VersionName='two')
    assert evaluate_multi_service_duplicate_names(linked_design(r,[other]),r)[0]['verdict']=='NEEDS_REVIEW'


def test_checker_evidence():
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1];d,r=setup('AWS::Athena::DataCatalog','same')
    row=next(x for x in Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results'] if x['rule_id']==SPECS[r.type]['rule_id'])
    assert row['verdict']=='FAIL' and row['source_urls'] and row['evidence_ids']
