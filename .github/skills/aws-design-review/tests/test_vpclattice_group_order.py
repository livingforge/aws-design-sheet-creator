import pytest
from aws_design_sheet.checks.vpclattice.group_order import evaluate_vpclattice_group_order
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_template_dependencies import template,link


def fixture():
    r=template(target('child','AWS::VpcLattice::ResourceConfiguration',ResourceConfigurationType='CHILD'),[])
    g=template(target('group',r.type,ResourceConfigurationType='GROUP'),[])
    d=linked_design(r,[g]);link(d,r,'ResourceConfigurationGroupId',g)
    return d,r,g


@pytest.mark.parametrize('case,want',[('valid','PASS'),('wrong_kind','FAIL'),('unknown_kind','NEEDS_REVIEW'),('cycle','FAIL'),('external','NEEDS_REVIEW'),('other_stack','NEEDS_REVIEW'),('no_template','NEEDS_REVIEW'),('conditional','NEEDS_REVIEW'),('literal','NEEDS_REVIEW'),('not_child','NOT_APPLICABLE')])
def test_parent_order(case,want):
    d,r,g=fixture()
    if case=='wrong_kind':g.fields[0].candidates[0].value='SINGLE'
    if case=='unknown_kind':g.fields[0].candidates[0].value=UNKNOWN
    if case=='cycle':g.template.depends_on=['child']
    if case=='external':d.resources.remove(g)
    if case=='other_stack':g.template.id='other'
    if case=='no_template':r.template=None
    if case=='conditional':d.relations[0].condition='Maybe'
    if case=='literal':r.fields.append(target('x',r.type,ResourceConfigurationGroupId='rcfg-12345678901234567').fields[0])
    if case=='not_child':r.fields[0].candidates[0].value='SINGLE'
    assert evaluate_vpclattice_group_order(d,r)[0]['verdict']==want


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    d,r,g=fixture();root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results']
    assert any(f['rule_id']=='LATTICE_CHILD_GROUP_ORDER' and f['verdict']=='PASS' for f in results)
