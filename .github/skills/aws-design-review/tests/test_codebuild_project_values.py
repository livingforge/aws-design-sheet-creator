import pytest
from aws_design_sheet.checks.codebuild.project_values import evaluate_codebuild_project_values, ENUMS
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


def resource_for(path, raw):
    parts = path.split('/')
    obj = raw
    for part in reversed(parts):
        obj = [obj] if part == '*' else {part: obj}
    return target('build', 'AWS::CodeBuild::Project', **obj)


@pytest.mark.parametrize('path,raw', [(path, raw) for path, values in ENUMS.items() for raw in values])
def test_current_enum_members(path, raw):
    r = resource_for(path, raw)
    assert evaluate_codebuild_project_values(linked_design(r), r)[0]['verdict'] == 'PASS'


@pytest.mark.parametrize('path', list(ENUMS))
@pytest.mark.parametrize('raw,want', [('invalid','FAIL'), ('','NEEDS_REVIEW'), (UNKNOWN,'NEEDS_REVIEW')])
def test_invalid_and_unresolved_enums(path, raw, want):
    r = resource_for(path, raw)
    assert evaluate_codebuild_project_values(linked_design(r), r)[0]['verdict'] == want


@pytest.mark.parametrize('raw,want', [('ab','PASS'), ('A'*150,'PASS'), ('A'*151,'FAIL'), ('a','FAIL'), ('_ab','FAIL'), ('a-b_c9','PASS'), ('日本語','FAIL'), ('ab\n','FAIL'), ('','NEEDS_REVIEW'), (UNKNOWN,'NEEDS_REVIEW')])
def test_name_boundaries(raw, want):
    r = resource_for('Name', raw)
    assert evaluate_codebuild_project_values(linked_design(r), r)[0]['verdict'] == want


@pytest.mark.parametrize('raw', [UNKNOWN, 'bad-container', [UNKNOWN]])
def test_unknown_or_malformed_secondary_ancestor(raw):
    r = resource_for('SecondarySources', raw)
    findings = evaluate_codebuild_project_values(linked_design(r), r)
    assert findings and all(f['verdict'] == 'NEEDS_REVIEW' for f in findings)


@pytest.mark.parametrize('fleet', [{'FleetArn':'arn'}, UNKNOWN, {}])
def test_fleet_type_creation_context(fleet):
    r = target('build','AWS::CodeBuild::Project',Environment={'Type':'invalid','Fleet':fleet})
    assert evaluate_codebuild_project_values(linked_design(r), r)[0]['verdict'] == 'NEEDS_REVIEW'


def test_omitted_fields():
    r = target('build','AWS::CodeBuild::Project')
    assert evaluate_codebuild_project_values(linked_design(r), r) == []


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    r = resource_for('Environment/ComputeType', 'CUSTOM_INSTANCE_TYPE')
    root = Path(__file__).resolve().parents[1]
    results = Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    assert any(f['rule_id']=='CODEBUILD_PROJECT_ENUMS' and f['verdict']=='PASS' for f in results)
