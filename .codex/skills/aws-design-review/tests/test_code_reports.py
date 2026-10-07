from pathlib import Path
import pytest
from aws_design_sheet.checks.codebuild.report_values import evaluate_codebuild_report_values
from aws_design_sheet.checks.codecommit.trigger_all_events import evaluate_codecommit_trigger_all_events
from aws_design_sheet.checks.registry import combine
code_reports_checks = combine(evaluate_codebuild_report_values, evaluate_codecommit_trigger_all_events)
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('path,good', [('Type','TEST'), ('Type','CODE_COVERAGE'), ('ExportConfig/ExportConfigType','S3'), ('ExportConfig/ExportConfigType','NO_EXPORT'), ('ExportConfig/S3Destination/Packaging','ZIP'), ('ExportConfig/S3Destination/Packaging','NONE')])
@pytest.mark.parametrize('mode', ['valid','invalid','unknown','intrinsic'])
def test_report_enum(path, good, mode):
    props = {}; node = props
    parts = path.split('/')
    for part in parts[:-1]:
        node[part] = {}; node = node[part]
    node[parts[-1]] = good if mode == 'valid' else 'INVALID' if mode == 'invalid' else UNKNOWN if mode == 'unknown' else '${Parameter}'
    r = target('main','AWS::CodeBuild::ReportGroup',**props)
    f = code_reports_checks(linked_design(r),r)
    assert len(f) == 1
    assert f[0]['verdict'] == ('PASS' if mode == 'valid' else 'FAIL' if mode == 'invalid' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('events,expected', [(['all'],'PASS'), (['all','all'],'PASS'), (['updateReference']*8+['all'],'FAIL'), (['all']+['createReference']*8,'FAIL'), (['updateReference']*8,'PASS'), (['all',UNKNOWN],'NEEDS_REVIEW'), (['all',UNKNOWN,'createReference'],'FAIL'), (UNKNOWN,'NEEDS_REVIEW'), ([], 'PASS')])
def test_all_events(events, expected):
    r=target('main','AWS::CodeCommit::Repository',Triggers=[{'Events':events}])
    assert code_reports_checks(linked_design(r),r)[0]['verdict'] == expected


@pytest.mark.parametrize('props', [{}, {'ExportConfig':{}}, {'ExportConfig':{'S3Destination':{}}}])
def test_absent_optional(props):
    r=target('main','AWS::CodeBuild::ReportGroup',**props)
    assert code_reports_checks(linked_design(r),r) == []


def test_checker_integration():
    r=target('main','AWS::CodeCommit::Repository',RepositoryName='repo',Triggers=[{'Name':'trigger','DestinationArn':'arn:aws:sns:ap-northeast-1:111111111111:topic','Branches':[],'Events':['updateReference']*8+['all']}])
    root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    assert any(f['rule_id']=='CODECOMMIT_TRIGGER_ALL_EVENTS' and f['verdict']=='FAIL' for f in results)
