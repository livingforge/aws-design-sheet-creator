import pytest
from aws_design_sheet.checks.connect.templates import evaluate_connect_templates
from aws_design_sheet.checks.codepipeline.template_config_reference import evaluate_codepipeline_template_config_reference
from aws_design_sheet.checks.registry import combine
connect_templates_checks = combine(evaluate_connect_templates, evaluate_codepipeline_template_config_reference)
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('field',['EntityUrlTemplate','ExecutionUrlTemplate'])
@pytest.mark.parametrize('props,want', [(None,'FAIL'),([],'FAIL'),([{'Name':'Other','Required':True,'Secret':False}],'FAIL'),([{'Name':UNKNOWN}],'NEEDS_REVIEW'),([{'Name':'Project','Required':True,'Secret':False}],'PASS')])
def test_declared_property_reference(field,props,want):
    r=target('action','AWS::CodePipeline::CustomActionType',Settings={field:'https://example.test/{Config:Project}'},**({} if props is None else {'ConfigurationProperties':props}))
    assert connect_templates_checks(linked_design(r),r)[0]['verdict']==want


def test_service_added_joblist_not_assumed_required():
    r=target('action','AWS::CodePipeline::CustomActionType',Settings={'EntityUrlTemplate':'https://example.test/{Config:JobList}'},ConfigurationProperties=[])
    assert connect_templates_checks(linked_design(r),r)[0]['verdict']=='NEEDS_REVIEW'


def test_multiple_references_one_secret():
    r=target('action','AWS::CodePipeline::CustomActionType',Settings={'ExecutionUrlTemplate':'https://example.test/{Config:Project}/{Config:Token}'},ConfigurationProperties=[{'Name':'Project','Required':True,'Secret':False},{'Name':'Token','Required':True,'Secret':True}])
    assert connect_templates_checks(linked_design(r),r)[0]['verdict']=='FAIL'
