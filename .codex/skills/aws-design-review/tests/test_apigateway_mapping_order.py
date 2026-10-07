import pytest
from aws_design_sheet.models import TemplateContext, Relation
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design


def template(resource,depends,identifier='stack'):
    resource.template=TemplateContext(id=identifier,depends_on=depends,evidence_ids=['e1'])
    return resource


@pytest.mark.parametrize('dependencies,stage_stack,expected',[
    (['stage'],'stack','PASS'),([],'stack','FAIL'),(None,'stack','NEEDS_REVIEW'),
    (['unknown'],'stack','NEEDS_REVIEW'),(['stage'],'other','NEEDS_REVIEW'),
])
def test_literal_stage_order(dependencies,stage_stack,expected):
    main=template(target('mapping','AWS::ApiGateway::BasePathMappingV2',Stage='prod',RestApiId='api123'),dependencies)
    stage=template(target('stage','AWS::ApiGateway::Stage',StageName='prod',RestApiId='api123'),[],stage_stack)
    rows=run_resource_checks(linked_design(main,[stage]),main)
    assert rows[0]['verdict']==expected


@pytest.mark.parametrize('conditional,expected',[(False,'PASS'),(True,'NEEDS_REVIEW')])
def test_explicit_stage_reference_order(conditional,expected):
    main=template(target('mapping','AWS::ApiGateway::BasePathMappingV2',Stage={'Ref':'stage'}),[])
    stage=template(target('stage','AWS::ApiGateway::Stage'),[])
    data=linked_design(main,[stage],[('Stage','stage')])
    if conditional:data.relations[0].condition='optional'
    assert run_resource_checks(data,main)[0]['verdict']==expected


def test_transitive_order_and_cycle():
    main=template(target('mapping','AWS::ApiGateway::BasePathMappingV2',Stage='prod',RestApiId='api123'),['bridge'])
    stage=template(target('stage','AWS::ApiGateway::Stage',StageName='prod',RestApiId='api123'),[])
    bridge=template(target('bridge','AWS::SNS::Topic'),['stage'])
    data=linked_design(main,[stage,bridge])
    assert run_resource_checks(data,main)[0]['verdict']=='PASS'
    stage.template.depends_on=['mapping']
    assert run_resource_checks(data,main)[0]['verdict']=='FAIL'


@pytest.mark.parametrize('change',['other-api','no-template','duplicate-stage'])
def test_stage_identity_uncertainty(change):
    main=template(target('mapping','AWS::ApiGateway::BasePathMappingV2',Stage='prod',RestApiId='api123'),[])
    stage=template(target('stage','AWS::ApiGateway::Stage',StageName='prod',RestApiId='different' if change=='other-api' else 'api123'),[])
    data=linked_design(main,[stage])
    if change=='no-template':stage.template=None
    if change=='duplicate-stage':data.resources.append(template(target('stage2','AWS::ApiGateway::Stage',StageName='prod',RestApiId='api123'),[]))
    assert run_resource_checks(data,main)[0]['verdict']=='NEEDS_REVIEW'
