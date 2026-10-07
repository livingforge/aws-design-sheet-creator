import pytest
from aws_design_sheet.checks.dax.notification_owner import evaluate_dax_notification_owner
from aws_design_sheet.checks.dlm.default_public_values import evaluate_dlm_default_public_values
from aws_design_sheet.checks.dms.migration_limits import evaluate_dms_migration_limits
from aws_design_sheet.checks.codepipeline.custom_public_values import evaluate_codepipeline_custom_public_values
from aws_design_sheet.checks.arczonalshift.autoshift_resource_type import evaluate_arczonalshift_autoshift_resource_type
from aws_design_sheet.checks.registry import combine
migration_limits_checks = combine(evaluate_dax_notification_owner, evaluate_dlm_default_public_values, evaluate_dms_migration_limits, evaluate_codepipeline_custom_public_values, evaluate_arczonalshift_autoshift_resource_type)
from aws_design_sheet.checks.amplifyuibuilder.navigation_type import evaluate_amplifyuibuilder_navigation_type
from aws_design_sheet.checks.appstream.associations import evaluate_appstream_associations
from aws_design_sheet.checks.apprunner.security_group_vpc import evaluate_apprunner_security_group_vpc
from aws_design_sheet.checks.registry import combine
app_associations_checks = combine(evaluate_amplifyuibuilder_navigation_type, evaluate_appstream_associations, evaluate_apprunner_security_group_vpc)
from test_autoscaling_group_and_scaling_policy import target,linked_design
from test_template_dependencies import template,link
from aws_design_sheet.checks.autoscalingplans.enums import evaluate_autoscalingplans_enums


@pytest.mark.parametrize('key',['Provider','Version','Category'])
def test_custom_empty_string_is_invalid(key):
    r=target('custom','AWS::CodePipeline::CustomActionType',**{key:''})
    assert migration_limits_checks(linked_design(r),r)[0]['verdict']=='FAIL'


@pytest.mark.parametrize('category',['Source','Build','Deploy','Test','Invoke','Approval','Compute'])
def test_all_custom_categories(category):
    r=target('custom','AWS::CodePipeline::CustomActionType',Category=category)
    assert migration_limits_checks(linked_design(r),r)[0]['verdict']=='PASS'


@pytest.mark.parametrize('case,want',[('matching','PASS'),('wrong_name','NEEDS_REVIEW'),('cycle','FAIL'),('self_name_collision','NEEDS_REVIEW')])
def test_appstream_target_identity_and_order(case,want):
    r=template(target('assoc','AWS::AppStream::StackFleetAssociation',FleetName='fleet',StackName='stack'),[])
    f=template(target('fleet','AWS::AppStream::Fleet',Name='fleet'),[])
    s=template(target('stack','AWS::AppStream::Stack',Name='stack'),[])
    d=linked_design(r,[f,s]);link(d,r,'FleetName',f);link(d,r,'StackName',s)
    if case=='wrong_name':f.fields[0].candidates[0].value='other'
    if case=='cycle':f.template.depends_on=['assoc']
    if case=='self_name_collision':f.fields[0].candidates[0].value={'$state':'UNRESOLVED'}
    results=app_associations_checks(d,r)
    assert next(x['verdict'] for x in results if x['rule_id']=='APPSTREAM_STACK_FLEET_ORDER')==want


@pytest.mark.parametrize('kind,stat,want',[
    ('load','Sum','PASS'),('load','Average','FAIL'),('load','','FAIL'),
    ('scaling','Average','PASS'),('scaling','Minimum','PASS'),('scaling','Maximum','PASS'),
    ('scaling','SampleCount','PASS'),('scaling','Sum','PASS'),('scaling','p99','FAIL'),
    ('scaling',{'$state':'UNRESOLVED'},'NEEDS_REVIEW')])
def test_custom_metric_statistics(kind,stat,want):
    entry={'CustomizedLoadMetricSpecification':{'Statistic':stat}} if kind=='load' else {'TargetTrackingConfigurations':[{'CustomizedScalingMetricSpecification':{'Statistic':stat}}]}
    r=target('plan','AWS::AutoScalingPlans::ScalingPlan',ScalingInstructions=[entry])
    assert evaluate_autoscalingplans_enums(linked_design(r),r)[0]['verdict']==want


def test_malformed_scaling_ancestor_is_not_an_enum_value():
    r=target('plan','AWS::AutoScalingPlans::ScalingPlan',ScalingInstructions='Sum')
    assert all(f['verdict']=='NEEDS_REVIEW' for f in evaluate_autoscalingplans_enums(linked_design(r),r))
