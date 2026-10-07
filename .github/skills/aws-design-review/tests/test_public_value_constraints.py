from pathlib import Path

import pytest

from aws_design_sheet.checker import Checker
from aws_design_sheet.checks.apprunner.service import evaluate_apprunner_service
from aws_design_sheet.checks.appstream.public_limits import evaluate_appstream_public_limits
from aws_design_sheet.checks.appsync.api_name_public_pattern import evaluate_appsync_api_name_public_pattern
from aws_design_sheet.checks.applicationautoscaling.namespace_values import evaluate_applicationautoscaling_namespace_values
from aws_design_sheet.checks.backup.airgapped_target_scope import evaluate_backup_airgapped_target_scope
from aws_design_sheet.checks.batch.service_environment_values import evaluate_batch_service_environment_values
from aws_design_sheet.checks.registry import combine
ordered_values_checks = combine(evaluate_apprunner_service, evaluate_appstream_public_limits, evaluate_appsync_api_name_public_pattern, evaluate_applicationautoscaling_namespace_values, evaluate_backup_airgapped_target_scope, evaluate_batch_service_environment_values)
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


def check(kind, props, rule, design_change=None):
    resource = target('ordered', 'AWS::'+kind, **props)
    design = linked_design(resource)
    if design_change: design_change(design)
    return [r for r in ordered_values_checks(design, resource) if r['rule_id'] == rule]


@pytest.mark.parametrize('url,expected', [('https://github.com/org/repo','FAIL'),('https://GITHUB.com/org/repo','FAIL'),('https://github.com.evil/org/repo','NEEDS_REVIEW'),('https://github.com@evil/org/repo','NEEDS_REVIEW'),('https://github.com:invalid/org/repo','NEEDS_REVIEW'),('https://github.com/','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW'),('https://gitlab.com/org/repo','NEEDS_REVIEW')])
def test_github_provider(url,expected):
    assert check('AppRunner::Service',{'SourceConfiguration':{'CodeRepository':{'RepositoryUrl':url}}},'APPRUNNER_GITHUB_CONNECTION')[0]['verdict'] == expected


@pytest.mark.parametrize('connection,expected', [('arn:aws:apprunner:us-east-1:111111111111:connection/test/1','PASS'),(UNKNOWN,'NEEDS_REVIEW'),('', 'NEEDS_REVIEW')])
def test_github_connection(connection,expected):
    props={'SourceConfiguration':{'CodeRepository':{'RepositoryUrl':'https://github.com/org/repo'},'AuthenticationConfiguration':{'ConnectionArn':connection}}}
    assert check('AppRunner::Service',props,'APPRUNNER_GITHUB_CONNECTION')[0]['verdict'] == expected


@pytest.mark.parametrize('enabled',[True,False,UNKNOWN])
@pytest.mark.parametrize('arn,expected',[(None,'FAIL'),('arn:aws:apprunner:r:111111111111:observabilityconfiguration/test','PASS'),(UNKNOWN,'NEEDS_REVIEW')])
def test_observability(enabled,arn,expected):
    props={'ObservabilityEnabled':enabled}
    if arn is not None: props['ObservabilityConfigurationArn']=arn
    assert check('AppRunner::Service',{'ObservabilityConfiguration':props},'APPRUNNER_OBSERVABILITY_REQUIRED')[0]['verdict'] == (expected if enabled is True else 'NEEDS_REVIEW')


@pytest.mark.parametrize('platform,expected',[('WINDOWS_SERVER_2019','PASS'),('AMAZON_LINUX2','FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_builder_platform(platform,expected):
    assert check('AppStream::AppBlockBuilder',{'Platform':platform},'APPSTREAM_BUILDER_PUBLIC_LIMITS')[0]['verdict'] == expected


@pytest.mark.parametrize('count,expected',[(0,'PASS'),(1,'PASS'),(2,'FAIL')])
def test_builder_count(count,expected):
    assert check('AppStream::AppBlockBuilder',{'AppBlockArns':[UNKNOWN]*count},'APPSTREAM_BUILDER_PUBLIC_LIMITS')[0]['verdict'] == expected


@pytest.mark.parametrize('key,good,bad',[('InstanceFamilies','GENERAL_PURPOSE','COMPUTE'),('Platforms','AMAZON_LINUX2','WINDOWS_SERVER_2022')])
@pytest.mark.parametrize('mode',['good','bad','unknown','ancestor'])
def test_application_members(key,good,bad,mode):
    raw={'good':[good],'bad':[bad],'unknown':[UNKNOWN],'ancestor':UNKNOWN}[mode]
    result=check('AppStream::Application',{key:raw},'APPSTREAM_APPLICATION_PUBLIC_LIMITS')
    assert result[0]['verdict'] == {'good':'PASS','bad':'FAIL','unknown':'NEEDS_REVIEW','ancestor':'NEEDS_REVIEW'}[mode]


@pytest.mark.parametrize('count,expected',[(4,'PASS'),(5,'FAIL')])
def test_application_platform_count(count,expected):
    assert check('AppStream::Application',{'Platforms':['AMAZON_LINUX2']*count},'APPSTREAM_APPLICATION_PUBLIC_LIMITS')[-1]['verdict'] == expected


@pytest.mark.parametrize('fleet',['ELASTIC','ALWAYS_ON',UNKNOWN])
@pytest.mark.parametrize('platform,expected',[('WINDOWS_SERVER_2025','PASS'),('invalid','FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_fleet_applicability(fleet,platform,expected):
    result=check('AppStream::Fleet',{'FleetType':fleet,'Platform':platform},'APPSTREAM_FLEET_PUBLIC_VALUES')
    if fleet == 'ELASTIC': assert result[0]['verdict'] == expected
    else: assert not result


@pytest.mark.parametrize('view,expected',[('APP','PASS'),('DESKTOP','PASS'),('OTHER','FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_stream_view(view,expected):
    assert check('AppStream::Fleet',{'StreamView':view},'APPSTREAM_FLEET_PUBLIC_VALUES')[0]['verdict'] == expected


@pytest.mark.parametrize('name,expected',[('_api12','PASS'),('api-name','FAIL'),('1name','FAIL'),('abc\n','FAIL'),('a'*65536,'PASS'),('a'*65537,'FAIL'),(UNKNOWN,'NEEDS_REVIEW')],ids=['valid','hyphen','digit','newline','max','over','unknown'])
def test_api_name(name,expected):
    assert check('AppSync::GraphQLApi',{'Name':name},'APPSYNC_API_NAME_PUBLIC_PATTERN')[0]['verdict'] == expected


@pytest.mark.parametrize('kind,rule',[('ScalableTarget','APP_AUTOSCALING_TARGET_NAMESPACE'),('ScalingPolicy','APP_AUTOSCALING_POLICY_NAMESPACE')])
@pytest.mark.parametrize('ns,dimension,expected',[('ecs','ecs:service:DesiredCount','PASS'),('ecs','appstream:fleet:DesiredCapacity','FAIL'),(UNKNOWN,'ecs:service:DesiredCount','NEEDS_REVIEW'),('ecs',UNKNOWN,'NEEDS_REVIEW'),('ecs','ecs:invalid','NEEDS_REVIEW'),('custom-resource','custom-resource:ResourceType:Property','PASS')])
def test_namespace_consistency(kind,rule,ns,dimension,expected):
    assert check('ApplicationAutoScaling::'+kind,{'ServiceNamespace':ns,'ScalableDimension':dimension},rule)[0]['verdict'] == expected


@pytest.mark.parametrize('ns,expected',[('ecs','PASS'),('workspaces','PASS'),('custom-resource','PASS'),('invalid','FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_namespace_values(ns,expected):
    assert check('ApplicationAutoScaling::ScalableTarget',{'ServiceNamespace':ns},'APP_AUTOSCALING_NAMESPACE_VALUES')[0]['verdict'] == expected


@pytest.mark.parametrize('raw,expected',[(2**360,'PASS'),(-(2**360),'PASS'),(2**360+1,'FAIL'),(-(2**360)-1,'FAIL'),(False,'NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW'),(1.1,'PASS')])
def test_target_value(raw,expected):
    assert check('ApplicationAutoScaling::ScalingPolicy',{'TargetTrackingScalingPolicyConfiguration':{'TargetValue':raw}},'APP_AUTOSCALING_TARGET_VALUE_RANGE')[0]['verdict'] == expected


@pytest.mark.parametrize('region,account,expected',[('ap-northeast-1','111111111111','PASS'),('us-east-1','111111111111','FAIL'),('ap-northeast-1','222222222222','FAIL')])
def test_vault_scope(region,account,expected):
    props={'BackupPlan':{'BackupPlanRule':[{'TargetLogicallyAirGappedBackupVaultArn':f'arn:aws:backup:{region}:{account}:backup-vault:test'}]}}
    assert check('Backup::BackupPlan',props,'BACKUP_AIRGAPPED_TARGET_SCOPE')[0]['verdict'] == expected


@pytest.mark.parametrize('raw',[UNKNOWN,'${VaultArn}','arn:invalid'])
def test_vault_unknown(raw):
    assert check('Backup::BackupPlan',{'BackupPlan':{'BackupPlanRule':[{'TargetLogicallyAirGappedBackupVaultArn':raw}]}},'BACKUP_AIRGAPPED_TARGET_SCOPE')[0]['verdict'] == 'NEEDS_REVIEW'


@pytest.mark.parametrize('kind,unit,expected',[('SAGEMAKER_TRAINING','NUM_INSTANCES','PASS'),('SAGEMAKER_TRAINING','VCPU','FAIL'),('SAGEMAKER_TRAINING',UNKNOWN,'NEEDS_REVIEW')])
def test_capacity_unit(kind,unit,expected):
    assert check('Batch::ServiceEnvironment',{'ServiceEnvironmentType':kind,'CapacityLimits':[{'CapacityUnit':unit}]},'BATCH_SERVICE_ENVIRONMENT_VALUES')[-1]['verdict'] == expected


def test_relation_prevents_scalar_presence_pass():
    def change(design):
        from aws_design_sheet.models import Relation
        design.relations.append(Relation(id='r',source_resource_id='ordered',source_path='/properties/ObservabilityConfiguration/ObservabilityConfigurationArn',target_resource_id='external',evidence_ids=['e1']))
    result=check('AppRunner::Service',{'ObservabilityConfiguration':{'ObservabilityEnabled':True}},'APPRUNNER_OBSERVABILITY_REQUIRED',change)
    assert result[0]['verdict'] == 'NEEDS_REVIEW'


def test_checker_integration():
    resource=target('ordered','AWS::AppRunner::Service',SourceConfiguration={'CodeRepository':{'RepositoryUrl':'https://github.com/org/repo'}})
    root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(resource))['results']
    result=next(r for r in results if r['rule_id']=='APPRUNNER_GITHUB_CONNECTION')
    assert result['verdict']=='FAIL'
    assert result['source_urls']
