import pytest
from aws_design_sheet.checks.dms.subnet_group_zones import evaluate_dms_subnet_group_zones
from aws_design_sheet.checks.dsql.witness_region import evaluate_dsql_witness_region
from aws_design_sheet.checks.databrew.metadata_service import evaluate_databrew_metadata_service
from aws_design_sheet.checks.cognito.log_group_account_encryption import evaluate_cognito_log_group_account_encryption
from aws_design_sheet.checks.registry import combine
data_regions_checks = combine(evaluate_dms_subnet_group_zones, evaluate_dsql_witness_region, evaluate_databrew_metadata_service, evaluate_cognito_log_group_account_encryption)
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN
from test_template_dependencies import link


@pytest.mark.parametrize('case,want', [('plain','PASS'),('cross_account','FAIL'),('cross_region','PASS'),('kms_ref','FAIL'),('conditional_key','NEEDS_REVIEW'),('conditional_literal_key','NEEDS_REVIEW'),('unknown_key','NEEDS_REVIEW'),('raw_pool','NEEDS_REVIEW'),('raw_group','NEEDS_REVIEW'),('conditional_group','NEEDS_REVIEW'),('unknown_group_scope','NEEDS_REVIEW')])
def test_log_identity_and_encryption(case,want):
    config={} if case!='raw_group' else {'LogGroupArn':'different'}
    r=target('delivery','AWS::Cognito::LogDeliveryConfiguration',LogConfigurations=[{'CloudWatchLogsConfiguration':config}],**({'UserPoolId':'different'} if case=='raw_pool' else {}))
    pool=target('pool','AWS::Cognito::UserPool')
    group=target('group','AWS::Logs::LogGroup',**({'KmsKeyId':UNKNOWN} if case=='unknown_key' else {'KmsKeyId':'arn:aws:kms:ap-northeast-1:111111111111:key/abc'} if case=='conditional_literal_key' else {}))
    key=target('key','AWS::KMS::Key')
    if case=='cross_account':group.scope.account='222222222222'
    if case=='cross_region':group.scope.region='us-east-1'
    if case=='unknown_group_scope':group.scope.account='unknown'
    d=linked_design(r,[pool,group,key]);link(d,r,'UserPoolId',pool);link(d,r,'LogConfigurations/0/CloudWatchLogsConfiguration/LogGroupArn',group,'maybe' if case=='conditional_group' else None)
    if case in ('kms_ref','conditional_key','conditional_literal_key'):link(d,group,'KmsKeyId',key,'maybe' if case in ('conditional_key','conditional_literal_key') else None)
    assert data_regions_checks(d,r)[0]['verdict']==want


@pytest.mark.parametrize('raw', [UNKNOWN,'bad',[UNKNOWN]])
def test_unresolved_log_configurations(raw):
    r=target('delivery','AWS::Cognito::LogDeliveryConfiguration',LogConfigurations=raw)
    findings=data_regions_checks(linked_design(r),r)
    assert findings and all(f['verdict']=='NEEDS_REVIEW' for f in findings)
