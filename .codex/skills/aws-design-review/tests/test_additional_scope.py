import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('kind',['Key','ReplicaKey'])
@pytest.mark.parametrize('change,expected',[('none','PASS'),('region','NEEDS_REVIEW'),('condition','NEEDS_REVIEW'),('unknown','NEEDS_REVIEW')])
def test_alias_key_and_replica(kind,change,expected):
    main=target('alias','AWS::KMS::Alias',TargetKeyId={'Ref':'key'})
    key=target('key','AWS::KMS::'+kind)
    if change=='region':key.scope.region='us-west-2'
    if change=='unknown':main.scope.account=key.scope.account='unknown'
    data=linked_design(main,[key],[('TargetKeyId','key')])
    if change=='condition':data.relations[0].condition='optional'
    assert next(r['verdict'] for r in run_resource_checks(data,main) if r['rule_id']=='KMS_ALIAS_TARGET_SCOPE')==expected


@pytest.mark.parametrize('arn,expected',[
    ('arn:aws:logs:us-east-1:111111111111:log-group:/aws/route53/example','PASS'),
    ('arn:aws:logs:us-east-1:222222222222:log-group:/aws/route53/example','FAIL'),
    ('group','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_route53_query_log_account(arn,expected):
    main=target('zone','AWS::Route53::HostedZone',QueryLoggingConfig={'CloudWatchLogsLogGroupArn':arn})
    assert next(r['verdict'] for r in run_resource_checks(linked_design(main),main) if r['rule_id']=='ROUTE53_QUERY_LOG_ACCOUNT')==expected


def test_route53_linked_log_group():
    main=target('zone','AWS::Route53::HostedZone',QueryLoggingConfig={'CloudWatchLogsLogGroupArn':{'Ref':'log'}})
    log=target('log','AWS::Logs::LogGroup')
    data=linked_design(main,[log],[('QueryLoggingConfig/CloudWatchLogsLogGroupArn','log')])
    assert next(r['verdict'] for r in run_resource_checks(data,main) if r['rule_id']=='ROUTE53_QUERY_LOG_ACCOUNT')=='PASS'
