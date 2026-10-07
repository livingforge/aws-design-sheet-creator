import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('kind',['DATA_PROTECTION_POLICY','SUBSCRIPTION_FILTER_POLICY'])
@pytest.mark.parametrize('other_name,other_region,expected',[
    ('second','ap-northeast-1','FAIL'),('first','ap-northeast-1','NEEDS_REVIEW'),
    ('second','us-west-2','NEEDS_REVIEW'),(UNKNOWN,'ap-northeast-1','NEEDS_REVIEW'),
])
def test_distinct_singleton_policy_names(kind,other_name,other_region,expected):
    main=target('first','AWS::Logs::AccountPolicy',PolicyType=kind,PolicyName='first')
    other=target('second',main.type,PolicyType=kind,PolicyName=other_name)
    other.scope.region=other_region
    assert run_resource_checks(linked_design(main,[other]),main)[0]['verdict']==expected


@pytest.mark.parametrize('kind',['TRANSFORMER_POLICY','FIELD_INDEX_POLICY'])
@pytest.mark.parametrize('first,second,expected',[
    ('LogGroupNamePrefix="/aws/app"','LogGroupNamePrefix = "/aws/app-prod"','FAIL'),
    ('LogGroupNamePrefix="/aws/app"','LogGroupNamePrefix="/aws/api"','NEEDS_REVIEW'),
    ('LogGroupNamePrefix="/aws/app"',UNKNOWN,'NEEDS_REVIEW'),
    (None,'LogGroupNamePrefix="/aws/app"','FAIL'),
    ('LogGroupNamePrefix IN ["/aws/app"]','LogGroupNamePrefix="/aws/app"','NEEDS_REVIEW'),
])
def test_policy_prefix_overlap(kind,first,second,expected):
    main=target('first','AWS::Logs::AccountPolicy',PolicyType=kind,PolicyName='first',**({'SelectionCriteria':first} if first is not None else {}))
    other=target('second',main.type,PolicyType=kind,PolicyName='second',SelectionCriteria=second)
    assert run_resource_checks(linked_design(main,[other]),main)[0]['verdict']==expected


def test_unresolved_scope_does_not_prove_policy_collision():
    main=target('first','AWS::Logs::AccountPolicy',PolicyType='DATA_PROTECTION_POLICY',PolicyName='first')
    other=target('second',main.type,PolicyType='DATA_PROTECTION_POLICY',PolicyName='second')
    main.scope.account=other.scope.account='unknown'
    assert run_resource_checks(linked_design(main,[other]),main)[0]['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('kind',['TRANSFORMER_POLICY','FIELD_INDEX_POLICY'])
@pytest.mark.parametrize('count,expected',[(20,'NEEDS_REVIEW'),(21,'FAIL')])
def test_scoped_policy_count(kind,count,expected):
    policies=[target(str(i),'AWS::Logs::AccountPolicy',PolicyType=kind,PolicyName='policy-'+str(i),SelectionCriteria='LogGroupNamePrefix="/app/'+str(i)+'/"') for i in range(count)]
    rows={r['rule_id']:r['verdict'] for r in run_resource_checks(linked_design(policies[0],policies[1:]),policies[0])}
    assert rows['LOGS_ACCOUNT_POLICY_SCOPED_COUNT']==expected


def test_field_index_data_source_scopes_do_not_consume_prefix_quota():
    main=target('prefix','AWS::Logs::AccountPolicy',PolicyType='FIELD_INDEX_POLICY',PolicyName='prefix',SelectionCriteria='LogGroupNamePrefix="/app/"')
    policies=[target(str(i),main.type,PolicyType='FIELD_INDEX_POLICY',PolicyName='data-'+str(i),SelectionCriteria='DataSourceName="source-'+str(i)+'" AND DataSourceType="flow"') for i in range(20)]
    rows={r['rule_id']:r['verdict'] for r in run_resource_checks(linked_design(main,policies),main)}
    assert rows['LOGS_ACCOUNT_POLICY_SCOPED_COUNT']=='NEEDS_REVIEW'


@pytest.mark.parametrize('other,expected',[
    ('DataSourceType="flow" AND DataSourceName="amazon_vpc"','FAIL'),
    ('DataSourceName="amazon_vpc" AND DataSourceType="audit"','NEEDS_REVIEW'),
    ('DataSourceName="amazon_vpc"','NEEDS_REVIEW'),
])
def test_data_source_pair_collision(other,expected):
    main=target('first','AWS::Logs::AccountPolicy',PolicyType='FIELD_INDEX_POLICY',PolicyName='first',SelectionCriteria='DataSourceName="amazon_vpc" AND DataSourceType="flow"')
    second=target('second',main.type,PolicyType='FIELD_INDEX_POLICY',PolicyName='second',SelectionCriteria=other)
    rows={r['rule_id']:r['verdict'] for r in run_resource_checks(linked_design(main,[second]),main)}
    assert rows['LOGS_ACCOUNT_POLICY_DATASOURCE_COLLISION']==expected


def test_data_source_quota_is_separate():
    policies=[target(str(i),'AWS::Logs::AccountPolicy',PolicyType='FIELD_INDEX_POLICY',PolicyName='data-'+str(i),SelectionCriteria='DataSourceName="source-'+str(i)+'" AND DataSourceType="flow"') for i in range(21)]
    rows={r['rule_id']:r['verdict'] for r in run_resource_checks(linked_design(policies[0],policies[1:]),policies[0])}
    assert rows['LOGS_ACCOUNT_POLICY_SCOPED_COUNT']=='FAIL'
