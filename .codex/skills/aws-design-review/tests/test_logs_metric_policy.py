import json
import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


def policy(name,criteria=None):
    return target(name,'AWS::Logs::AccountPolicy',PolicyName=name,PolicyType='METRIC_EXTRACTION_POLICY',**({'SelectionCriteria':criteria} if criteria is not None else {}))


def check(main,others=()):
    return {r['rule_id']:r['verdict'] for r in run_resource_checks(linked_design(main,list(others)),main)}


@pytest.mark.parametrize('left,right,expected',[
    ('LogGroupName IN ["/app/a"]','LogGroupName IN ["/app/a"]','FAIL'),
    ('LogGroupName IN ["/app/a"]','LogGroupName IN ["/app/b"]','NEEDS_REVIEW'),
    ('LogGroupNamePrefix IN ["/app"]','LogGroupNamePrefix IN ["/app-prod"]','FAIL'),
    ('LogGroupNamePrefix IN ["/app"]','LogGroupName IN ["/app/a"]','FAIL'),
    ('LogGroupName IN ["/app"]','LogGroupNamePrefix IN ["/app/a"]','NEEDS_REVIEW'),
    ('LogGroupName IN ["/app/a"]','LogGroupNamePrefix NOT IN ["/app"]','NEEDS_REVIEW'),
    ('LogGroupNamePrefix IN ["/app"]','LogGroupNamePrefix NOT IN ["/app/a"]','FAIL'),
    ('LogGroupName IN ["/app/a","/other"]','LogGroupNamePrefix NOT IN ["/app"]','FAIL'),
    ('LogGroupNamePrefix IN ["/app"]','LogGroupName NOT IN ["/app"]','FAIL'),
    ('LogGroupName IN []','LogGroupNamePrefix NOT IN ["/app"]','NEEDS_REVIEW'),
    ('LogGroupName IN ["/app"]',UNKNOWN,'NEEDS_REVIEW'),
    ('LogGroupNamePrefix="/app"','LogGroupName IN ["/app"]','NEEDS_REVIEW'),
])
@pytest.mark.parametrize('reverse',[False,True])
def test_in_and_not_in_intersections(left,right,expected,reverse):
    if reverse:left,right=right,left
    assert check(policy('first',left),[policy('second',right)])['LOGS_METRIC_POLICY_OVERLAP']==expected


@pytest.mark.parametrize('count,expected',[(5,'NEEDS_REVIEW'),(6,'FAIL')])
def test_five_policy_limit(count,expected):
    rows=[policy(str(i),'LogGroupName IN ["group-'+str(i)+'"]') for i in range(count)]
    assert check(rows[0],rows[1:])['LOGS_METRIC_POLICY_COUNT']==expected


def test_all_log_groups_is_exclusive():
    assert check(policy('all'),[policy('scoped','LogGroupName IN ["/app"]')])['LOGS_METRIC_POLICY_COUNT']=='FAIL'


def test_only_one_not_in_policy():
    rows=check(policy('first','LogGroupName NOT IN ["/a"]'),[policy('second','LogGroupNamePrefix NOT IN ["/b"]')])
    assert rows['LOGS_METRIC_POLICY_NOT_IN_SINGLETON']=='FAIL'


@pytest.mark.parametrize('size,expected',[(50,'PASS'),(51,'FAIL')])
def test_selection_value_limit(size,expected):
    raw='LogGroupName IN '+json.dumps(['group-'+str(i) for i in range(size)])
    assert check(policy('first',raw))['LOGS_METRIC_POLICY_SELECTION_VALUES']==expected


def test_same_name_alias_and_other_region_are_not_collisions():
    main=policy('first','LogGroupName IN ["/app"]')
    alias=policy('first','LogGroupName IN ["/app"]');alias.id='alias'
    other=policy('second','LogGroupName IN ["/app"]');other.scope.region='us-west-2'
    assert check(main,[alias,other])['LOGS_METRIC_POLICY_OVERLAP']=='NEEDS_REVIEW'
