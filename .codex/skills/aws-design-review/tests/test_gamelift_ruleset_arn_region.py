import pytest
from aws_design_sheet.checks.common.context_values import _Context
from aws_design_sheet.checks.gamelift.ruleset_arn_region import ruleset_arn_region
from test_autoscaling_group_and_scaling_policy import target,linked_design


@pytest.mark.parametrize('region,expected',[('ap-northeast-1','PASS'),('us-east-1','FAIL')])
@pytest.mark.parametrize('account',['','111111111111'])
@pytest.mark.parametrize('context',['literal','linked','conditional','mismatch','unknown_scope'])
def test_arn_region(region,expected,account,context):
    arn='arn:aws:gamelift:'+region+':'+account+':matchmakingruleset/RuleSet'
    r=target('main','AWS::GameLift::MatchmakingConfiguration',RuleSetName=arn)
    other=target('rules','AWS::GameLift::MatchmakingRuleSet',Name='RuleSet');other.scope.region=region
    d=linked_design(r,[other],[] if context=='literal' else [('RuleSetName','rules')])
    if context=='conditional':d.relations[0].condition='maybe'
    if context=='mismatch':other.fields[0].candidates[0].value='Other'
    if context=='unknown_scope':other.scope.region='UNKNOWN'
    assert ruleset_arn_region(_Context(d,r),r,'/properties/RuleSetName')==(expected if context in ('literal','linked') else 'NEEDS_REVIEW')


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('main','AWS::GameLift::MatchmakingConfiguration',RuleSetName='arn:aws:gamelift:us-east-1::matchmakingruleset/RuleSet')
    assert any(f['rule_id']=='GAMELIFT_MATCHMAKING_RULESET_REGION' and f['verdict']=='FAIL' for f in Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results'])
