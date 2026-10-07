import json
from pathlib import Path

import pytest

from aws_design_sheet.checker import Checker
from aws_design_sheet.checks.ce.threshold_expression_values import threshold_verdict, evaluate_ce_threshold_expression_values
from aws_design_sheet.checks.bedrockagentcore.agentcore_values import MEMORY_PATHS, JWT_BASE, evaluate_bedrockagentcore_agentcore_values
from aws_design_sheet.checks.budgets.budget_values import evaluate_budgets_budget_values
from aws_design_sheet.checks.registry import combine
bedrock_cost_checks = combine(evaluate_bedrockagentcore_agentcore_values, evaluate_budgets_budget_values, evaluate_ce_threshold_expression_values)
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


def props_at(path, value):
    node=value
    for part in reversed(path.removeprefix('/properties/').split('/')):
        node=[node] if part == '*' else {part:node}
    return node


def check(kind,props,rule):
    resource=target('main','AWS::'+kind,**props)
    return [r for r in bedrock_cost_checks(linked_design(resource),resource) if r['rule_id']==rule]


@pytest.mark.parametrize('path',MEMORY_PATHS,ids=range(7))
@pytest.mark.parametrize('extraction,expected',[('LLM_INFERRED','PASS'),('STRICTLY_CONSISTENT','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_memory_scope(path,extraction,expected):
    props=props_at(path,{'ExtractionType':extraction,'ExtractionConfig':{'Description':'extract country'}})
    assert check('BedrockAgentCore::Memory',props,'AGENTCORE_MEMORY_EXTRACTION_SCOPE')[0]['verdict']==expected


def test_memory_unknown_and_omitted_config():
    props=props_at(MEMORY_PATHS[0],{'ExtractionType':'LLM_INFERRED','ExtractionConfig':UNKNOWN})
    assert check('BedrockAgentCore::Memory',props,'AGENTCORE_MEMORY_EXTRACTION_SCOPE')[0]['verdict']=='NEEDS_REVIEW'
    assert not check('BedrockAgentCore::Memory',props_at(MEMORY_PATHS[0],{'ExtractionType':'LLM_INFERRED'}),'AGENTCORE_MEMORY_EXTRACTION_SCOPE')


@pytest.mark.parametrize('spec,usage,algorithm,expected',[
    ('RSA_2048','SIGN_VERIFY','RS256','PASS'),('RSA_3072','SIGN_VERIFY','PS256','PASS'),
    ('RSA_4096','SIGN_VERIFY','ES256','FAIL'),('ECC_NIST_P256','SIGN_VERIFY','ES256','PASS'),
    ('ECC_NIST_P384','SIGN_VERIFY','ES256','FAIL'),('ECC_SECG_P256K1','SIGN_VERIFY','ES256','FAIL'),
    ('ECC_NIST_P256','SIGN_VERIFY','RS256','FAIL'),('SYMMETRIC_DEFAULT','ENCRYPT_DECRYPT','RS256','FAIL'),
    ('RSA_2048','ENCRYPT_DECRYPT','RS256','FAIL'),('RSA_2048',UNKNOWN,'RS256','NEEDS_REVIEW'),
    (UNKNOWN,'SIGN_VERIFY','RS256','NEEDS_REVIEW'),('RSA_2048','SIGN_VERIFY',UNKNOWN,'NEEDS_REVIEW'),
    ('FUTURE_KEY','SIGN_VERIFY','RS256','NEEDS_REVIEW'),('RSA_2048','SIGN_VERIFY','FUTURE_ALG','NEEDS_REVIEW')])
def test_linked_signing_key(spec,usage,algorithm,expected):
    resource=target('main','AWS::BedrockAgentCore::OAuth2CredentialProvider',**props_at(JWT_BASE,{'SigningAlgorithm':algorithm,'PrivateKeySource':{'KmsKeySource':{'KmsKeyArn':'key'}}}))
    key=target('key','AWS::KMS::Key',KeySpec=spec,KeyUsage=usage)
    path=(JWT_BASE+'/PrivateKeySource/KmsKeySource/KmsKeyArn').removeprefix('/properties/')
    design=linked_design(resource,[key],[(path,'key')])
    assert bedrock_cost_checks(design,resource)[0]['verdict']==expected


@pytest.mark.parametrize('mode',['literal','conditional','scope','unknown_ancestor'])
def test_unproven_signing_key(mode):
    raw={'SigningAlgorithm':'RS256','PrivateKeySource':{'KmsKeySource':{'KmsKeyArn':'key'}}}
    if mode=='unknown_ancestor': raw['PrivateKeySource']=UNKNOWN
    resource=target('main','AWS::BedrockAgentCore::OAuth2CredentialProvider',**props_at(JWT_BASE,raw))
    key=target('key','AWS::KMS::Key',KeySpec='RSA_2048',KeyUsage='SIGN_VERIFY')
    path=(JWT_BASE+'/PrivateKeySource/KmsKeySource/KmsKeyArn').removeprefix('/properties/')
    design=linked_design(resource,[key],[] if mode=='literal' else [(path,'key')])
    if mode=='conditional': design.relations[0].condition='Maybe'
    if mode=='scope': key.scope.account='222222222222'
    assert bedrock_cost_checks(design,resource)[0]['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('path,valid,invalid',[
    ('Budget/BudgetType','COST','PRICE'),('Budget/TimeUnit','CUSTOM','WEEKLY'),
    ('Budget/AutoAdjustData/AutoAdjustType','FORECAST','MANUAL'),
    ('NotificationsWithSubscribers/*/Notification/ComparisonOperator','EQUAL_TO','NOT_EQUAL'),
    ('NotificationsWithSubscribers/*/Notification/NotificationType','ACTUAL','PAST'),
    ('NotificationsWithSubscribers/*/Notification/ThresholdType','ABSOLUTE_VALUE','AMOUNT'),
    ('NotificationsWithSubscribers/*/Subscribers/*/SubscriptionType','SNS','SMS')],ids=range(7))
@pytest.mark.parametrize('state',['valid','invalid','unknown'])
def test_budget_enums(path,valid,invalid,state):
    props=props_at('/properties/'+path,{'valid':valid,'invalid':invalid,'unknown':UNKNOWN}[state])
    result=check('Budgets::Budget',props,'BUDGET_PUBLIC_METADATA')
    assert result[0]['verdict']=={'valid':'PASS','invalid':'FAIL','unknown':'NEEDS_REVIEW'}[state]


@pytest.mark.parametrize('raw,expected',[(1,'PASS'),(60,'PASS'),(0,'FAIL'),(61,'FAIL'),(True,'NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_budget_period(raw,expected):
    props=props_at('/properties/Budget/AutoAdjustData/HistoricalOptions/BudgetAdjustmentPeriod',raw)
    assert check('Budgets::Budget',props,'BUDGET_PUBLIC_METADATA')[0]['verdict']==expected


@pytest.mark.parametrize('raw,expected',[([UNKNOWN]*200,'PASS'),([UNKNOWN]*201,'FAIL'),(UNKNOWN,'NEEDS_REVIEW')],ids=['max','over','unknown'])
def test_budget_tags(raw,expected):
    assert check('Budgets::Budget',{'ResourceTags':raw},'BUDGET_PUBLIC_METADATA')[0]['verdict']==expected


def test_notification_count_conflict_remains_held():
    assert not check('Budgets::Budget',{'NotificationsWithSubscribers':[{}]*11},'BUDGET_PUBLIC_METADATA')


@pytest.mark.parametrize('arn,expected',[
    ('arn:aws:iam::111111111111:role/path/action','PASS'),
    ('arn:aws:iam::222222222222:role/action','FAIL'),
    ('arn:aws-eusc:iam::111111111111:role/action','PASS'),
    (UNKNOWN,'NEEDS_REVIEW'),('arn:aws:iam::111111111111:user/a','NEEDS_REVIEW')])
def test_action_account(arn,expected):
    assert check('Budgets::BudgetsAction',{'ExecutionRoleArn':arn},'BUDGET_ACTION_ROLE_ACCOUNT')[0]['verdict']==expected


def expression(value='10',options=None):
    return {'Dimensions':{'Key':'ANOMALY_TOTAL_IMPACT_ABSOLUTE','MatchOptions':['GREATER_THAN_OR_EQUAL'] if options is None else options,'Values':[value]}}


@pytest.mark.parametrize('value,expected',[
    ('0','PASS'),('10000000000','PASS'),('10000000000.00000001','FAIL'),('-0.0001','FAIL'),
    ('1e10','PASS'),('1e11','FAIL'),('1e-999999','PASS'),('NaN','NEEDS_REVIEW'),
    ('Infinity','NEEDS_REVIEW'),(True,'NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW'),('01','NEEDS_REVIEW')])
@pytest.mark.parametrize('depth',[0,3])
def test_threshold_numbers(value,expected,depth):
    node=expression(value)
    for i in range(depth): node={'Or':[{'And':[node]}]}
    assert threshold_verdict(json.dumps(node))==expected


@pytest.mark.parametrize('options,expected',[([], 'FAIL'),(['EQUALS'],'FAIL'),(['GREATER_THAN_OR_EQUAL','EQUALS'],'NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_threshold_options(options,expected):
    assert threshold_verdict(json.dumps(expression(options=options)))==expected


@pytest.mark.parametrize('raw',['{"Dimensions":{},"Dimensions":{}}','{"And":[NaN]}','{}','not JSON','{"Not":{}}','['*1100+']'*1100,' '*100001],ids=['duplicate','nonfinite','empty','invalid','unsupported','deep','large'])
def test_threshold_parser_limits(raw):
    assert threshold_verdict(raw)=='NEEDS_REVIEW'


def test_threshold_integration():
    resource=target('main','AWS::CE::AnomalySubscription',ThresholdExpression=json.dumps(expression('-1')))
    root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(resource))['results']
    result=next(r for r in results if r['rule_id']=='CE_THRESHOLD_EXPRESSION_VALUES')
    assert result['verdict']=='FAIL'
    assert result['source_checked_at']=='2026-10-04'
    assert result['source_urls']
