import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.lex.kendra_scope import evaluate_lex_kendra_scope
from test_autoscaling_group_and_scaling_policy import target,linked_design


@pytest.mark.parametrize('region,account,expected',[('ap-northeast-1','111111111111','PASS'),('us-east-1','111111111111','FAIL'),('ap-northeast-1','222222222222','FAIL')])
@pytest.mark.parametrize('context',['literal','linked','conditional','template','mismatch','source_template'])
def test_arn_scope(region,account,expected,context):
    arn='arn:aws:kendra:'+region+':'+account+':index/abc-123'
    r=target('main','AWS::Lex::Bot',BotLocales=[{'Intents':[{'KendraConfiguration':{'KendraIndex':arn}}]}])
    other=target('index','AWS::Kendra::Index');other.scope.region=region;other.scope.account=account
    d=linked_design(r,[other],[] if context=='literal' else [('BotLocales/0/Intents/0/KendraConfiguration/KendraIndex','index')])
    if context=='conditional':d.relations[0].condition='maybe'
    if context=='template':other.template=TemplateContext(state='UNRESOLVED')
    if context=='source_template':r.template=TemplateContext(state='UNRESOLVED')
    if context=='mismatch':other.scope.region='eu-west-1'
    assert evaluate_lex_kendra_scope(d,r)[0]['verdict']==(expected if context in ('literal','linked') else 'NEEDS_REVIEW')


def test_named_reference():
    r=target('main','AWS::Lex::Bot',BotLocales=[{'Intents':[{'KendraConfiguration':{'KendraIndex':'index'}}]}])
    other=target('index','AWS::Kendra::Index')
    d=linked_design(r,[other],[('BotLocales/0/Intents/0/KendraConfiguration/KendraIndex','index')])
    assert evaluate_lex_kendra_scope(d,r)[0]['verdict']=='PASS'


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('main','AWS::Lex::Bot',BotLocales=[{'Intents':[{'KendraConfiguration':{'KendraIndex':'arn:aws:kendra:us-east-1:111111111111:index/abc'}}]}])
    assert any(f['rule_id']=='LEX_KENDRA_INDEX_SCOPE' and f['verdict']=='FAIL' for f in Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results'])
