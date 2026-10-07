import pytest
import json
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


def check(items):
    main=target('transformer','AWS::Logs::Transformer',TransformerConfig=items)
    return {r['rule_id']:r['verdict'] for r in run_resource_checks(linked_design(main),main)}


@pytest.mark.parametrize('kind',['ParseJSON','ParseKeyValue','Grok','Csv','ParseCloudfront','ParsePostgres','ParseRoute53','ParseVPC','ParseWAF'])
def test_known_parser_first(kind):
    assert check([{kind:{}}])['LOGS_PARSER_PIPELINE']=='PASS'


@pytest.mark.parametrize('items,expected',[
    ([], 'FAIL'),([{'AddKeys':{}},{'ParseJSON':{}}],'FAIL'),
    ([{'ParseJSON':{}}]*5,'PASS'),([{'ParseJSON':{}}]*6,'FAIL'),
    ([{'ParseToOCSF':{}}],'NEEDS_REVIEW'),([UNKNOWN],'NEEDS_REVIEW'),
    ([{'FutureParser':{}}],'NEEDS_REVIEW'),([{'ParseJSON':UNKNOWN}],'NEEDS_REVIEW'),
    ([{'ParseJSON':{},'Csv':{}}],'NEEDS_REVIEW'),
])
def test_parser_sequence(items,expected):
    assert check(items)['LOGS_PARSER_PIPELINE']==expected


@pytest.mark.parametrize('kind',['ParseCloudfront','ParsePostgres','ParseRoute53','ParseVPC','ParseWAF'])
def test_builtin_parser_must_be_first(kind):
    assert check([{'ParseJSON':{}},{kind:{}}])['LOGS_BUILTIN_PARSER_POSITION']=='FAIL'


@pytest.mark.parametrize('kind',['Grok','AddKeys','CopyValue'])
def test_singleton_processor(kind):
    assert check([{'ParseJSON':{}},{kind:{}},{kind:{}}])['LOGS_PROCESSOR_SINGLETONS']=='FAIL'


@pytest.mark.parametrize('source,expected',[('@message','PASS'),('nested','FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_first_json_source(source,expected):
    assert check([{'ParseJSON':{'Source':source}}])['LOGS_FIRST_JSON_SOURCE']==expected


@pytest.mark.parametrize('items,expected',[
    ([{'parseJSON':{}}],'PASS'),([{'csv':{}}],'PASS'),
    ([{'addKeys':{}},{'parseJSON':{}}],'FAIL'),
    ([{'ParseJSON':{}}],'NEEDS_REVIEW'),([{'parseToOCSF':{}}],'NEEDS_REVIEW'),
    ([UNKNOWN],'NEEDS_REVIEW'),
])
def test_account_transformer_pipeline(items,expected):
    main=target('policy','AWS::Logs::AccountPolicy',PolicyType='TRANSFORMER_POLICY',PolicyDocument=json.dumps(items))
    rows={r['rule_id']:r['verdict'] for r in run_resource_checks(linked_design(main),main)}
    assert rows['LOGS_PARSER_PIPELINE']==expected


def test_duplicate_json_processor_keys_are_ambiguous():
    main=target('policy','AWS::Logs::AccountPolicy',PolicyType='TRANSFORMER_POLICY',PolicyDocument='[{"parseJSON":{},"parseJSON":{}}]')
    rows={r['rule_id']:r['verdict'] for r in run_resource_checks(linked_design(main),main)}
    assert rows['LOGS_PARSER_PIPELINE']=='NEEDS_REVIEW'


def test_unknown_predecessor_does_not_prove_builtin_position():
    assert check([UNKNOWN,{'ParseWAF':{}}])['LOGS_BUILTIN_PARSER_POSITION']=='NEEDS_REVIEW'
