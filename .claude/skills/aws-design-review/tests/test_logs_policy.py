import json
import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, UNKNOWN
from test_autoscaling_group_nested_constraints import design


def body():
    return {'Statement': [
        {'DataIdentifier': ['email', 'name'], 'Operation': {'Audit': {'FindingsDestination': {}}}},
        {'DataIdentifier': ['email', 'name'], 'Operation': {'Deidentify': {'MaskConfig': {}}}},
    ]}


def check(raw, kind='DATA_PROTECTION_POLICY'):
    resource = target('policy', 'AWS::Logs::AccountPolicy', PolicyType=kind, PolicyDocument=raw)
    return {r['rule_id']: r['verdict'] for r in run_resource_checks(design(resource), resource)}


def test_valid_block_structure_and_statement_order():
    value = body()
    assert check(json.dumps(value))['LOGS_DATA_PROTECTION_BLOCKS'] == 'PASS'
    value['Statement'].reverse()
    assert check(json.dumps(value))['LOGS_DATA_PROTECTION_BLOCKS'] == 'PASS'


@pytest.mark.parametrize('change', ['audit', 'destination', 'redact', 'mask', 'identifiers'])
def test_missing_required_blocks_or_fields(change):
    value = body(); audit, redact = value['Statement']
    if change == 'audit': del audit['Operation']['Audit']
    if change == 'destination': del audit['Operation']['Audit']['FindingsDestination']
    if change == 'redact': del redact['Operation']['Deidentify']
    if change == 'mask': redact['Operation']['Deidentify']['MaskConfig'] = {'x': True}
    if change == 'identifiers': redact['DataIdentifier'] = ['different']
    assert check(json.dumps(value))['LOGS_DATA_PROTECTION_BLOCKS'] == 'FAIL'


def test_identifier_order_and_extra_statements_require_review():
    value = body(); value['Statement'][1]['DataIdentifier'].reverse()
    assert check(json.dumps(value))['LOGS_DATA_PROTECTION_BLOCKS'] == 'NEEDS_REVIEW'
    value = body(); value['Statement'].append({'Operation': {'FutureAction': {}}})
    assert check(json.dumps(value))['LOGS_DATA_PROTECTION_BLOCKS'] == 'NEEDS_REVIEW'


@pytest.mark.parametrize('raw,expected', [('{', 'FAIL'), ('NaN', 'FAIL'), (UNKNOWN, 'NEEDS_REVIEW'),
    ('{{resolve:ssm:policy}}', 'NEEDS_REVIEW')])
def test_json_syntax_and_unresolved_values(raw, expected):
    result = check(raw)
    assert result['LOGS_ACCOUNT_POLICY_JSON'] == expected
    assert result['LOGS_DATA_PROTECTION_BLOCKS'] == expected


def test_transformer_policy_checks_pipeline():
    result = check('[{"parseJSON":{}}]', kind='TRANSFORMER_POLICY')
    assert result == {rule:'PASS' for rule in ('LOGS_ACCOUNT_POLICY_JSON','LOGS_PARSER_PIPELINE',
        'LOGS_BUILTIN_PARSER_POSITION','LOGS_PROCESSOR_SINGLETONS','LOGS_FIRST_JSON_SOURCE')}


def test_other_policy_types_only_parse_json():
    assert check('{}', kind='SUBSCRIPTION_FILTER_POLICY') == {'LOGS_ACCOUNT_POLICY_JSON':'PASS'}
