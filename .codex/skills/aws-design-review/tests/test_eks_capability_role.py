import json

import pytest

from aws_design_sheet.models import Relation
from aws_design_sheet.checks.registry import run_resource_checks
from aws_design_sheet.checks.eks.capability_role import capability_trust_verdict
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


def statement(actions=('sts:AssumeRole', 'sts:TagSession'), **changes):
    return {'Effect': 'Allow', 'Principal': {'Service': 'capabilities.eks.amazonaws.com'},
            'Action': list(actions), **changes}


@pytest.mark.parametrize('statements,expected', [
    ([statement()], 'PASS'),
    ([statement(['sts:AssumeRole']), statement(['sts:TagSession'])], 'PASS'),
    (statement(), 'PASS'),
    ([statement(['sts:AssumeRole'])], 'FAIL'),
    ([statement(['sts:TagSession'])], 'FAIL'),
    ([statement(Principal={'Service': 'eks.amazonaws.com'})], 'FAIL'),
    ([statement(), statement(['sts:TagSession'], Effect='Deny')], 'FAIL'),
    ([statement(), statement(['sts:AssumeRole'], Effect='Deny')], 'FAIL'),
    ([statement(), statement(['s3:GetObject'], Effect='Deny')], 'PASS'),
    ([statement(Condition={'StringEquals': {'aws:SourceAccount': '111111111111'}})], 'NEEDS_REVIEW'),
    ([statement(), statement(Condition={})], 'NEEDS_REVIEW'),
    ([statement(Principal='*')], 'NEEDS_REVIEW'),
    ([statement(['sts:*'])], 'NEEDS_REVIEW'),
    ([statement(['sts:assumerole', 'sts:TagSession'])], 'NEEDS_REVIEW'),
    ([statement(NotAction='sts:Other')], 'NEEDS_REVIEW'),
    ([statement(Resource='*')], 'NEEDS_REVIEW'),
    ([statement(Principal={'Service': UNKNOWN})], 'NEEDS_REVIEW'),
    ([statement(Principal={'Service': ['capabilities.eks.amazonaws.com', 'eks.amazonaws.com']})], 'PASS'),
    ([statement(Principal={'Service': '${Principal}'})], 'NEEDS_REVIEW'),
    ([statement(Action=[])], 'NEEDS_REVIEW'),
    ([], 'NEEDS_REVIEW'),
])
def test_declared_trust(statements, expected):
    assert capability_trust_verdict({'Version': '2012-10-17', 'Statement': statements}) == expected


@pytest.mark.parametrize('document,expected', [
    (json.dumps({'Statement': statement()}), 'PASS'),
    ('{"Statement":[],"Statement":{}}', 'NEEDS_REVIEW'),
    ('{', 'NEEDS_REVIEW'),
    pytest.param('x' * 65537, 'NEEDS_REVIEW', id='oversized-document'),
    ({'Version': 'future', 'Statement': statement()}, 'NEEDS_REVIEW'),
    ({'Statement': statement(), 'Unknown': True}, 'NEEDS_REVIEW'),
    (UNKNOWN, 'NEEDS_REVIEW'),
])
def test_policy_encoding(document, expected):
    assert capability_trust_verdict(document) == expected


@pytest.mark.parametrize('variation,expected', [
    ('linked', 'PASS'), ('literal', 'NEEDS_REVIEW'), ('condition', 'NEEDS_REVIEW'),
    ('account', 'NEEDS_REVIEW'), ('region', 'NEEDS_REVIEW'), ('partition', 'NEEDS_REVIEW'),
    ('unknown_scope', 'NEEDS_REVIEW'), ('nested', 'NEEDS_REVIEW'), ('missing', 'NEEDS_REVIEW'),
    ('wrong_type', 'NEEDS_REVIEW'),
])
def test_capability_integration(variation, expected):
    capability = target('capability', 'AWS::EKS::Capability', RoleArn='arn:aws:iam::111111111111:role/example')
    role = target('role', 'AWS::IAM::Role', **({} if variation == 'missing' else
                  {'AssumeRolePolicyDocument': {'Statement': statement()}}))
    design = linked_design(capability, [role], [] if variation == 'literal' else [('RoleArn', 'role')])
    if variation == 'condition': design.relations[0].condition = 'conditional'
    if variation == 'account': role.scope.account = '999999999999'
    if variation == 'region': role.scope.region = 'us-west-2'
    if variation == 'partition': capability.scope.region = role.scope.region = 'cn-north-1'
    if variation == 'unknown_scope': capability.scope.account = role.scope.account = 'unknown'
    if variation == 'wrong_type': role.type = 'AWS::IAM::User'
    if variation == 'nested':
        design.relations.append(Relation(id='nested', source_resource_id='role',
            source_path='/properties/AssumeRolePolicyDocument/Statement/Principal/Service',
            target_resource_id='capability', evidence_ids=['e1']))
    finding = next(f for f in run_resource_checks(design, capability)
                   if f['rule_id'] == 'EKS_CAPABILITY_DECLARED_TRUST')
    assert finding['verdict'] == expected
    assert 'effective permissions remain unverified' in finding['reason']
