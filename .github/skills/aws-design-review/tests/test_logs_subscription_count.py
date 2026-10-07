import pytest
from aws_design_sheet.models import Relation
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


def filters(names):
    resources = [target(str(i), 'AWS::Logs::SubscriptionFilter', FilterName=name, LogGroupName='/example')
                 for i, name in enumerate(names)]
    return linked_design(resources[0], resources[1:]), resources[0]


def result(design, resource, rule='LOGS_SUBSCRIPTION_FILTER_COUNT'):
    return next(f['verdict'] for f in run_resource_checks(design, resource) if f['rule_id'] == rule)


@pytest.mark.parametrize('names,expected', [(['a'], 'NEEDS_REVIEW'), (['a','b'], 'NEEDS_REVIEW'),
    (['a','b','c'], 'FAIL'), (['a','a','b'], 'NEEDS_REVIEW'),
    (['a','b',UNKNOWN], 'NEEDS_REVIEW'), (['a','b','${Name}'], 'NEEDS_REVIEW')])
def test_named_filter_count(names, expected):
    design, resource = filters(names)
    assert result(design, resource) == expected


@pytest.mark.parametrize('variation,expected', [('linked','FAIL'), ('conditional','NEEDS_REVIEW'),
    ('region','NEEDS_REVIEW'), ('account','NEEDS_REVIEW'), ('mixed','NEEDS_REVIEW')])
def test_group_identity(variation, expected):
    design, resource = filters(['a','b','c'])
    group = target('group','AWS::Logs::LogGroup',LogGroupName='/example')
    design.resources.append(group)
    for i in range(3 if variation != 'mixed' else 2):
        design.relations.append(Relation(id=str(i),source_resource_id=str(i),source_path='/properties/LogGroupName',
                                        target_resource_id='group',evidence_ids=['e1']))
    if variation == 'conditional': design.relations[-1].condition='conditional'
    if variation == 'region': design.resources[2].scope.region='us-west-2'
    if variation == 'account': design.resources[2].scope.account='999999999999'
    assert result(design, resource) == expected


@pytest.mark.parametrize('service,suffix',[('kinesis','stream/example'),('firehose','deliverystream/example'),
                                         ('lambda','function:example:live')])
@pytest.mark.parametrize('same,expected',[(True,'PASS'),(False,'FAIL')])
def test_destination_account(service,suffix,same,expected):
    resource=target('filter','AWS::Logs::SubscriptionFilter')
    account=resource.scope.account if same else '999999999999'
    extra=target('extra','AWS::Logs::SubscriptionFilter',DestinationArn=f'arn:aws:{service}:us-east-1:{account}:{suffix}')
    resource.fields.extend(extra.fields)
    assert result(linked_design(resource),resource,'LOGS_DIRECT_DESTINATION_ACCOUNT')==expected


@pytest.mark.parametrize('arn',[UNKNOWN,'arn:aws:logs:us-east-1:999999999999:destination:example',
                              'arn:aws:kinesis:us-east-1:999999999999:unknown/example','${Destination}'])
def test_unresolved_destination(arn):
    resource=target('filter','AWS::Logs::SubscriptionFilter',DestinationArn=arn)
    assert result(linked_design(resource),resource,'LOGS_DIRECT_DESTINATION_ACCOUNT')=='NEEDS_REVIEW'
