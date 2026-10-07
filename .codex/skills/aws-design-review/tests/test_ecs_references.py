import pytest

from aws_design_sheet.checker import Checker
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, UNKNOWN
from test_autoscaling_group_nested_constraints import design


def findings(containers, rule, **properties):
    resource = target('task', 'AWS::ECS::TaskDefinition', ContainerDefinitions=containers, **properties)
    return [r for r in run_resource_checks(design(resource), resource) if r['rule_id'] == rule]


@pytest.mark.parametrize('field', ['VolumesFrom', 'Links'])
@pytest.mark.parametrize('name,expected', [('data', 'PASS'), ('missing', 'FAIL'), ('app', 'FAIL'),
    (UNKNOWN, 'NEEDS_REVIEW'), ('{{resolve:ssm:container}}', 'NEEDS_REVIEW')])
def test_other_container_reference(field, name, expected):
    refs = [{'SourceContainer': name}] if field == 'VolumesFrom' else [name]
    result = findings([{'Name': 'app', field: refs}, {'Name': 'data'}], 'ECS_TASK_CONTAINER_REFERENCE')
    assert result[0]['verdict'] == expected


def test_link_alias_and_duplicate_target():
    containers = [{'Name': 'app', 'Links': ['data:storage']}, {'Name': 'data'}]
    assert findings(containers, 'ECS_TASK_CONTAINER_REFERENCE')[0]['verdict'] == 'PASS'
    containers.append({'Name': 'data'})
    assert findings(containers, 'ECS_TASK_CONTAINER_REFERENCE')[0]['verdict'] == 'NEEDS_REVIEW'


@pytest.mark.parametrize('field', ['VolumesFrom', 'Links'])
def test_unresolved_reference_list(field):
    assert findings([{'Name': 'app', field: UNKNOWN}], 'ECS_TASK_CONTAINER_REFERENCE')[0]['verdict'] == 'NEEDS_REVIEW'


@pytest.mark.parametrize('containers,name,expected', [
    ([{'Name': 'proxy'}], 'proxy', 'PASS'), ([{'Name': 'app'}], 'proxy', 'FAIL'),
    ([{'Name': UNKNOWN}], 'proxy', 'NEEDS_REVIEW'), (UNKNOWN, 'proxy', 'NEEDS_REVIEW'),
    ([{'Name': 'proxy'}], UNKNOWN, 'NEEDS_REVIEW'),
])
def test_proxy_reference(containers, name, expected):
    result = findings(containers, 'ECS_TASK_CONTAINER_REFERENCE', ProxyConfiguration={'ContainerName': name})
    assert result[0]['verdict'] == expected


@pytest.mark.parametrize('devices,name,expected', [
    ([{'DeviceName': 'infer'}], 'infer', 'PASS'), ([], 'infer', 'FAIL'),
    (UNKNOWN, 'infer', 'NEEDS_REVIEW'), ([{'DeviceName': UNKNOWN}], 'infer', 'NEEDS_REVIEW'),
    ([{'DeviceName': 'infer'}, {'DeviceName': 'infer'}], 'infer', 'NEEDS_REVIEW'),
    ([{'DeviceName': 'infer'}], UNKNOWN, 'NEEDS_REVIEW'),
])
def test_inference_reference(devices, name, expected):
    result = findings([{'Name': 'app', 'ResourceRequirements': [{'Type': 'InferenceAccelerator', 'Value': name}]}],
        'ECS_TASK_INFERENCE_REFERENCE', InferenceAccelerators=devices)
    assert result[0]['verdict'] == expected


@pytest.mark.parametrize('types,expected', [
    ([['NeuronDevice']], 'PASS'), ([['NeuronDevice', 'NeuronDevice']], 'PASS'),
    ([['NeuronDevice'], ['NeuronDevice']], 'FAIL'), ([['GPU'], ['NeuronDevice']], 'PASS'),
    ([['NeuronDevice'], [UNKNOWN]], 'NEEDS_REVIEW'),
    ([['NeuronDevice'], ['NeuronDevice'], [UNKNOWN]], 'FAIL'),
])
def test_neuron_counts_containers_not_entries(types, expected):
    containers = [{'Name': str(i), 'ResourceRequirements': [{'Type': t, 'Value': 'ALL'} for t in items]}
                  for i, items in enumerate(types)]
    assert findings(containers, 'ECS_TASK_NEURON_CONTAINER_COUNT')[0]['verdict'] == expected


@pytest.mark.parametrize('options,expected', [
    ({}, 'PASS'), ({'enable-ecs-log-metadata': 'true'}, 'PASS'),
    ({'config-file-type': 'file', 'config-file-value': '/etc/config'}, 'PASS'),
    ({'config-file-type': 's3'}, 'PASS'), ({'config-file-type': 'http'}, 'FAIL'),
    ({'enable-ecs-log-metadata': 'yes'}, 'FAIL'), ({'unknown-key': 'x'}, 'FAIL'),
    ({'config-file-type': UNKNOWN}, 'NEEDS_REVIEW'), (UNKNOWN, 'NEEDS_REVIEW'),
])
def test_firelens_options(options, expected):
    result = findings([{'Name': 'logs', 'FirelensConfiguration': {'Options': options}}], 'ECS_TASK_FIRELENS_OPTIONS')
    assert result[0]['verdict'] == expected


def test_optional_fields_absent():
    assert findings([{'Name': 'app'}], 'ECS_TASK_CONTAINER_REFERENCE') == []
    assert findings([{'Name': 'app'}], 'ECS_TASK_FIRELENS_OPTIONS') == []


@pytest.mark.parametrize('config,expected', [
    ({'Options': {'splunk-token': 'token', 'splunk-url': 'https://logs'}}, 'PASS'),
    ({'Options': {'splunk-url': 'https://logs'}, 'SecretOptions': [{'Name': 'splunk-token', 'ValueFrom': 'arn'}]}, 'PASS'),
    ({'Options': {'splunk-url': 'https://logs'}}, 'FAIL'),
    ({'Options': UNKNOWN}, 'NEEDS_REVIEW'),
    ({'Options': {'splunk-url': 'https://logs'}, 'SecretOptions': UNKNOWN}, 'NEEDS_REVIEW'),
    ({'Options': {'splunk-url': 'https://logs'}, 'SecretOptions': [{'Name': UNKNOWN}]}, 'NEEDS_REVIEW'),
])
def test_splunk_literal_or_secret_options(config, expected):
    result = findings([{'LogConfiguration': {'LogDriver': 'splunk', **config}}], 'ECS_TASK_SPLUNK_OPTIONS')
    assert result[0]['verdict'] == expected


def test_checker_integrates_sources():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    resource = target('task', 'AWS::ECS::TaskDefinition', ContainerDefinitions=[{'Name': 'app', 'Links': ['missing']}])
    checker = Checker(root / 'schemas', root / 'profiles/vpc-subnet.json')
    result = checker.check(design(resource))
    matches = [r for r in result['results'] if r['rule_id'] == 'ECS_TASK_CONTAINER_REFERENCE']
    assert matches[0]['verdict'] == 'FAIL'
    assert matches[0]['source_urls']
