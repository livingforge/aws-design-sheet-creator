import pytest
from aws_design_sheet.checks.ecs.size import task_units
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, UNKNOWN
from test_autoscaling_group_nested_constraints import design


def check(**props):
    resource = target('task', 'AWS::ECS::TaskDefinition', **props)
    return {r['rule_id']: r['verdict'] for r in run_resource_checks(design(resource), resource)}


@pytest.mark.parametrize('raw,kind,expected', [
    ('1 vCPU', 'Cpu', 1024), ('.25 vcpu', 'Cpu', 256), ('0.125 vCPU', 'Cpu', 128),
    ('1024', 'Cpu', 1024), ('3 GB', 'Memory', 3072), ('512 MiB', 'Memory', 512),
    ('.5 GB', 'Memory', 512), ('3 vCPU', 'Memory', None), ('3 GB', 'Cpu', None),
    ('1e3', 'Cpu', None), ('1.1 vCPU', 'Cpu', None), (UNKNOWN, 'Cpu', None),
    ('1.00000000000000000000000000000000001 vCPU', 'Cpu', None),
    ('{{resolve:ssm:size}}', 'Memory', None),
])
def test_unit_normalization(raw, kind, expected):
    assert task_units(raw, kind) == expected


@pytest.mark.parametrize('cpu,memory,expected', [
    ('256', '512', 'PASS'), ('.25 vCPU', '2 GB', 'PASS'), ('256', '3 GB', 'FAIL'),
    ('512', '4 GB', 'PASS'), ('512', '512', 'FAIL'), ('1024', '8 GB', 'PASS'),
    ('1024', '9 GB', 'FAIL'), ('2048', '16 GB', 'PASS'), ('2048', '4.5 GB', 'FAIL'),
    ('4096', '30 GB', 'PASS'), ('4096', '31 GB', 'FAIL'),
    ('8192', '60 GB', 'PASS'), ('8192', '18 GB', 'FAIL'),
    ('16384', '120 GB', 'PASS'), ('16384', '36 GB', 'FAIL'),
    ('32768', '244 GB', 'PASS'), ('32768', '64 GB', 'FAIL'),
    ('768', '2 GB', 'FAIL'), (UNKNOWN, '2 GB', 'NEEDS_REVIEW'),
    ('1024', UNKNOWN, 'NEEDS_REVIEW'), ('1.1 vCPU', '2 GB', 'NEEDS_REVIEW'),
])
def test_fargate_pairs(cpu, memory, expected):
    assert check(RequiresCompatibilities=['EC2', 'FARGATE'], Cpu=cpu, Memory=memory)['ECS_FARGATE_TASK_SIZE'] == expected


@pytest.mark.parametrize('cpu,memory', [('256', '512'), ('512', '1024'), ('8192', '16384'), ('32768', '61440')])
def test_linux_only_sizes_reject_explicit_windows(cpu, memory):
    assert check(RequiresCompatibilities=['FARGATE'], Cpu=cpu, Memory=memory,
        RuntimePlatform={'OperatingSystemFamily': 'WINDOWS_SERVER_2022_CORE'})['ECS_FARGATE_TASK_SIZE'] == 'FAIL'


def test_windows_supported_size_and_unknown_os():
    props = dict(RequiresCompatibilities=['FARGATE'], Cpu='1024', Memory='2048')
    assert check(**props, RuntimePlatform={'OperatingSystemFamily': 'WINDOWS_SERVER_2022_CORE'})['ECS_FARGATE_TASK_SIZE'] == 'PASS'
    assert check(**props, RuntimePlatform=UNKNOWN)['ECS_FARGATE_TASK_SIZE'] == 'NEEDS_REVIEW'


@pytest.mark.parametrize('props', [{}, {'Cpu': '1024'}, {'Memory': '2048'}])
def test_fargate_requires_both_fields(props):
    assert check(RequiresCompatibilities=['FARGATE'], **props)['ECS_FARGATE_TASK_SIZE'] == 'FAIL'


def test_large_size_keeps_platform_requirement_separate():
    result = check(RequiresCompatibilities=['FARGATE'], Cpu='8192', Memory='16384')
    assert result['ECS_FARGATE_TASK_SIZE'] == 'PASS'
    assert result['ECS_FARGATE_SIZE_PLATFORM'] == 'NEEDS_REVIEW'


@pytest.mark.parametrize('cpu,expected', [('127', 'FAIL'), ('128', 'NEEDS_REVIEW'), ('255', 'NEEDS_REVIEW'),
    ('256', 'PASS'), ('192 vCPU', 'PASS'), ('193 vCPU', 'FAIL'), (UNKNOWN, 'NEEDS_REVIEW')])
def test_ec2_range_and_document_conflict(cpu, expected):
    assert check(RequiresCompatibilities=['EC2'], Cpu=cpu)['ECS_EC2_TASK_CPU_RANGE'] == expected


def test_compatibility_is_not_inferred():
    assert check(Cpu='1024', Memory='2048')['ECS_FARGATE_TASK_SIZE'] == 'NEEDS_REVIEW'
    assert 'ECS_FARGATE_TASK_SIZE' not in check(RequiresCompatibilities=['EC2'], Cpu='1024', Memory='2048')


@pytest.mark.parametrize('amounts,expected', [([100, 100], 'PASS'), ([128, 128], 'NEEDS_REVIEW'),
    ([200, 100], 'FAIL'), ([UNKNOWN, 100], 'NEEDS_REVIEW'), ([300, UNKNOWN], 'FAIL')])
def test_container_cpu_total(amounts, expected):
    result = check(RequiresCompatibilities=['FARGATE'], Cpu='256', Memory='512',
        ContainerDefinitions=[{'Name': str(i), 'Cpu': n} for i, n in enumerate(amounts)])
    assert result['ECS_TASK_CONTAINER_CPU_TOTAL'] == expected


def test_memory_reservation_precedes_hard_limit():
    result = check(Memory='1024', ContainerDefinitions=[{'Name': 'a', 'Memory': 2048, 'MemoryReservation': 512}])
    assert result['ECS_TASK_CONTAINER_MEMORY_TOTAL'] == 'PASS'
    result = check(Memory='1024', ContainerDefinitions=[{'Name': 'a', 'Memory': 2048}])
    assert result['ECS_TASK_CONTAINER_MEMORY_TOTAL'] == 'FAIL'
    result = check(Memory='1024', ContainerDefinitions=[{'Name': 'a', 'Memory': 512, 'MemoryReservation': UNKNOWN}])
    assert result['ECS_TASK_CONTAINER_MEMORY_TOTAL'] == 'NEEDS_REVIEW'


def test_windows_does_not_assert_collective_limits():
    result = check(RequiresCompatibilities=['FARGATE'], Cpu='1024', Memory='2048',
        RuntimePlatform={'OperatingSystemFamily': 'WINDOWS_SERVER_2022_CORE'},
        ContainerDefinitions=[{'Cpu': 4096, 'Memory': 8192}])
    assert 'ECS_TASK_CONTAINER_CPU_TOTAL' not in result
    assert 'ECS_TASK_CONTAINER_MEMORY_TOTAL' not in result
