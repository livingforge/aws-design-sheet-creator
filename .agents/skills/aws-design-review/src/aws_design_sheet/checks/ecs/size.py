"""Normalize documented task-size units and validate explicit launch contracts."""
import re
from decimal import Decimal, localcontext
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT

TASK = 'https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html'
API = 'https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_RegisterTaskDefinition.html'
TROUBLESHOOT = 'https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-cpu-memory-error.html'
SOURCES = {
    'ECS_TASK_CONTAINER_CPU_TOTAL': ['https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_ContainerDefinition.html'],
    'ECS_TASK_CONTAINER_MEMORY_TOTAL': [TASK],
    'ECS_FARGATE_TASK_SIZE': [TASK, TROUBLESHOOT],
    'ECS_FARGATE_SIZE_PLATFORM': [TASK],
    'ECS_EC2_TASK_CPU_RANGE': [API, TROUBLESHOOT],
}
MEMORY = {
    256: {512, 1024, 2048}, 512: set(range(1024, 4097, 1024)),
    1024: set(range(2048, 8193, 1024)), 2048: set(range(4096, 16385, 1024)),
    4096: set(range(8192, 30721, 1024)), 8192: set(range(16384, 61441, 4096)),
    16384: set(range(32768, 122881, 8192)), 32768: {61440, 122880, 249856},
}


def task_units(raw, kind):
    """Return exact integer units, or None when the spelling is not established."""
    if not isinstance(raw, str) or len(raw) > 80:
        return None
    match = re.fullmatch(r'([0-9]+(?:\.[0-9]+)?|\.[0-9]+)\s*(vCPU|MiB|GB)?', raw, re.I)
    if not match:
        return None
    suffix = (match[2] or '').lower()
    if suffix not in (('', 'vcpu') if kind == 'Cpu' else ('', 'mib', 'gb')):
        return None
    with localcontext() as context:
        context.prec = 100
        amount = Decimal(match[1]) * (1024 if suffix in ('vcpu', 'gb') else 1)
        return int(amount) if amount == amount.to_integral_value() else None


def evaluate_task_size(design, resource):
    ctx = _Context(design, resource)
    compat = value(ctx, resource, '/properties/RequiresCompatibilities')
    cpu_raw = value(ctx, resource, '/properties/Cpu')
    memory_raw = value(ctx, resource, '/properties/Memory')
    cpu, memory = task_units(cpu_raw, 'Cpu'), task_units(memory_raw, 'Memory')
    os = value(ctx, resource, '/properties/RuntimePlatform/OperatingSystemFamily')
    results = []
    if isinstance(compat, list) and 'FARGATE' in compat:
        if os is ABSENT:
            os = 'LINUX'  # Fargate's documented default.
        windows = isinstance(os, str) and os.startswith('WINDOWS_')
        bad = cpu_raw is ABSENT or memory_raw is ABSENT
        bad |= cpu is not None and cpu not in MEMORY
        bad |= cpu in MEMORY and memory is not None and memory not in MEMORY[cpu]
        bad |= windows and cpu is not None and cpu not in (1024, 2048, 4096)
        pending = cpu is None or memory is None or not (os == 'LINUX' or windows)
        results.append(ctx.finding('ECS_FARGATE_TASK_SIZE', '/properties/Cpu',
            'FAIL' if bad else 'NEEDS_REVIEW' if pending else 'PASS',
            'explicit FARGATE compatibility requires a documented CPU/memory pair and OS; units are normalized exactly'))
        if cpu in (8192, 16384, 32768):
            results.append(ctx.finding('ECS_FARGATE_SIZE_PLATFORM', '/properties/Cpu', 'NEEDS_REVIEW',
                'this size additionally requires Linux platform 1.4.0 or later; task definition alone does not identify the launch platform version'))
    elif not isinstance(compat, list) or any(not isinstance(v, str) for v in compat):
        if cpu_raw is not ABSENT or memory_raw is not ABSENT:
            results.append(ctx.finding('ECS_FARGATE_TASK_SIZE', '/properties/RequiresCompatibilities', 'NEEDS_REVIEW',
                'launch compatibility is unresolved; task sizes cannot be classified as Fargate'))
    if isinstance(compat, list) and any(v in ('EC2', 'EXTERNAL') for v in compat) and cpu_raw is not ABSENT:
        windows = isinstance(os, str) and os.startswith('WINDOWS_')
        verdict = ('NEEDS_REVIEW' if cpu is None or windows else 'FAIL' if not 128 <= cpu <= 196608 else
                   'NEEDS_REVIEW' if cpu < 256 else 'PASS')
        results.append(ctx.finding('ECS_EC2_TASK_CPU_RANGE', '/properties/Cpu', verdict,
            'API range is 128..196608 units; 128..255 is held for conflicting troubleshooting minimum and Windows runtime semantics require review'))
    results.extend(container_totals(ctx, resource, cpu, memory, compat, os))
    return results


def container_totals(ctx, resource, cpu, memory, compat, os):
    if isinstance(os, str) and os.startswith('WINDOWS_'):
        return []  # Collective task limits are not enforced for Windows.
    root = '/properties/ContainerDefinitions'
    containers = value(ctx, resource, root)
    results = []
    for kind, limit in [('Cpu', cpu), ('Memory', memory)]:
        if limit is None:
            continue
        if kind == 'Cpu' and not (isinstance(compat, list) and 'FARGATE' in compat):
            continue
        total, pending = 0, not isinstance(containers, list) or os not in (ABSENT, 'LINUX')
        for i in range(len(containers) if isinstance(containers, list) else 0):
            base = root + f'/{i}'
            amount = value(ctx, resource, base + '/' + kind)
            if kind == 'Memory':
                reservation = value(ctx, resource, base + '/MemoryReservation')
                if reservation is not ABSENT:
                    amount = reservation
            if kind == 'Cpu' and amount is ABSENT:
                amount = 0
            if type(amount) is int and amount >= 0:
                total += amount
            else:
                pending = True
        verdict = 'FAIL' if total > limit else 'NEEDS_REVIEW' if pending or total == limit else 'PASS'
        results.append(ctx.finding('ECS_TASK_CONTAINER_' + kind.upper() + '_TOTAL', root, verdict,
            'known reservations must fit the task limit; memoryReservation takes precedence over memory; equality and unresolved allocations remain under review'))
    return results
