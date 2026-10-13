"""Checks for AWS::Lambda::Function."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.required_values import uncertain

SOURCES = {
    'LAMBDA_SNAPSTART_LOCAL_COMPATIBILITY': ['https://docs.aws.amazon.com/lambda/latest/dg/snapstart.html'],
}


@resource_check('AWS::Lambda::Function')
def evaluate_lambda_snapstart_compatibility(design, resource):
    ctx = _Context(design, resource)
    root = '/properties/'
    snap = value(ctx, resource, root + 'SnapStart/ApplyOn')
    if snap is ABSENT or snap == 'None':
        return []
    rule = 'LAMBDA_SNAPSTART_LOCAL_COMPATIBILITY'
    reason = 'documented SnapStart feature support as of 2026-10-03; image contents, published versions, concurrency and external role capabilities require review'
    rows = []
    runtime = value(ctx, resource, root + 'Runtime')
    ephemeral = value(ctx, resource, root + 'EphemeralStorage/Size')
    file_systems = value(ctx, resource, root + 'FileSystemConfigs')
    for name, v in [('Runtime', runtime), ('EphemeralStorage/Size', ephemeral), ('FileSystemConfigs', file_systems)]:
        verdict = 'NEEDS_REVIEW'
        if snap == 'PublishedVersions':
            if name == 'Runtime' and isinstance(v, str) and not uncertain(v):
                match = re.fullmatch(r'(java|python3\.|dotnet)(\d{1,3})', v)
                if match:
                    minimum = {'java': 11, 'python3.': 12, 'dotnet': 8}[match[1]]
                    verdict = 'PASS' if int(match[2]) >= minimum else 'FAIL'
                elif v.startswith(('nodejs', 'ruby', 'provided', 'python', 'dotnet', 'java', 'go')):
                    verdict = 'FAIL'
            elif name == 'EphemeralStorage/Size':
                if v is ABSENT:
                    verdict = 'PASS'
                elif type(v) is int:
                    verdict = 'PASS' if v <= 512 else 'FAIL'
            elif name == 'FileSystemConfigs':
                if v is ABSENT or v == []:
                    verdict = 'PASS'
                elif isinstance(v, list) and any(isinstance(item, dict) and
                        '$state' not in item and '$ref' not in item for item in v):
                    verdict = 'FAIL'
        rows.append({**ctx.finding(rule, root + name, verdict, reason), 'severity': 'WARNING'})
    return rows
