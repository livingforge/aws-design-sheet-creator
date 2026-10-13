"""Checks for AWS::EMRContainers::Endpoint."""
import re
from fractions import Fraction
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'EMRCONTAINERS_LOG_ROTATION_SIZE': [CF+'aws-properties-emrcontainers-endpoint-containerlogrotationconfiguration.html'],
}


def rotation_size(raw):
    if not literal(raw) or len(raw)>12:
        return 'NEEDS_REVIEW'
    match = re.fullmatch(r'([0-9]+(?:\.[0-9]+)?)([KMG])[Bb]?',raw)
    if not match:
        return 'NEEDS_REVIEW'
    amount = Fraction(match[1])
    exponent = {'K':1,'M':2,'G':3}[match[2]]
    # Only prove results that agree under decimal and binary unit conventions.
    decisions = [2*base <= amount*base**exponent <= 2*base**3 for base in (1000,1024)]
    return 'PASS' if all(decisions) else 'FAIL' if not any(decisions) else 'NEEDS_REVIEW'


@resource_check('AWS::EMRContainers::Endpoint')
def evaluate_emrcontainers_log_rotation_size(design,resource):
    ctx = _Context(design,resource)
    results = []
    def emit(rule,path,verdict,reason):
        finding = ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at'] = '2026-10-04'
        results.append(finding)
    if resource.type == 'AWS::EMRContainers::Endpoint':
        path = '/properties/ConfigurationOverrides/MonitoringConfiguration/ContainerLogRotationConfiguration/RotationSize'
        raw = value(ctx,resource,path)
        if raw is not ABSENT:
            emit('EMRCONTAINERS_LOG_ROTATION_SIZE',path,rotation_size(raw),'bounded exact decimal parsing; 2KB through 2GB only where decimal/binary unit conventions agree; ambiguous boundaries, unsupported syntax and unresolved inputs remain held')
    return results
