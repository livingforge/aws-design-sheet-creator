"""Documented minimum worker keys; do not assume the list is exhaustive."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

SOURCES={'EMRSERVERLESS_WORKER_REQUIRED_KEYS':['https://docs.aws.amazon.com/emr-serverless/latest/APIReference/API_CreateApplication.html','https://docs.aws.amazon.com/emr/latest/EMR-Serverless-UserGuide/application-custom-image.html','https://docs.aws.amazon.com/emr/latest/EMR-Serverless-UserGuide/pre-init-capacity.html']}
KEYS={'Spark':{'Driver','Executor'},'SPARK':{'Driver','Executor'},'Hive':{'HiveDriver','TezTask'},'HIVE':{'HiveDriver','TezTask'}}


@resource_check('AWS::EMRServerless::Application')
def evaluate_emrserverless_worker_keys(design,resource):
    if resource.type!='AWS::EMRServerless::Application':return []
    ctx=_Context(design,resource);path='/properties/WorkerTypeSpecifications';raw=value(ctx,resource,path)
    if raw is ABSENT:return []
    kind=value(ctx,resource,'/properties/Type');expected=KEYS.get(kind) if isinstance(kind,str) else None
    verdict='NEEDS_REVIEW'
    if expected is not None and isinstance(raw,dict) and len(raw)<=1000 and all(literal(k) and not k.startswith('$') for k in raw) and (resource.template is None or resource.template.state.value=='KNOWN'):
        verdict='PASS' if expected.issubset(raw) else 'FAIL'
    return [ctx.finding('EMRSERVERLESS_WORKER_REQUIRED_KEYS',path,verdict,
        'A supplied worker specification map must include the documented Driver/Executor or HiveDriver/TezTask keys. This checks the documented required subset, not an exhaustive enum: additional worker keys are not rejected. Only documented application type spellings are interpreted; unknown/dynamic maps and unconfirmed spellings remain reviewable.')]
