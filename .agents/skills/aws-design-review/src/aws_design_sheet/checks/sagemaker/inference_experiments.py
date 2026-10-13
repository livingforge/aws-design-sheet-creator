"""Checks for AWS::SageMaker::Endpoint, AWS::SageMaker::InferenceExperiment."""
import re
from datetime import datetime, timedelta, timezone
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'SAGEMAKER_EXPERIMENT_DURATION': [CF+'aws-properties-sagemaker-inferenceexperiment-inferenceexperimentschedule.html'],
    'SAGEMAKER_ROLLBACK_ALARM_COUNT': [CF+'aws-properties-sagemaker-endpoint-autorollbackconfig.html'],
}


def timestamp(raw):
    if not literal(raw) or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})',raw):return None
    try:return datetime.fromisoformat(raw.replace('Z','+00:00')).astimezone(timezone.utc)
    except (ValueError,OverflowError):return None


def duration(ctx,r):
    start=timestamp(value(ctx,r,'/properties/Schedule/StartTime'));end=timestamp(value(ctx,r,'/properties/Schedule/EndTime'))
    if start is None or end is None or end<start:return 'NEEDS_REVIEW'
    return 'FAIL' if end-start>timedelta(days=30) else 'PASS'


@resource_check('AWS::SageMaker::InferenceExperiment', 'AWS::SageMaker::Endpoint')
def evaluate_sagemaker_inference_experiments(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    if resource.type=='AWS::SageMaker::InferenceExperiment' and value(ctx,resource,'/properties/Schedule') is not ABSENT:
        emit('SAGEMAKER_EXPERIMENT_DURATION','/properties/Schedule',duration(ctx,resource),'explicit timezone-aware ISO timestamps span at most 30 days; omitted/default starts, unknown/unsupported timestamps, reversed ordering and lifecycle state remain held')
    if resource.type=='AWS::SageMaker::Endpoint':
        path='/properties/DeploymentConfig/AutoRollbackConfiguration/Alarms';raw=value(ctx,resource,path)
        if raw is not ABSENT:emit('SAGEMAKER_ROLLBACK_ALARM_COUNT',path,'NEEDS_REVIEW' if not isinstance(raw,list) else 'PASS' if 1<=len(raw)<=10 else 'FAIL','explicit rollback alarm list contains 1..10 entries; other endpoint attribute limits, alarm existence and runtime rollback behavior remain held')
    return results
