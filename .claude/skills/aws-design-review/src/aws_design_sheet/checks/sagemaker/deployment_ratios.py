"""Checks for AWS::SageMaker::InferenceComponent, AWS::SageMaker::MonitoringSchedule."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'SAGEMAKER_COMPONENT_BATCH_RATIO': [CF+'aws-properties-sagemaker-inferencecomponent-inferencecomponentrollingupdatepolicy.html',CF+'aws-properties-sagemaker-inferencecomponent-inferencecomponentcapacitysize.html',CF+'aws-properties-sagemaker-inferencecomponent-inferencecomponentruntimeconfig.html'],
    'SAGEMAKER_MONITORING_WINDOW': [CF+'aws-properties-sagemaker-monitoringschedule-scheduleconfig.html'],
}


def offset_seconds(raw):
    """Only fixed, integer day/hour/minute/second ISO durations, within schema size."""
    if not isinstance(raw,str) or len(raw)>15:return None
    match=re.fullmatch(r'(-?)P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?',raw,re.ASCII)
    if not match or not any(match.group(i) for i in range(2,6)) or raw.endswith('T'):return None
    total=sum(int(match.group(i) or 0)*factor for i,factor in zip(range(2,6),(86400,3600,60,1)))
    return -total if match.group(1) else total


@resource_check('AWS::SageMaker::InferenceComponent', 'AWS::SageMaker::MonitoringSchedule')
def evaluate_sagemaker_deployment_ratios(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::SageMaker::InferenceComponent':
        path='/properties/DeploymentConfig/RollingUpdatePolicy/MaximumBatchSize'
        if get(path) is not ABSENT:
            kind=get(path+'/Type');size=get(path+'/Value');copies=get('/properties/RuntimeConfig/CopyCount');verdict='NEEDS_REVIEW'
            if type(size) is int:
                if kind=='CAPACITY_PERCENT':verdict='PASS' if 5<=size<=50 else 'FAIL'
                elif kind=='COPY_COUNT' and type(copies) is int and copies>0:
                    snapshots=[get('/properties/RuntimeConfig/'+k) for k in ('CurrentCopyCount','DesiredCopyCount')]
                    if all(n is ABSENT or type(n) is int and n==copies for n in snapshots):
                        verdict='PASS' if 5*copies<=100*size<=50*copies else 'FAIL'
            emit('SAGEMAKER_COMPONENT_BATCH_RATIO',path,verdict,'MaximumBatchSize must be 5-50 percent of explicit positive CopyCount, or direct CAPACITY_PERCENT; no runtime count or rounding inferred; zero/unknown/conflicting counts and rollback sizing remain separate')
    if resource.type=='AWS::SageMaker::MonitoringSchedule':
        path='/properties/MonitoringScheduleConfig/ScheduleConfig';start=get(path+'/DataAnalysisStartTime');end=get(path+'/DataAnalysisEndTime')
        if start is not ABSENT or end is not ABSENT:
            a=offset_seconds(start);b=offset_seconds(end);verdict='NEEDS_REVIEW'
            if a is not None and b is not None and b>a:verdict='PASS' if b-a<=86400 else 'FAIL'
            emit('SAGEMAKER_MONITORING_WINDOW',path,verdict,'explicit fixed ISO duration offsets may span at most 24 hours; calendar/fractional/unknown offsets, missing endpoints and equal/reversed windows remain under review; NOW requiredness is separate')
    return results
