"""Checks for AWS::SageMaker::Model."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'SAGEMAKER_PIPELINE_HOSTNAMES': [CF+'aws-properties-sagemaker-model-containerdefinition.html',CF+'aws-properties-sagemaker-model-inferenceexecutionconfig.html'],
}


@resource_check('AWS::SageMaker::Model')
def evaluate_sagemaker_pipeline_hostnames(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::SageMaker::Model':
        path='/properties/Containers';raw=get(path)
        if raw is not ABSENT:
            mode=get('/properties/InferenceExecutionConfig/Mode');verdict='NEEDS_REVIEW'
            if mode=='Serial' and isinstance(raw,list) and raw and get('/properties/PrimaryContainer') is ABSENT:
                present=False;missing=False;pending=False
                for i in range(len(raw)):
                    name=get(path+'/'+str(i)+'/ContainerHostname')
                    if name is ABSENT:missing=True
                    elif literal(name):present=True
                    else:pending=True
                verdict='FAIL' if present and missing else 'NEEDS_REVIEW' if pending else 'PASS'
            emit('SAGEMAKER_PIPELINE_HOSTNAMES',path,verdict,'explicit Serial pipeline must specify ContainerHostname for every container if any has it; PrimaryContainer combinations and unknown/omitted/Direct execution modes remain under review; spelling and uniqueness are separate')
    return results
