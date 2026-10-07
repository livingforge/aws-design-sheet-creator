"""Checks for AWS::SageMaker::EndpointConfig, AWS::SageMaker::TrialComponent."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal
from ..common.numbers import number
from ..common.string_lists import strings

SOURCES = {
    'SAGEMAKER_CLARIFY_TEXT_FEATURE': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-sagemaker-endpointconfig-clarifyinferenceconfig.html',
    ],
    'SAGEMAKER_TRIAL_PARAMETER_UNION': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-sagemaker-trialcomponent-trialcomponentparametervalue.html',
    ],
}


@resource_check('AWS::SageMaker::EndpointConfig','AWS::SageMaker::TrialComponent')
def evaluate_sagemaker_clarify_and_trial(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::SageMaker::EndpointConfig':
        path='/properties/ExplainerConfig/ClarifyExplainerConfig/InferenceConfig/FeatureTypes'
        if get(path) is not ABSENT:
            names,pending=strings(ctx,resource,path)
            emit('SAGEMAKER_CLARIFY_TEXT_FEATURE',path,'PASS' if 'text' in names else 'NEEDS_REVIEW' if pending else 'FAIL','explicit FeatureTypes must contain the exact text token; unknown members and model applicability remain separate')
    if resource.type=='AWS::SageMaker::TrialComponent':
        path='/properties/Parameters';raw=get(path)
        if raw is not ABSENT:
            pending=not isinstance(raw,dict);invalid=False
            for key in raw if isinstance(raw,dict) else ():
                if not literal(key) or any(c in key for c in '/~') or key.startswith(('Fn::','$')) or key=='Ref':pending=True;continue
                p=path+'/'+key;numeric=get(p+'/NumberValue');string=get(p+'/StringValue')
                n=number(numeric) is not None;s=isinstance(string,str) and '${' not in string and '{{' not in string
                invalid|=n and s
                pending|=(numeric is not ABSENT and not n) or (string is not ABSENT and not s) or numeric is ABSENT and string is ABSENT
            emit('SAGEMAKER_TRIAL_PARAMETER_UNION',path,'FAIL' if invalid else 'NEEDS_REVIEW' if pending else 'PASS','NumberValue and StringValue cannot both be specified in one parameter; empty objects, escaped map keys and unknown values remain under review')
    return results
