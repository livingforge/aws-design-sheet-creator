"""Checks for AWS::SageMaker::ModelPackage."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.literals import expand, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'SAGEMAKER_PACKAGE_ENV_COUNT': [CF+'aws-properties-sagemaker-modelpackage-modelpackagecontainerdefinition.html',CF+'aws-properties-sagemaker-modelpackage-transformjobdefinition.html'],
}


@resource_check('AWS::SageMaker::ModelPackage')
def evaluate_sagemaker_package_env_count(design,resource):
 ctx=_Context(design,resource);results=[]
 def get(p):return value(ctx,resource,p)
 def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
 if resource.type=='AWS::SageMaker::ModelPackage':
  patterns=('/properties/InferenceSpecification/Containers/*/Environment','/properties/AdditionalInferenceSpecifications/*/Containers/*/Environment','/properties/ValidationSpecification/ValidationProfiles/*/TransformJobDefinition/Environment')
  for pattern in patterns:
   for p in expand(ctx,resource,pattern):
    raw=get(p);v='NEEDS_REVIEW' if not isinstance(raw,dict) or any(not literal(k) for k in raw) else 'PASS' if len(raw)<=16 else 'FAIL'
    emit('SAGEMAKER_PACKAGE_ENV_COUNT',p,v,'explicit environment map permits at most sixteen keys; values and update-only AdditionalInferenceSpecificationsToAdd remain separate')
 return results
