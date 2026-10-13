"""Checks for AWS::Cognito::UserPool."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'COGNITO_PRETOKEN_EQUAL': [CF+'aws-properties-cognito-userpool-lambdaconfig.html'],
}


@resource_check('AWS::Cognito::UserPool')
def evaluate_cognito_pretoken_equal(design,resource):
 ctx=_Context(design,resource);results=[]
 def get(p):return value(ctx,resource,p)
 def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
 if resource.type=='AWS::Cognito::UserPool':
  p='/properties/LambdaConfig/PreTokenGeneration';a=get(p);b=get('/properties/LambdaConfig/PreTokenGenerationConfig/LambdaArn')
  if a is not ABSENT or b is not ABSENT:
   v='NOT_APPLICABLE' if a is ABSENT or b is ABSENT else 'PASS' if literal(a) and literal(b) and a==b else 'FAIL' if literal(a) and literal(b) else 'NEEDS_REVIEW'
   emit('COGNITO_PRETOKEN_EQUAL',p,v,'when both ARN properties are set their explicit text must be identical; unresolved references and external function behavior remain held')
 return results
