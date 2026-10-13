"""Checks for AWS::MediaStore::Container."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.literals import expand, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'MEDIASTORE_CORS_WILDCARDS': [CF+'aws-properties-mediastore-container-corsrule.html'],
}


@resource_check('AWS::MediaStore::Container')
def evaluate_mediastore_cors_wildcards(design,resource):
 ctx=_Context(design,resource);results=[]
 def get(p):return value(ctx,resource,p)
 def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
 if resource.type=='AWS::MediaStore::Container':
  for key in ('AllowedOrigins','AllowedHeaders'):
   for p in expand(ctx,resource,'/properties/CorsPolicy/*/'+key+'/*'):
    raw=get(p);v='NEEDS_REVIEW' if not literal(raw) else 'FAIL' if raw.count('*')>1 else 'PASS'
    emit('MEDIASTORE_CORS_WILDCARDS',p,v,'each explicit origin/header string has at most one wildcard; unknown values and overall CORS semantics remain separate')
 return results
