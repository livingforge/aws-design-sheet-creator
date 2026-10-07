"""Endpoint configuration limits published outside the pinned property schema."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.literals import expand
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={r:[CF+'aws-resource-sagemaker-endpointconfig.html']+[CF+'aws-properties-sagemaker-endpointconfig-'+p+'.html' for p in ('productionvariant','serverlessconfig','datacaptureconfig','vpcconfig')] for r in ('SAGEMAKER_ENDPOINT_ARRAY_BOUNDS','SAGEMAKER_ENDPOINT_SERVERLESS_BOUNDS')}
ARRAYS=[('ProductionVariants',1,10),('ShadowProductionVariants',1,10),('DataCaptureConfig/CaptureOptions',1,32),('VpcConfig/SecurityGroupIds',1,5),('VpcConfig/Subnets',1,16),('Tags',0,50)]+[(root+'/*/InstancePools',1,5) for root in ('ProductionVariants','ShadowProductionVariants')]
NUMBERS=[(root+'/*/ServerlessConfig/'+key,low,high) for root in ('ProductionVariants','ShadowProductionVariants') for key,low,high in [('MaxConcurrency',1,200),('ProvisionedConcurrency',1,200),('MemorySizeInMB',1024,6144)]]


@resource_check('AWS::SageMaker::EndpointConfig')
def evaluate_sagemaker_bounds(design,resource):
    if resource.type!='AWS::SageMaker::EndpointConfig':return []
    ctx=_Context(design,resource);out=[];seen=set()
    for rule,specs in [('SAGEMAKER_ENDPOINT_ARRAY_BOUNDS',ARRAYS),('SAGEMAKER_ENDPOINT_SERVERLESS_BOUNDS',NUMBERS)]:
        for suffix,low,high in specs:
            pattern='/properties/'+suffix
            for path in expand(ctx,resource,pattern):
                if (rule,path) in seen:continue
                seen.add((rule,path));raw=value(ctx,resource,path)
                exact=re.fullmatch(re.escape(pattern).replace(r'\*',r'\d+'),path)
                known=resolved(resource) and exact and (isinstance(raw,list) if specs is ARRAYS else type(raw) is int)
                size=len(raw) if specs is ARRAYS and isinstance(raw,list) else raw
                verdict=('PASS' if low<=size<=high else 'FAIL') if known else 'NEEDS_REVIEW'
                f=ctx.finding(rule,path,verdict,f'The documented {"array length" if specs is ARRAYS else "integer value"} is between {low} and {high}. Unknown ancestors and conditional input remain reviewable. This checks the bound only; item contents, instance-type catalog, discrete memory sizes, shadow-mode cardinality and cross-property requirements are separate.')
                f['source_checked_at']='2026-10-04';out.append(f)
    return out
