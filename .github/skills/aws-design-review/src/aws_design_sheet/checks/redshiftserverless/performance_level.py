"""Checks for AWS::RedshiftServerless::Workgroup."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT

SOURCES = {
    'REDSHIFT_SERVERLESS_PERFORMANCE_LEVEL': ['https://docs.aws.amazon.com/redshift-serverless/latest/APIReference/API_PerformanceTarget.html'],
}


@resource_check('AWS::RedshiftServerless::Workgroup')
def evaluate_redshiftserverless_performance_level(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    if resource.type=='AWS::RedshiftServerless::Workgroup':
        path='/properties/PricePerformanceTarget/Level';raw=value(ctx,resource,path)
        if raw is not ABSENT:
            verdict='NEEDS_REVIEW' if type(raw) is not int else 'PASS' if raw in (1,25,50,75,100) else 'FAIL'
            emit('REDSHIFT_SERVERLESS_PERFORMANCE_LEVEL',path,verdict,'explicit integer level must be one of five documented values; omitted defaults, unknown level, status applicability and runtime performance remain held')
    return results
