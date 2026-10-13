"""Checks for AWS::GreengrassV2::Deployment."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.decimal_places import decimal_places
from ..common.field_reads import ABSENT
from ..common.literals import expand

GG='https://docs.aws.amazon.com/greengrass/v2/APIReference/'
SOURCES = {
    'GREENGRASS_JOB_DECIMAL_PLACES': [GG+'API_IoTJobAbortCriteria.html',GG+'API_IoTJobExponentialRolloutRate.html'],
}


@resource_check('AWS::GreengrassV2::Deployment')
def evaluate_greengrassv2_job_decimal_places(design,resource):
    ctx=_Context(design,resource)
    results=[]
    def emit(rule,path,verdict,reason):
        finding=ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at']='2026-10-04'
        results.append(finding)
    if resource.type=='AWS::GreengrassV2::Deployment':
        base='/properties/IotJobConfiguration'
        paths=[(p,2) for p in expand(ctx,resource,base+'/AbortConfig/CriteriaList/*/ThresholdPercentage')]
        path=base+'/JobExecutionsRolloutConfig/ExponentialRate/IncrementFactor'
        if value(ctx,resource,path) is not ABSENT:paths.append((path,1))
        for path,places in paths:
            emit('GREENGRASS_JOB_DECIMAL_PLACES',path,decimal_places(value(ctx,resource,path),places),'serialized finite numeric value supports at most '+str(places)+' decimal places; trailing zeroes are insignificant; unknown/non-numeric input held and range checks remain separate')
    return results
