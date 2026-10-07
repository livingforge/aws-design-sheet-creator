"""Canary literal rate intervals and explicit timeout comparisons."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={r:[CF+'aws-properties-synthetics-canary-'+p+'.html' for p in ('schedule','runconfig')] for r in ('SYNTHETICS_RATE_INTERVAL','SYNTHETICS_TIMEOUT_INTERVAL')}


def interval(raw):
    if not literal(raw):return None
    m=re.fullmatch(r'rate\((0|[1-9][0-9]{0,5}) (minute|minutes|hour)\)',raw)
    if not m:return None
    number=int(m[1]);unit=m[2]
    if number in (0,1) and unit=='minutes':return None
    if number>1 and unit=='minute':return None
    return number*(3600 if unit=='hour' else 60)


@resource_check('AWS::Synthetics::Canary')
def evaluate_synthetics_canary_rate(design,resource):
    if resource.type!='AWS::Synthetics::Canary':return []
    ctx=_Context(design,resource);out=[]
    path='/properties/Schedule/Expression';duration=interval(value(ctx,resource,path)) if resolved(resource) else None
    bound='NEEDS_REVIEW' if duration is None else 'PASS' if duration==0 or 60<=duration<=3600 else 'FAIL'
    timeout=value(ctx,resource,'/properties/RunConfig/TimeoutInSeconds')
    verdict='NEEDS_REVIEW'
    if duration==0:verdict='NOT_APPLICABLE'
    elif duration is not None and 60<=duration<=3600 and type(timeout) is int and timeout>=0:verdict='PASS' if timeout<=duration else 'FAIL'
    elif timeout is ABSENT and duration is not None and 60<=duration<=3600:verdict='NOT_APPLICABLE'
    for rule,at,result in [('SYNTHETICS_RATE_INTERVAL',path,bound),('SYNTHETICS_TIMEOUT_INTERVAL','/properties/RunConfig/TimeoutInSeconds',verdict)]:
        f=ctx.finding(rule,at,result,'Canonical literal rate intervals must be 1 minute through 1 hour, or the documented zero single-run forms. Explicit timeout must not exceed a positive valid interval. Cron, noncanonical grammar, substitutions and unknown values remain reviewable; omitted timeout uses the service default and zero rates have no recurring interval. Timeout absolute bounds and the cron maximum-wait condition are separate.')
        f['source_checked_at']='2026-10-04';out.append(f)
    return out
