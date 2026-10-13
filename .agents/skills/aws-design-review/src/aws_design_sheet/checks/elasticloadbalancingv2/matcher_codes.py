"""Literal matcher code intervals; load-balancer-specific scope is separate."""
import re
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT

SOURCES={'ELBV2_MATCHER_CODE_RANGE':['https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_Matcher.html']}


def matcher_codes(design,resource):
    ctx=_Context(design,resource)
    results=[]
    for key,minimum,maximum in [('GrpcCode',0,99),('HttpCode',200,599)]:
        path='/properties/Matcher/'+key
        raw=value(ctx,resource,path)
        if raw is ABSENT:continue
        verdict='NEEDS_REVIEW'
        if isinstance(raw,str) and len(raw)<=4096 and re.fullmatch(r'[0-9]{1,4}(?:-[0-9]{1,4})?(?:,[0-9]{1,4}(?:-[0-9]{1,4})?)*',raw):
            intervals=[list(map(int,part.split('-'))) for part in raw.split(',')]
            valid=all(minimum<=pair[0]<=pair[-1]<=maximum for pair in intervals)
            verdict='PASS' if valid else 'FAIL'
        results.append(ctx.finding('ELBV2_MATCHER_CODE_RANGE',path,verdict,
            'checks gRPC 0..99 or the outer HTTP 200..599 bounds for literal codes/ranges; ALB 200..499, gateway exact matcher, protocol applicability and unsupported syntax require separate review'))
    return results
