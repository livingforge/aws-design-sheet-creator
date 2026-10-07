"""Availability zones of explicitly declared subnets."""
import re
from .context_values import linked, value
from .field_reads import ABSENT, read
from .literals import literal
from .scoped_resolution import resolved


def explicit(ctx,r,path,kind):
    if not resolved(r):return None
    other=linked(ctx,r,path,kind)
    raw=read(ctx,r,path)
    return other if resolved(other) and (raw is ABSENT or literal(raw)) else None


def zones(ctx,subnets):
    if len(subnets)!=2 or any(s is None for s in subnets):return 'NEEDS_REVIEW'
    a,b=subnets
    if a.id==b.id:return 'FAIL'
    answers=[]
    for prop,pattern in [('AvailabilityZone',re.escape(a.scope.region)+r'[a-z]'),('AvailabilityZoneId',r'[a-z0-9]+-az[0-9]+')]:
        x,y=(value(ctx,s,'/properties/'+prop) for s in subnets)
        if all(literal(v) and re.fullmatch(pattern,v) for v in (x,y)):answers.append(x!=y)
    if not answers or any(v!=answers[0] for v in answers):return 'NEEDS_REVIEW'
    return 'PASS' if answers[0] else 'FAIL'
