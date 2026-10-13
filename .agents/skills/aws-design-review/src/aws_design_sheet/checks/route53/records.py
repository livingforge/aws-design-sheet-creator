"""Proven routing conflicts among explicitly identified DNS record sets."""
import re
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT

URL = 'https://docs.aws.amazon.com/Route53/latest/APIReference/API_ResourceRecordSet.html'
SOURCES = {rule: [URL] for rule in ('ROUTE53_ROUTING_POLICY_CONFLICT', 'ROUTE53_WEIGHTED_TTL_MATCH')}


def records(ctx, resource):
    if resource.type == 'AWS::Route53::RecordSet':
        return ['/properties']
    if resource.type != 'AWS::Route53::RecordSetGroup':
        return []
    items = value(ctx, resource, '/properties/RecordSets')
    return [f'/properties/RecordSets/{i}' for i in range(len(items))] if isinstance(items, list) else []


def zone(ctx, resource, base):
    # Names can identify several public/private zones, so require an ID or link.
    own_id = value(ctx, resource, base + '/HostedZoneId')
    own_name = value(ctx, resource, base + '/HostedZoneName')
    root = '/properties'
    if base != root and own_id is ABSENT and own_name is ABSENT:
        base = root
    elif base != root and (value(ctx, resource, root + '/HostedZoneId') is not ABSENT
                          or value(ctx, resource, root + '/HostedZoneName') is not ABSENT):
        return None
    if value(ctx, resource, base + '/HostedZoneName') is not ABSENT:
        return None
    target = linked(ctx, resource, base + '/HostedZoneId', 'AWS::Route53::HostedZone')
    if target:
        return ('resource', target.id)
    raw = value(ctx, resource, base + '/HostedZoneId')
    return ('id', raw) if isinstance(raw, str) and re.fullmatch(r'Z[A-Z0-9]+', raw) else None


def identity(ctx, resource, base):
    name = value(ctx, resource, base + '/Name')
    kind = value(ctx, resource, base + '/Type')
    hosted = zone(ctx, resource, base)
    if hosted is None or not isinstance(name, str) or not re.fullmatch(r'(?:[A-Za-z0-9_-]+|\*)(?:\.[A-Za-z0-9_-]+)*\.?', name):
        return None
    if not isinstance(kind, str) or kind not in ('SOA','A','TXT','NS','CNAME','MX','NAPTR','PTR','SRV','SPF','AAAA','CAA','DS','TLSA','SSHFP','SVCB','HTTPS'):
        return None
    return hosted, name.rstrip('.').lower(), kind


def routing(ctx, resource, base):
    kinds=[]
    for prop in ('Weight','Region','Failover','GeoLocation','CidrRoutingConfig','GeoProximityLocation'):
        raw=value(ctx,resource,base+'/'+prop)
        if raw is ABSENT:
            continue
        valid = (type(raw) is int and 0 <= raw <= 255 if prop=='Weight' else
                 isinstance(raw,str) and re.fullmatch(r'[a-z]{2}(?:-[a-z]+)+-\d+',raw) is not None if prop=='Region' else
                 raw in ('PRIMARY','SECONDARY') if prop=='Failover' else isinstance(raw,dict) and bool(raw) and not any(k.startswith('Fn::') or k in ('$state','Ref') for k in raw))
        if not valid:return None
        kinds.append(prop)
    multi=value(ctx,resource,base+'/MultiValueAnswer')
    if multi is True:kinds.append('MultiValueAnswer')
    elif multi is not ABSENT and multi is not False:return None
    return set(kinds) if kinds else {'simple'}


def ttl(ctx, resource, base):
    raw=value(ctx,resource,base+'/TTL')
    if isinstance(raw,str) and re.fullmatch(r'[0-9]+',raw) and len(raw)<=10:
        return int(raw) if int(raw)<=2147483647 else None
    return raw if type(raw) is int and 0 <= raw <= 2147483647 else None


def route53_records(design, resource):
    ctx=_Context(design,resource)
    result=[]
    known_scope = bool(re.fullmatch(r'\d{12}', resource.scope.account))
    for base in records(ctx,resource):
        own=identity(ctx,resource,base)
        policy=routing(ctx,resource,base)
        conflicts=bool(policy and len(policy)>1 and policy & {'Region','Failover','GeoLocation'})
        ttl_conflict=False
        own_ttl=ttl(ctx,resource,base)
        for other in design.resources:
            if not known_scope or other.scope!=resource.scope:
                continue
            for other_base in records(ctx,other):
                if other.id==resource.id and base==other_base:continue
                if own is None or identity(ctx,other,other_base)!=own:continue
                other_policy=routing(ctx,other,other_base)
                if policy is not None and other_policy is not None and policy!=other_policy:
                    conflicts |= bool((policy | other_policy) & {'Region','Failover','GeoLocation'})
                other_ttl=ttl(ctx,other,other_base)
                if policy=={'Weight'} and other_policy=={'Weight'} and own_ttl is not None and other_ttl is not None:
                    ttl_conflict |= own_ttl!=other_ttl
        result.append(ctx.finding('ROUTE53_ROUTING_POLICY_CONFLICT',base,'FAIL' if conflicts else 'NEEDS_REVIEW',
            'detects proven latency/failover/geolocation conflicts for an explicit zone, DNS name and type; other policies, escaped names and external records remain unverified'))
        if policy=={'Weight'}:
            result.append(ctx.finding('ROUTE53_WEIGHTED_TTL_MATCH',base+'/TTL','FAIL' if ttl_conflict else 'NEEDS_REVIEW',
                'weighted records with the same explicit zone/name/type require equal TTLs; implicit alias TTLs and external records remain unverified'))
    return result
