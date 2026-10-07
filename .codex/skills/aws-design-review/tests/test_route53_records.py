import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


def record(id, **props):
    return target(id,'AWS::Route53::RecordSet',**({'HostedZoneId':'Z123','Name':'www.example.com','Type':'A'}|props))


def verdict(main, others, rule='ROUTE53_ROUTING_POLICY_CONFLICT'):
    return next(r['verdict'] for r in run_resource_checks(linked_design(main,others),main) if r['rule_id']==rule)


@pytest.mark.parametrize('props,other,expected',[
    ({'Weight':1},{'Region':'us-east-1'},'FAIL'),
    ({'Failover':'PRIMARY'},{'GeoLocation':{'CountryCode':'JP'}},'FAIL'),
    ({'Region':'us-east-1'},{},'FAIL'),
    ({'GeoLocation':{'CountryCode':'JP'}},{'MultiValueAnswer':True},'FAIL'),
    ({'Weight':1},{},'NEEDS_REVIEW'),
    ({'Weight':1},{'Weight':2},'NEEDS_REVIEW'),
    ({'Region':'us-east-1'},{'Region':UNKNOWN},'NEEDS_REVIEW'),
    ({'Region':'us-east-1'},{'Weight':UNKNOWN},'NEEDS_REVIEW'),
])
def test_policy_pairs(props,other,expected):
    assert verdict(record('a',**props),[record('b',**other)])==expected


@pytest.mark.parametrize('change',['zone','type','name','account','unresolved-zone','escaped-name','unknown-account'])
def test_uncertain_or_distinct_identity(change):
    a=record('a',Weight=1);b=record('b',Region='us-east-1')
    if change=='account':b.scope.account='222222222222'
    elif change=='unknown-account':a.scope.account=b.scope.account='unknown'
    else:
        prop,raw={'zone':('HostedZoneId','Z456'),'type':('Type','AAAA'),'name':('Name','other.example.com'),'unresolved-zone':('HostedZoneId',UNKNOWN),'escaped-name':('Name',r'www\056example.com')}[change]
        b.field('/properties/'+prop).selected().value=raw
    assert verdict(a,[b])=='NEEDS_REVIEW'


@pytest.mark.parametrize('a,b,expected',[('60',60,'NEEDS_REVIEW'),('060','60','NEEDS_REVIEW'),('60','120','FAIL'),(UNKNOWN,'60','NEEDS_REVIEW'),(True,'60','NEEDS_REVIEW')])
def test_weighted_ttls(a,b,expected):
    assert verdict(record('a',Weight=0,TTL=a),[record('b',Weight=10,TTL=b)],'ROUTE53_WEIGHTED_TTL_MATCH')==expected


def test_group_root_zone_and_dns_normalization():
    main=target('records','AWS::Route53::RecordSetGroup',HostedZoneId='Z123',RecordSets=[
        {'Name':'WWW.example.com.','Type':'A','Weight':0},
        {'Name':'www.example.com','Type':'A','Region':'us-east-1'}])
    rows=run_resource_checks(linked_design(main),main)
    assert [r['verdict'] for r in rows if r['rule_id']=='ROUTE53_ROUTING_POLICY_CONFLICT']==['FAIL','FAIL']


def test_linked_zone_identity():
    a=record('a',Weight=1,HostedZoneId={'Ref':'zone'})
    b=record('b',Region='us-east-1',HostedZoneId={'Ref':'zone'})
    zone=target('zone','AWS::Route53::HostedZone')
    data=linked_design(a,[b,zone],[('HostedZoneId','zone')])
    from aws_design_sheet.models import Relation
    data.relations.append(Relation(id='other-zone',source_resource_id='b',source_path='/properties/HostedZoneId',target_resource_id='zone',evidence_ids=['e1']))
    assert next(r['verdict'] for r in run_resource_checks(data,a) if r['rule_id']=='ROUTE53_ROUTING_POLICY_CONFLICT')=='FAIL'
    data.relations[-1].condition='optional'
    assert next(r['verdict'] for r in run_resource_checks(data,a) if r['rule_id']=='ROUTE53_ROUTING_POLICY_CONFLICT')=='NEEDS_REVIEW'
