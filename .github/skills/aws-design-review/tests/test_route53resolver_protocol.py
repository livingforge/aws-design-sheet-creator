import pytest
from aws_design_sheet.checks.route53resolver.protocol import evaluate_route53resolver_protocol
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_template_dependencies import link


def fixture(targets=None,supported=None,direction='OUTBOUND'):
    r=target('rule','AWS::Route53Resolver::ResolverRule',TargetIps=[{'Protocol':p} for p in (targets or ['Do53'])])
    e=target('endpoint','AWS::Route53Resolver::ResolverEndpoint',Direction=direction,**({} if supported is None else {'Protocols':supported}))
    d=linked_design(r,[e]);link(d,r,'ResolverEndpointId',e)
    return d,r,e


def verdict(d,r):return evaluate_route53resolver_protocol(d,r)[0]['verdict']


@pytest.mark.parametrize('targets,supported,want',[
    (['Do53'],None,'PASS'),(['DoH'],None,'FAIL'),(['DoH'],['DoH'],'PASS'),
    (['Do53','DoH'],['Do53','DoH'],'PASS'),(['Do53','DoH'],['Do53'],'FAIL'),
    ([UNKNOWN],['Do53'],'NEEDS_REVIEW'),(['Do53'],[UNKNOWN],'NEEDS_REVIEW'),
    (['Do53'],[],'NEEDS_REVIEW'),(['Do53'],['DoH-FIPS'],'NEEDS_REVIEW')])
def test_protocol_support(targets,supported,want):
    d,r,*_=fixture(targets,supported);assert verdict(d,r)==want


@pytest.mark.parametrize('direction,want',[('INBOUND','FAIL'),('INBOUND_DELEGATION','FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_outbound_required(direction,want):
    d,r,*_=fixture(direction=direction);assert verdict(d,r)==want


@pytest.mark.parametrize('mode',['literal','conditional','missing','scope','omitted_target','unknown_targets'])
def test_unknown_evidence(mode):
    d,r,e=fixture()
    if mode=='literal':r.fields+=target('dummy',r.type,ResolverEndpointId='rslvr-out-1234').fields
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='missing':d.resources.remove(e)
    if mode=='scope':e.scope.region='us-east-1'
    if mode=='omitted_target':r.fields[0].candidates[0].value=[{}]
    if mode=='unknown_targets':r.fields[0].candidates[0].value=UNKNOWN
    assert verdict(d,r)=='NEEDS_REVIEW'


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    d,r,*_=fixture();root=Path(__file__).resolve().parents[1]
    results=Checker(root/"schemas",root/"profiles/vpc-subnet.json").check(d)["results"]
    assert any(f["rule_id"]=="RESOLVER_RULE_ENDPOINT_PROTOCOL" and f["verdict"]=="PASS" for f in results)
