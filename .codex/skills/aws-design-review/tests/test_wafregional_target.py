import pytest
from aws_design_sheet.checks.waf.wafregional_target import evaluate_waf_wafregional_target
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_template_dependencies import link


@pytest.mark.parametrize('kind,props,want',[
    ('AWS::ApiGateway::Stage',{},'PASS'),('AWS::ApiGatewayV2::Stage',{},'FAIL'),
    ('AWS::ElasticLoadBalancingV2::LoadBalancer',{'Type':'application'},'PASS'),
    ('AWS::ElasticLoadBalancingV2::LoadBalancer',{'Type':'network'},'FAIL'),
    ('AWS::ElasticLoadBalancingV2::LoadBalancer',{'Type':'gateway'},'FAIL'),
    ('AWS::ElasticLoadBalancingV2::LoadBalancer',{},'NEEDS_REVIEW')])
def test_linked_target(kind,props,want):
    r=target('assoc','AWS::WAFRegional::WebACLAssociation');o=target('target',kind,**props)
    d=linked_design(r,[o]);link(d,r,'ResourceArn',o)
    assert evaluate_waf_wafregional_target(d,r)[0]['verdict']==want


@pytest.mark.parametrize('arn,want',[
    ('arn:aws:elasticloadbalancing:ap-northeast-1:111111111111:loadbalancer/app/name/123','PASS'),
    ('arn:aws:elasticloadbalancing:ap-northeast-1:111111111111:loadbalancer/net/name/123','FAIL'),
    ('arn:aws:apigateway:ap-northeast-1::/restapis/abc/stages/prod','PASS'),
    ('arn:aws:apigateway:ap-northeast-1::/apis/abc/stages/prod','FAIL'),
    ('arn:aws:lambda:ap-northeast-1:111111111111:function:name','FAIL'),
    (UNKNOWN,'NEEDS_REVIEW'),('${Arn}','NEEDS_REVIEW')])
def test_literal_target(arn,want):
    r=target('assoc','AWS::WAFRegional::WebACLAssociation',ResourceArn=arn)
    assert evaluate_waf_wafregional_target(linked_design(r),r)[0]['verdict']==want


@pytest.mark.parametrize('case',['conditional','external','duplicate','region','literal'])
def test_uncertain_links(case):
    r=target('assoc','AWS::WAFRegional::WebACLAssociation');o=target('stage','AWS::ApiGateway::Stage')
    d=linked_design(r,[o]);link(d,r,'ResourceArn',o)
    if case=='conditional':d.relations[0].condition='Maybe'
    if case=='external':d.resources.remove(o)
    if case=='duplicate':link(d,r,'ResourceArn',o)
    if case=='region':o.scope.region='us-east-1'
    if case=='literal':r.fields=target('x',r.type,ResourceArn='different-physical-id').fields
    assert evaluate_waf_wafregional_target(d,r)[0]['verdict']=='NEEDS_REVIEW'


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    r=target('assoc','AWS::WAFRegional::WebACLAssociation',ResourceArn='arn:aws:apigateway:ap-northeast-1::/restapis/abc/stages/prod');d=linked_design(r);root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results']
    assert any(f['rule_id']=='WAFREGIONAL_ASSOCIATION_TARGET_KIND' and f['verdict']=='PASS' for f in results)
