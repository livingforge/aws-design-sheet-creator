from pathlib import Path
import pytest
from aws_design_sheet.checks.directconnect.ipv6_prefixes import evaluate_directconnect_ipv6_prefixes
from aws_design_sheet.checks.iot.http_confirmation_prefix import evaluate_iot_http_confirmation_prefix
from aws_design_sheet.checks.mediastore.cors_wildcards import evaluate_mediastore_cors_wildcards
from aws_design_sheet.checks.registry import combine
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
finite_strings_checks = combine(evaluate_directconnect_ipv6_prefixes, evaluate_iot_http_confirmation_prefix, evaluate_mediastore_cors_wildcards)

def check(kind,**props):
 r=target('subject','AWS::'+kind,**props)
 return finite_strings_checks(linked_design(r),r)

@pytest.mark.parametrize('kind,key',[('DirectConnectGatewayAssociation','AllowedPrefixesToDirectConnectGateway'),('PublicVirtualInterface','RouteFilterPrefixes')])
@pytest.mark.parametrize('cidr,expected',[('2001:db8::/64','PASS'),('2001:db8::/63','PASS'),('::/0','PASS'),('2001:db8::/65','FAIL'),('::1/128','FAIL'),('10.0.0.0/24','NOT_APPLICABLE'),('2001:db8::1/64','NEEDS_REVIEW'),('bad','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_prefix(kind,key,cidr,expected):
 assert check('DirectConnect::'+kind,**{key:[cidr]})[0]['verdict']==expected

@pytest.mark.parametrize('error',[False,True])
@pytest.mark.parametrize('prefix,url,expected',[('https://a/','https://a/x','PASS'),('https://a/','https://a/','PASS'),('https://a/x','https://a/','FAIL'),('https://a/','https://b/','FAIL'),('https://a/','https://a/${path}','NEEDS_REVIEW'),(UNKNOWN,'https://a/','NEEDS_REVIEW')])
def test_http(error,prefix,url,expected):
 action={'Http':{'ConfirmationUrl':prefix,'Url':url}}
 payload={'ErrorAction':action} if error else {'Actions':[action]}
 assert check('IoT::TopicRule',TopicRulePayload=payload)[0]['verdict']==expected

@pytest.mark.parametrize('key',['AllowedOrigins','AllowedHeaders'])
@pytest.mark.parametrize('raw,expected',[('*','PASS'),('https://*.example','PASS'),('a','PASS'),('**','FAIL'),('*a*','FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_cors(key,raw,expected):
 assert check('MediaStore::Container',CorsPolicy=[{key:[raw]}])[0]['verdict']==expected

def test_checker():
 from aws_design_sheet.checker import Checker
 root=Path(__file__).resolve().parents[1]
 r=target('subject','AWS::DirectConnect::PublicVirtualInterface',RouteFilterPrefixes=['2001:db8::/65'])
 row=next(x for x in Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results'] if x['rule_id']=='DIRECTCONNECT_PUBLIC_IPV6_PREFIX')
 assert row['verdict']=='FAIL' and row['source_urls'] and row['evidence_ids']
