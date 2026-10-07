from pathlib import Path
import pytest
from aws_design_sheet.checks.route53resolver.endpoint_enums import evaluate_route53resolver_endpoint_enums
from aws_design_sheet.checks.s3tables.table_name_characters import evaluate_s3tables_table_name_characters
from aws_design_sheet.checks.pinpoint.gcm_auth_method import evaluate_pinpoint_gcm_auth_method
from aws_design_sheet.checks.registry import combine
resolver_values_checks = combine(evaluate_route53resolver_endpoint_enums, evaluate_s3tables_table_name_characters, evaluate_pinpoint_gcm_auth_method)
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('raw,verdict',[(s,'PASS') for s in ('INBOUND','OUTBOUND','INBOUND_DELEGATION')]+[('Outbound','FAIL'),('OTHER','FAIL'),(UNKNOWN,'NEEDS_REVIEW'),('${direction}','NEEDS_REVIEW')])
def test_direction(raw,verdict):
 r=target('main','AWS::Route53Resolver::ResolverEndpoint',Direction=raw)
 assert resolver_values_checks(linked_design(r),r)[0]['verdict']==verdict


@pytest.mark.parametrize('raw,verdict',[(s,'PASS') for s in ('Do53','DoH','DoH-FIPS')]+[('DNS','FAIL'),('doh','FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_protocol(raw,verdict):
 r=target('main','AWS::Route53Resolver::ResolverEndpoint',Protocols=[raw])
 assert resolver_values_checks(linked_design(r),r)[0]['verdict']==verdict


@pytest.mark.parametrize('raw,verdict',[('table_01','PASS'),('123','PASS'),('UPPER','FAIL'),('with-hyphen','FAIL'),('a\n','FAIL'),('é','FAIL'),(UNKNOWN,'NEEDS_REVIEW'),('${table}','NEEDS_REVIEW')])
def test_table(raw,verdict):
 r=target('main','AWS::S3Tables::Table',TableName=raw)
 assert resolver_values_checks(linked_design(r),r)[0]['verdict']==verdict


@pytest.mark.parametrize('raw,verdict',[('KEY','PASS'),('TOKEN','PASS'),('key','FAIL'),('OTHER','FAIL'),(UNKNOWN,'NEEDS_REVIEW'),('${method}','NEEDS_REVIEW')])
def test_gcm(raw,verdict):
 r=target('main','AWS::Pinpoint::GCMChannel',DefaultAuthenticationMethod=raw)
 assert resolver_values_checks(linked_design(r),r)[0]['verdict']==verdict


@pytest.mark.parametrize('kind',['AWS::Route53Resolver::ResolverEndpoint','AWS::S3Tables::Table','AWS::Pinpoint::GCMChannel'])
def test_absent(kind):
 r=target('main',kind);assert not resolver_values_checks(linked_design(r),r)


def test_unknown_protocol_list():
 r=target('main','AWS::Route53Resolver::ResolverEndpoint',Protocols=UNKNOWN)
 assert resolver_values_checks(linked_design(r),r)[0]['verdict']=='NEEDS_REVIEW'


def test_checker():
 r=target('main','AWS::S3Tables::Table',TableName='UPPER')
 root=Path(__file__).resolve().parents[1]
 results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
 assert any(f['rule_id']=='S3TABLES_TABLE_NAME_CHARACTERS' and f['verdict']=='FAIL' for f in results)
