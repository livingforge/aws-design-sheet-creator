from pathlib import Path
import pytest
from aws_design_sheet.checks.cassandra.cql_types import evaluate_cassandra_cql_types, parse_type
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_template_dependencies import link


@pytest.mark.parametrize('raw,expected',[('text','PASS'),('list<text>','FAIL'),('frozen<list<text>>','PASS'),('FROZEN < MAP < text, int > >','PASS'),('frozen<map<text,list<int>>>','NEEDS_REVIEW'),('frozen<map<text,frozen<list<int>>>>','PASS'),('child','FAIL'),('frozen<child>','PASS'),('frozen<unknown>','NEEDS_REVIEW'),('frozen<text>','NEEDS_REVIEW'),('parent','NEEDS_REVIEW'),('frozen<parent>','NEEDS_REVIEW'),('frozen<list>','NEEDS_REVIEW'),('map<text>','NEEDS_REVIEW'),('frozen<"child">','NEEDS_REVIEW'),('ks.child','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_frozen(raw,expected):
    r=target('main','AWS::Cassandra::Type',KeyspaceName='ks',TypeName='parent',Fields=[{'FieldName':'value','FieldType':raw}])
    child=target('child','AWS::Cassandra::Type',KeyspaceName='ks',TypeName='child')
    assert evaluate_cassandra_cql_types(linked_design(r,[child]),r)[0]['verdict']==expected


@pytest.mark.parametrize('case',['linked','external','different','duplicate','conditional','scope'])
def test_type_identity(case):
    r=target('main','AWS::Cassandra::Type',KeyspaceName='ks',TypeName='parent',Fields=[{'FieldName':'x','FieldType':'child'}])
    c=target('child','AWS::Cassandra::Type',KeyspaceName='ks2' if case=='different' else 'ks',TypeName='child');k=target('ks','AWS::Cassandra::Keyspace')
    d=linked_design(r,[c,k])
    if case=='linked':link(d,r,'KeyspaceName',k);link(d,c,'KeyspaceName',k)
    if case=='external':d.resources.remove(c)
    if case=='duplicate':d.resources.append(target('copy','AWS::Cassandra::Type',KeyspaceName='ks',TypeName='child'))
    if case=='conditional':link(d,c,'KeyspaceName',k,'maybe')
    if case=='scope':c.scope.account='222222222222'
    assert evaluate_cassandra_cql_types(d,r)[0]['verdict']==('FAIL' if case=='linked' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('raw',['frozen<'*34+'text'+'>'*34,'x'*8193,'list<int>;drop table t','map<int,,text>'],ids=['deep','oversize','injection','syntax'])
def test_limits(raw):
    assert parse_type(raw) is None


def test_checker():
    r=target('main','AWS::Cassandra::Type',KeyspaceName='ks',TypeName='parent',Fields=[{'FieldName':'x','FieldType':'list<int>'}])
    root=Path(__file__).resolve().parents[1]
    found=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    assert any(f['rule_id']=='CASSANDRA_UDT_FIELD_FROZEN' and f['verdict']=='FAIL' for f in found)
