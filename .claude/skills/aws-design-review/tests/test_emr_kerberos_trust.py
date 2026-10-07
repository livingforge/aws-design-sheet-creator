import json
import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.emr.kerberos_trust import evaluate_emr_kerberos_trust
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


def config(trust=True):
    dedicated={'TicketLifetimeInHours':24}
    if trust:dedicated['CrossRealmTrustConfiguration']={'Realm':'OTHER.EXAMPLE','Domain':'other.example','AdminServer':'other.example','KdcServer':'other.example'}
    return {'AuthenticationConfiguration':{'KerberosConfiguration':{'Provider':'ClusterDedicatedKdc','ClusterDedicatedKdcConfiguration':dedicated}}}


def fixture(node,attrs):
    main=target('main','AWS::EMR::Cluster',SecurityConfiguration='config',KerberosAttributes=attrs)
    other=target('config','AWS::EMR::SecurityConfiguration',Name='config',SecurityConfiguration=node)
    return linked_design(main,[other],[('SecurityConfiguration','config')]),main,other


@pytest.mark.parametrize('encoded',[False,True])
@pytest.mark.parametrize('attrs,expected',[({},'FAIL'),({'CrossRealmTrustPrincipalPassword':'test-placeholder'},'PASS'),({'CrossRealmTrustPrincipalPassword':UNKNOWN},'NEEDS_REVIEW'),({'CrossRealmTrustPrincipalPassword':'{{resolve:secretsmanager:placeholder}}'},'NEEDS_REVIEW')])
def test_required_presence(encoded,attrs,expected):
    node=config();d,r,_=fixture(json.dumps(node) if encoded else node,attrs)
    row=evaluate_emr_kerberos_trust(d,r)[0]
    assert row['verdict']==expected
    assert 'test-placeholder' not in json.dumps(row)


@pytest.mark.parametrize('mode',['conditional','wrong_name','external','scope','template','unknown_json','unknown_realm','external_kdc','incomplete_trust','dynamic_json','duplicate_json'])
def test_incomplete_evidence(mode):
    node=config()
    if mode=='unknown_json':node=UNKNOWN
    if mode=='unknown_realm':node['AuthenticationConfiguration']['KerberosConfiguration']['ClusterDedicatedKdcConfiguration']['CrossRealmTrustConfiguration']['Realm']=UNKNOWN
    if mode=='external_kdc':node['AuthenticationConfiguration']['KerberosConfiguration']['Provider']='ExternalKdc'
    if mode=='incomplete_trust':node['AuthenticationConfiguration']['KerberosConfiguration']['ClusterDedicatedKdcConfiguration']['CrossRealmTrustConfiguration']={}
    if mode=='dynamic_json':node={'Fn::Sub':json.dumps(node)}
    if mode=='duplicate_json':node='{"AuthenticationConfiguration":{},"AuthenticationConfiguration":{}}'
    d,r,other=fixture(node,{})
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='wrong_name':other.fields[0].candidates[0].value='different'
    if mode=='external':d.relations=[]
    if mode=='scope':other.scope.region='us-east-1'
    if mode=='template':other.template=TemplateContext(state='UNRESOLVED')
    assert evaluate_emr_kerberos_trust(d,r)[0]['verdict']=='NEEDS_REVIEW'


def test_no_trust_does_not_require_password_or_infer_active_directory():
    d,r,_=fixture(config(False),{})
    assert evaluate_emr_kerberos_trust(d,r)[0]['verdict']=='NOT_APPLICABLE'
    d,r,_=fixture(config(),{'CrossRealmTrustPrincipalPassword':'placeholder'})
    assert evaluate_emr_kerberos_trust(d,r)[0]['verdict']=='PASS'
    assert 'ADDomainJoinUser' not in str(evaluate_emr_kerberos_trust(d,r))


def test_bounded_payload():
    node=config();node['extra']='x'*30001
    d,r,_=fixture(node,{})
    assert evaluate_emr_kerberos_trust(d,r)[0]['verdict']=='NEEDS_REVIEW'


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    d,r,_=fixture(config(),{});root=Path(__file__).resolve().parents[1]
    rows=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results']
    assert any(f['rule_id']=='EMR_CROSS_REALM_PASSWORD_REQUIREMENT' and f['verdict']=='FAIL' for f in rows)
