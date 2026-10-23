"""Regional catalog selection, unknowns, and bounded cross-region controls."""
import copy
import json
from pathlib import Path

import pytest
from openpyxl import load_workbook
from pydantic import ValidationError

from aws_design_sheet.document_catalog import catalog
from aws_design_sheet.document_cli import generate
from aws_design_sheet.document_evaluation import evaluate, adapt
from aws_design_sheet.document_normalize import normalize, InputError
from aws_design_sheet.schema_bootstrap import SchemaSetupError


def lit(value):return {'mode':'LITERAL','value':value}


def sample():
    return {'schema_version':'1.1','system':{'id':'test','name':'Regional controls'},
            'environments':[{'id':'prod','name':'Production','region':'ap-northeast-1'}],
            'resources':[
                {'id':'pool','name':'User pool','type':'AWS::Cognito::UserPool','settings':{'MfaConfiguration':lit('OPTIONAL')}},
                {'id':'waf','name':'Edge WAF','type':'AWS::WAFv2::WebACL','region':'us-east-1',
                 'settings':{'Scope':lit('CLOUDFRONT'),'DefaultAction':lit({'Allow':{}}),
                             'VisibilityConfig':lit({'CloudWatchMetricsEnabled':False,'SampledRequestsEnabled':False,'MetricName':'test'})}},
                {'id':'certificate','name':'Viewer certificate','type':'AWS::CertificateManager::Certificate','region':'us-east-1',
                 'settings':{'DomainName':{'status':'UNDECIDED'}}}]}


def norm(data):return normalize(json.dumps(data).encode(),'prod')


def test_regional_generation_and_excel_provenance(tmp_path):
    data=sample();path=tmp_path/'input.json';path.write_text(json.dumps(data))
    out=tmp_path/'output';result=generate(path,'prod',out,evaluate_design=True)
    doc=json.loads((out/'design.json').read_text(encoding='utf-8'))
    assert result['evaluation_status']=='COMPLETE'
    assert doc['resource_regions']=={'pool':'ap-northeast-1','waf':'us-east-1','certificate':'us-east-1'}
    for region,record in doc['regional_catalog_provenance'].items():
        assert record['region']==region and record['zip_sha256']==catalog(region).manifest['zip_sha256']
    assert doc['design']['resources'][2]['settings']['DomainName']['status']=='UNDECIDED'
    assert doc['design']['resources'][2]['settings']['DomainName']['value'] is None
    book=load_workbook(out/'design.xlsx');rows=list(book['地域別資源'].values)
    assert all(any(row[0]==r['id'] and row[1]==doc['resource_regions'][r['id']] for row in rows) for r in data['resources'])
    assert not any(c.data_type=='f' for sheet in book for row in sheet for c in row)
    book.close()
    evidence=[(row['resource_id'],source) for row in doc['checklist']['rows'] for source in row['evidence']
              if source.get('provider')=='pinned-cfn-schema']
    assert evidence and {source['region'] for _,source in evidence}=={'us-east-1'}
    # UserPool has no mandatory provider-schema property for this declaration.
    # Both catalogs were nevertheless selected; do not invent Tokyo obligations.
    assert set(doc['checklist']['provenance']['regional_schema_sha256'])=={'ap-northeast-1','us-east-1'}
    assert all(source['region']==doc['resource_regions'][rid] for rid,source in evidence)


def test_cognito_invalid_mfa_and_repair():
    data=sample();data['resources']=data['resources'][:1]
    for value,invalid in [('NOT_A_MODE',True),('OPTIONAL',False)]:
        data['resources'][0]['settings']['MfaConfiguration']=lit(value)
        result=evaluate(norm(data))
        assert result.status=='COMPLETE'
        errors=[r for r in result.results if r['verdict']=='FAIL' and r['rule_id']=='CFN_LINT.E3030']
        assert bool(errors)==invalid


def test_unavailable_region_is_not_substituted():
    data=sample();data['resources'][1]['region']='eu-west-1'
    with pytest.raises((SchemaSetupError,ValidationError)):norm(data)


def test_single_cfn_does_not_compare_multi_region_design():
    with pytest.raises(InputError,match='multi-region'):
        normalize(json.dumps(sample()).encode(),'prod',b'{"Resources":{}}')


@pytest.mark.parametrize('region,verdict',[('us-east-1','PASS'),('ap-northeast-1','FAIL')])
def test_cloudfront_certificate_regional_reference(region,verdict):
    data=sample();data['resources'][2]['region']=region
    data['resources'].append({'id':'cdn','name':'Distribution','type':'AWS::CloudFront::Distribution',
        'settings':{'DistributionConfig':{'mode':'COMPOSITE','value':{
            'Enabled':True,'ViewerCertificate':{'AcmCertificateArn':{'$design':{'mode':'RESOURCE_REF','ref':'certificate'}}}}}}})
    result=evaluate(norm(data))
    rows=[r for r in result.results if r['rule_id']=='REFERENCE' and r['resource_id']=='cdn']
    assert result.status=='COMPLETE' and len(rows)==1 and rows[0]['verdict']==verdict


@pytest.mark.parametrize('scope,verdict',[('CLOUDFRONT','PASS'),('REGIONAL','FAIL'),(None,'NEEDS_REVIEW')])
def test_cloudfront_waf_scope_is_not_inferred(scope,verdict):
    data=sample();data['resources'][1]['settings']['Scope']=lit(scope) if scope else {'status':'UNDECIDED'}
    data['resources'].append({'id':'cdn','name':'Distribution','type':'AWS::CloudFront::Distribution',
        'settings':{'DistributionConfig':{'mode':'COMPOSITE','value':{
            'Enabled':True,'WebACLId':{'$design':{'mode':'RESOURCE_REF','ref':'waf'}}}}}})
    result=evaluate(norm(data))
    rows=[r for r in result.results if r['rule_id']=='REFERENCE' and r['resource_id']=='cdn']
    assert result.status=='COMPLETE' and len(rows)==1 and rows[0]['verdict']==verdict


def test_ordinary_cross_region_reference_still_fails():
    data=sample();data['resources']=[
        {'id':'vpc','name':'VPC','type':'AWS::EC2::VPC','region':'us-east-1','settings':{'CidrBlock':lit('10.0.0.0/16')}},
        {'id':'subnet','name':'Subnet','type':'AWS::EC2::Subnet','settings':{
            'CidrBlock':lit('10.0.1.0/24'),'VpcId':{'mode':'RESOURCE_REF','ref':'vpc'}}}]
    result=evaluate(norm(data))
    assert any(r['rule_id']=='REFERENCE' and r['verdict']=='FAIL' for r in result.results)
    assert {r.scope.region for r in adapt(norm(data))[0].resources}=={'us-east-1','ap-northeast-1'}


@pytest.mark.parametrize('state,reverse,expected',[('DECIDED',False,'PASS'),('DECIDED',True,'FAIL'),('UNDECIDED',False,'NEEDS_REVIEW')])
def test_explicit_dependency_graph_and_cycle_repair(state,reverse,expected):
    data=sample()
    data['connections']=[{'id':'dependency','source':'pool','target':'certificate','kind':'DEPENDENCY','status':state}]
    if reverse:data['connections'].append({'id':'reverse','source':'certificate','target':'pool','kind':'DEPENDENCY'})
    result=evaluate(norm(data))
    rows=[r for r in result.results if r['rule_id']=='DOCUMENT_DEPENDENCY_ACYCLIC']
    assert len(rows)==1 and rows[0]['verdict']==expected
    if reverse:
        data['connections'].pop()
        assert next(r for r in evaluate(norm(data)).results if r['rule_id']=='DOCUMENT_DEPENDENCY_ACYCLIC')['verdict']=='PASS'


def osaka():
    return {'schema_version':'1.1','system':{'id':'files','name':'Osaka file service'},
            'environments':[{'id':'dr','name':'Disaster recovery','region':'ap-northeast-3'}],
            'resources':[
                {'id':'ontap','name':'ONTAP file system','type':'AWS::FSx::FileSystem',
                 'settings':{'FileSystemType':lit('ONTAP'),'StorageCapacity':lit(1024),'SubnetIds':{'mode':'EXTERNAL_REF','ref':'subnet/osaka-a'},
                             'OntapConfiguration':{'mode':'COMPOSITE','value':{'DeploymentType':'SINGLE_AZ_1','ThroughputCapacity':128,
                                 'FsxAdminPassword':{'$design':{'mode':'SECRET_REF','classification':'SECRET','ref':'secret://fsx/admin'}}}}}},
                {'id':'svm','name':'File SVM','type':'AWS::FSx::StorageVirtualMachine',
                 'settings':{'Name':lit('svm1'),'FileSystemId':{'mode':'RESOURCE_REF','ref':'ontap'}}},
                {'id':'share-volume','name':'Share volume','type':'AWS::FSx::Volume',
                 'settings':{'Name':lit('share'),'VolumeType':lit('ONTAP'),
                             'OntapConfiguration':lit({'JunctionPath':'/share','SizeInMegabytes':'10240','StorageVirtualMachineId':'svm-placeholder'})}}]}


def test_osaka_generates_fsx_with_its_own_reviewed_catalog(tmp_path):
    path=tmp_path/'input.json';path.write_text(json.dumps(osaka()),encoding='utf-8')
    out=tmp_path/'output';result=generate(path,'dr',out,evaluate_design=True)
    doc=json.loads((out/'design.json').read_text(encoding='utf-8'))
    assert result['evaluation_status']=='COMPLETE'
    assert set(doc['resource_regions'].values())=={'ap-northeast-3'}
    assert doc['regional_catalog_provenance']['ap-northeast-3']['source'].startswith('https://schema.cloudformation.ap-northeast-3.')
    assert {i['service'] for i in doc['items']}=={'FSx'}
    report=json.loads((out/'review-report.json').read_text(encoding='utf-8'))
    assert set(report['rule_review_causes']['counts'])<={'REGIONAL_APPLICABILITY','SCHEMA_CHANGE','OPEN_QUESTION'}
    assert 'secret://fsx/admin' not in (out/'design.xlsx').read_bytes().decode('latin-1')


def test_type_missing_from_osaka_is_not_taken_from_tokyo():
    data=osaka();data['resources'].append({'id':'lens','name':'Storage Lens','type':'AWS::S3::StorageLens','settings':{}})
    with pytest.raises((InputError,ValidationError,ValueError)):
        normalize(json.dumps(data).encode(),'dr')


def arn_case(region,key_arn,extra=()):
    return {'schema_version':'1.1','system':{'id':'arn','name':'ARN regions'},
            'environments':[{'id':'dr','name':'DR','region':region}],
            'resources':[{'id':'logs','name':'Logs','type':'AWS::Logs::LogGroup','settings':{'KmsKeyId':lit(key_arn)}},*extra]}


def arn_rows(data):
    doc=normalize(json.dumps(data).encode(),'dr')
    return [r for r in evaluate(doc).results if r['rule_id']=='DOCUMENT_ARN_REGION']


def test_literal_tokyo_key_in_osaka_needs_review_and_matching_key_is_silent():
    tokyo='arn:aws:kms:ap-northeast-1:111122223333:key/11111111-2222-3333-4444-555555555555'
    rows=arn_rows(arn_case('ap-northeast-3',tokyo))
    assert [(r['resource_id'],r['path'],r['verdict'],r['expected'],r['actual']) for r in rows]==[
        ('logs','/properties/KmsKeyId','NEEDS_REVIEW','ap-northeast-3','aws:ap-northeast-1')]
    assert arn_rows(arn_case('ap-northeast-1',tokyo))==[]
    assert arn_rows(arn_case('ap-northeast-3','arn:aws:iam::111122223333:role/global-has-no-region'))==[]


@pytest.mark.parametrize('cert_region,verdict',[('us-east-1','PASS'),('ap-northeast-1','FAIL')])
def test_literal_cloudfront_certificate_arn_must_be_in_us_east_1(cert_region,verdict):
    cert=f'arn:aws:acm:{cert_region}:111122223333:certificate/x'
    distribution={'id':'cdn','name':'CDN','type':'AWS::CloudFront::Distribution','settings':{'DistributionConfig':{'mode':'COMPOSITE','value':{
        'Enabled':True,'ViewerCertificate':{'AcmCertificateArn':{'$design':{'mode':'LITERAL','value':cert}},'SslSupportMethod':'sni-only'}}}}}
    rows=arn_rows(arn_case('ap-northeast-1','arn:aws:kms:ap-northeast-1:111122223333:key/x',[distribution]))
    assert [(r['path'],r['verdict'],r['severity']) for r in rows]==[
        ('/properties/DistributionConfig/ViewerCertificate/AcmCertificateArn',verdict,'ERROR')]
