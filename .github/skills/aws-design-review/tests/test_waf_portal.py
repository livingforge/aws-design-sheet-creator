"""Nested WAF traversal, byte boundaries and explicit Kinesis key identity."""
import base64
from pathlib import Path
import pytest
from aws_design_sheet.models import Relation
from aws_design_sheet.checks.wafv2.portal import evaluate_wafv2_portal
from aws_design_sheet.checks.workspacesweb.waf_portal import evaluate_workspacesweb_waf_portal
from aws_design_sheet.checks.registry import combine
waf_portal_checks = combine(evaluate_wafv2_portal, evaluate_workspacesweb_waf_portal)
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


def check(kind,rule=None,**props):
    r=target('subject','AWS::'+kind,**props)
    return [x for x in waf_portal_checks(linked_design(r),r) if rule is None or x['rule_id']==rule]


@pytest.mark.parametrize('kind',['WebACL','RuleGroup'])
@pytest.mark.parametrize('statement,expected',[
    ({'SearchString':'a'*200},'PASS'),({'SearchString':'a'*201},'FAIL'),
    ({'SearchString':'日'*66+'aa'},'PASS'),({'SearchString':'日'*67},'FAIL'),
    ({'SearchStringBase64':base64.b64encode(b'x'*200).decode()},'PASS'),
    ({'SearchStringBase64':base64.b64encode(b'x'*201).decode()},'FAIL'),
    ({'SearchStringBase64':base64.b64encode(b'\xff'*200).decode()},'PASS'),
    ({'SearchString':'a'*201,'SearchStringBase64':'YQ=='},'NEEDS_REVIEW'),
    ({'SearchString':UNKNOWN},'NEEDS_REVIEW'),({'SearchStringBase64':'???'},'NEEDS_REVIEW'),
    ({'SearchStringBase64':'YQ'},'NEEDS_REVIEW'),({'SearchString':'\ud800'},'NEEDS_REVIEW'),
    ({'SearchString':'${value}'},'NEEDS_REVIEW'),({},'NEEDS_REVIEW')])
def test_byte_limits(kind,statement,expected):
    rows=check('WAFv2::'+kind,'WAFV2_'+kind.upper()+'_SEARCH_BYTES',Rules=[{'Statement':{'ByteMatchStatement':statement}}])
    assert rows[0]['verdict']==expected


@pytest.mark.parametrize('kind',['WebACL','RuleGroup'])
@pytest.mark.parametrize('container',['AndStatement','OrStatement','NotStatement','RateBasedStatement','ManagedRuleGroupStatement'])
def test_nested_statements(kind,container):
    leaf={'ByteMatchStatement':{'SearchString':'x'*201}}
    child={'Statements':[{'GeoMatchStatement':{}},leaf]} if container in ('AndStatement','OrStatement') else {'Statement':leaf} if container=='NotStatement' else {'ScopeDownStatement':leaf}
    root={'NotStatement':{'Statement':{container:child}}}
    rows=check('WAFv2::'+kind,'WAFV2_'+kind.upper()+'_SEARCH_BYTES',Rules=[{'Statement':root}])
    assert len(rows)==1 and rows[0]['verdict']=='FAIL' and '/NotStatement/Statement/' in rows[0]['path']


@pytest.mark.parametrize('statement',[
    UNKNOWN,{'ByteMatchStatement':{'SearchString':'x'*201},'GeoMatchStatement':{}},
    {'AndStatement':{'Statements':UNKNOWN}}, {'NotStatement':UNKNOWN}, {'FutureStatement':{}}])
def test_unknown_statements(statement):
    rows=check('WAFv2::WebACL','WAFV2_WEBACL_SEARCH_BYTES',Rules=[{'Statement':statement}])
    assert rows and all(x['verdict']=='NEEDS_REVIEW' for x in rows)


def test_deep_statement_traversal():
    node={'ByteMatchStatement':{'SearchString':'x'*201}}
    for _ in range(40):node={'NotStatement':{'Statement':node}}
    assert check('WAFv2::WebACL','WAFV2_WEBACL_SEARCH_BYTES',Rules=[{'Statement':node}])[0]['verdict']=='FAIL'


@pytest.mark.parametrize('kind',['WebACL','RuleGroup'])
@pytest.mark.parametrize('action',['Allow','Count','Captcha','Challenge'])
@pytest.mark.parametrize('names,expected',[
    (['x-a','x-b'],'PASS'),(['x-a','x-a'],'FAIL'),(['x-a','X-A'],'NEEDS_REVIEW'),
    (['x-a',UNKNOWN],'NEEDS_REVIEW'),(['x-a','x-a',UNKNOWN],'FAIL')])
def test_insert_header_names(kind,action,names,expected):
    config={action:{'CustomRequestHandling':{'InsertHeaders':[{'Name':name,'Value':'value'} for name in names]}}}
    assert check('WAFv2::'+kind,'WAFV2_'+kind.upper()+'_INSERT_HEADER_NAMES',Rules=[{'Action':config}])[0]['verdict']==expected


@pytest.mark.parametrize('kind',['WebACL','RuleGroup'])
@pytest.mark.parametrize('key,bodies,expected',[
    ('body',{'body':{'Content':'x'}},'PASS'),('missing',{'body':{}},'FAIL'),
    ('body',UNKNOWN,'NEEDS_REVIEW'),(UNKNOWN,{'body':{}},'NEEDS_REVIEW'),
    ('body',{'body':UNKNOWN},'PASS'),('missing',{'${key}':{}},'NEEDS_REVIEW'),
    ('body',None,'FAIL')])
def test_body_keys(kind,key,bodies,expected):
    props={'Rules':[{'Action':{'Block':{'CustomResponse':{'CustomResponseBodyKey':key}}}}]}
    if bodies is not None:props['CustomResponseBodies']=bodies
    assert check('WAFv2::'+kind,'WAFV2_'+kind.upper()+'_RESPONSE_BODY_KEY',**props)[0]['verdict']==expected


def test_default_actions():
    assert check('WAFv2::WebACL',DefaultAction={'Allow':{'CustomRequestHandling':{'InsertHeaders':[{'Name':'x'},{'Name':'x'}]}}})[0]['verdict']=='FAIL'
    assert check('WAFv2::WebACL',DefaultAction={'Block':{'CustomResponse':{'CustomResponseBodyKey':'missing'}}})[0]['verdict']=='FAIL'


@pytest.mark.parametrize('locale,url,expected',[
    ('en-US','https://example.com','PASS'),('ja-JP','mailto:ops@example.com','PASS'),
    ('en-US','http://example.com','NEEDS_REVIEW'),('en-US','HTTPS://example.com','NEEDS_REVIEW'),
    ('en-US','ftp://example.com','FAIL'),('en-US',UNKNOWN,'NEEDS_REVIEW'),
    ('en/US','https://example.com','NEEDS_REVIEW')])
def test_contact_links(locale,url,expected):
    assert check('WorkSpacesWeb::UserSettings',BrandingConfiguration={'LocalizedStrings':{locale:{'ContactLink':url}}})[0]['verdict']==expected


@pytest.mark.parametrize('encryption,expected',[
    (None,'PASS'),({'EncryptionType':'KMS','KeyId':'alias/aws/kinesis'},'PASS'),
    ({'EncryptionType':'KMS','KeyId':'aws/kinesis'},'NEEDS_REVIEW'),
    ({'EncryptionType':'KMS','KeyId':'alias/customer'},'NEEDS_REVIEW'),
    ({'EncryptionType':'KMS','KeyId':'12345678-1234-1234-1234-123456789012'},'NEEDS_REVIEW'),
    ({'EncryptionType':'KMS','KeyId':UNKNOWN},'NEEDS_REVIEW'),
    ({'EncryptionType':UNKNOWN,'KeyId':'alias/aws/kinesis'},'NEEDS_REVIEW'),
    (UNKNOWN,'NEEDS_REVIEW')])
def test_stream_encryption(encryption,expected):
    r=target('logging','AWS::WorkSpacesWeb::UserAccessLoggingSettings')
    stream=target('stream','AWS::Kinesis::Stream',**({} if encryption is None else {'StreamEncryption':encryption}))
    assert waf_portal_checks(linked_design(r,[stream],[('KinesisStreamArn','stream')]),r)[0]['verdict']==expected


@pytest.mark.parametrize('mode,expected',[
    ('customer_key','FAIL'),('conditional_key','NEEDS_REVIEW'),('conditional_stream','NEEDS_REVIEW'),
    ('cross_scope','NEEDS_REVIEW'),('unlinked_stream','NEEDS_REVIEW'),('wrong_key_type','NEEDS_REVIEW')])
def test_linked_customer_key(mode,expected):
    r=target('logging','AWS::WorkSpacesWeb::UserAccessLoggingSettings')
    stream=target('stream','AWS::Kinesis::Stream',StreamEncryption={'EncryptionType':'KMS'})
    key=target('key','AWS::KMS::Key')
    d=linked_design(r,[stream,key],[] if mode=='unlinked_stream' else [('KinesisStreamArn','stream')])
    d.relations.append(Relation(id='key-link',source_resource_id='stream',source_path='/properties/StreamEncryption/KeyId',target_resource_id='key',evidence_ids=['e1']))
    if mode=='conditional_key':d.relations[-1].condition='Maybe'
    if mode=='conditional_stream':d.relations[0].condition='Maybe'
    if mode=='cross_scope':key.scope.region='us-east-1'
    if mode=='wrong_key_type':key.type='AWS::KMS::Alias'
    assert waf_portal_checks(d,r)[0]['verdict']==expected


def test_checker_integration():
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('subject','AWS::WAFv2::WebACL',Rules=[{'Statement':{'ByteMatchStatement':{'SearchString':'x'*201}}}])
    row=next(x for x in Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results'] if x['rule_id']=='WAFV2_WEBACL_SEARCH_BYTES')
    assert row['verdict']=='FAIL' and row['source_urls'] and row['evidence_ids']
