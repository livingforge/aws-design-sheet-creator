"""Transform boundaries and local-reference uncertainty across nested WAF rules."""
from pathlib import Path
import pytest
from aws_design_sheet.checks.wafv2.transforms import evaluate_wafv2_transforms, CUSTOM, REFERENCES
from aws_design_sheet.checks.wafv2.inspection import FIELD_STATEMENTS
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


def check(statement,suffix,kind='WebACL'):
    r=target('subject','AWS::WAFv2::'+kind,Rules=[{'Statement':statement}])
    return [x for x in evaluate_wafv2_transforms(linked_design(r),r) if x['rule_id']=='WAFV2_'+kind.upper()+suffix]


@pytest.mark.parametrize('kind',['WebACL','RuleGroup'])
@pytest.mark.parametrize('statement',FIELD_STATEMENTS)
@pytest.mark.parametrize('count,expected',[(0,'PASS'),(10,'PASS'),(11,'FAIL')])
def test_preparse_bound(kind,statement,count,expected):
    node={statement:{'FieldToMatch':{'AllQueryArguments':{}},'PreParseTextTransformations':[{'Priority':0,'Type':'NONE'}]*count}}
    assert check(node,'_PREPARSE_LIMIT',kind)[0]['verdict']==expected


@pytest.mark.parametrize('field,expected',[
    ({'SingleQueryArgument':{'Name':'q'}},'PASS'),({'AllQueryArguments':{}},'PASS'),
    ({'Body':{}},'FAIL'),({'Future':{}},'NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW'),
    ({'Body':{},'AllQueryArguments':{}},'NEEDS_REVIEW')])
def test_preparse_applicability(field,expected):
    node={'ByteMatchStatement':{'FieldToMatch':field,'PreParseTextTransformations':[{}]}}
    assert check(node,'_PREPARSE_LIMIT')[0]['verdict']==expected


@pytest.mark.parametrize('kind',['WebACL','RuleGroup'])
@pytest.mark.parametrize('values,expected',[
    ([0,9],'PASS'),([9,0],'PASS'),([0,0],'FAIL'),([-1,0],'FAIL'),
    ([True,1],'NEEDS_REVIEW'),(['0',0],'NEEDS_REVIEW'),([1.0,1],'NEEDS_REVIEW'),
    ([UNKNOWN,0],'NEEDS_REVIEW'),([UNKNOWN,0,0],'FAIL'),([], 'FAIL')])
def test_transform_priorities(kind,values,expected):
    node={'ByteMatchStatement':{'TextTransformations':[{'Priority':x} for x in values]}}
    assert check(node,'_TRANSFORM_PRIORITY',kind)[0]['verdict']==expected


@pytest.mark.parametrize('kind',['WebACL','RuleGroup'])
@pytest.mark.parametrize('key',CUSTOM)
@pytest.mark.parametrize('values,expected',[([0,3],'PASS'),([0,0],'FAIL'),([UNKNOWN,0],'NEEDS_REVIEW')])
def test_rate_key_priorities(kind,key,values,expected):
    node={'RateBasedStatement':{'CustomKeys':[{key:{'TextTransformations':[{'Priority':x} for x in values]}}]}}
    assert check(node,'_RATE_KEY_PRIORITY',kind)[0]['verdict']==expected


def test_priorities_are_local_to_each_key():
    node={'RateBasedStatement':{'CustomKeys':[{key:{'TextTransformations':[{'Priority':0}]}} for key in CUSTOM]}}
    assert all(x['verdict']=='PASS' for x in check(node,'_RATE_KEY_PRIORITY'))


@pytest.mark.parametrize('container',['AndStatement','OrStatement','NotStatement','RateBasedStatement','ManagedRuleGroupStatement'])
def test_traversal_descends_after_selecting_rate_statement(container):
    leaf={'RegexMatchStatement':{'TextTransformations':[{'Priority':1},{'Priority':1}]}}
    inner={'Statements':[leaf]} if container in ('AndStatement','OrStatement') else {'Statement':leaf} if container=='NotStatement' else {'ScopeDownStatement':leaf}
    node={container:inner}
    for _ in range(25):node={'NotStatement':{'Statement':node}}
    assert check(node,'_TRANSFORM_PRIORITY')[-1]['verdict']=='FAIL'


@pytest.mark.parametrize('statement',REFERENCES)
@pytest.mark.parametrize('own,their,expected',[
    ('REGIONAL','REGIONAL','PASS'),('CLOUDFRONT','CLOUDFRONT','PASS'),
    ('CLOUDFRONT','REGIONAL','FAIL'),('REGIONAL',UNKNOWN,'NEEDS_REVIEW'),
    (UNKNOWN,'REGIONAL','NEEDS_REVIEW')])
def test_linked_reference_scopes(statement,own,their,expected):
    r=target('acl','AWS::WAFv2::WebACL',Scope=own,Rules=[{'Statement':{statement:{}}}])
    t=target('ref','AWS::WAFv2::'+REFERENCES[statement],Scope=their)
    d=linked_design(r,[t],[('Rules/0/Statement/'+statement+'/Arn','ref')])
    rows=[x for x in evaluate_wafv2_transforms(d,r) if x['rule_id']=='WAFV2_WEBACL_REFERENCE_SCOPE']
    assert rows[0]['verdict']==expected


@pytest.mark.parametrize('statement',REFERENCES)
def test_global_reference_to_regional_scope(statement):
    r=target('acl','AWS::WAFv2::WebACL',Scope='REGIONAL',Rules=[{'Statement':{statement:{}}}])
    t=target('ref','AWS::WAFv2::'+REFERENCES[statement],Scope='CLOUDFRONT')
    d=linked_design(r,[t],[('Rules/0/Statement/'+statement+'/Arn','ref')])
    rows=[x for x in evaluate_wafv2_transforms(d,r) if x['rule_id']=='WAFV2_WEBACL_REFERENCE_SCOPE']
    assert rows[0]['verdict']==('NEEDS_REVIEW' if statement=='RuleGroupReferenceStatement' else 'FAIL')


@pytest.mark.parametrize('mode',['conditional','cross_region','cross_account','external','wrong_type','duplicate'])
def test_uncertain_links(mode):
    statement='IPSetReferenceStatement';r=target('acl','AWS::WAFv2::WebACL',Scope='REGIONAL',Rules=[{'Statement':{statement:{'Arn':'arn:aws:wafv2:us-east-1:111111111111:global/ipset/test/id'}}}])
    t=target('ref','AWS::WAFv2::IPSet',Scope='CLOUDFRONT')
    links=[] if mode=='external' else [('Rules/0/Statement/'+statement+'/Arn','ref')]
    if mode=='duplicate':links*=2
    d=linked_design(r,[t],links)
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='cross_region':t.scope.region='us-east-1'
    if mode=='cross_account':t.scope.account='222222222222'
    if mode=='wrong_type':t.type='AWS::WAFv2::RegexPatternSet'
    rows=[x for x in evaluate_wafv2_transforms(d,r) if x['rule_id']=='WAFV2_WEBACL_REFERENCE_SCOPE']
    assert rows[0]['verdict']=='NEEDS_REVIEW'


def test_checker_integration():
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('acl','AWS::WAFv2::WebACL',Rules=[{'Statement':{'ByteMatchStatement':{'TextTransformations':[{'Priority':0},{'Priority':0}]}}}])
    rows=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    row=next(x for x in rows if x['rule_id']=='WAFV2_WEBACL_TRANSFORM_PRIORITY')
    assert row['verdict']=='FAIL' and row['source_urls'] and row['evidence_ids']
