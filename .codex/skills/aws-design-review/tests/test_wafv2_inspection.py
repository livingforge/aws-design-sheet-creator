"""WAF configuration applicability, exact uniqueness and nested match patterns."""
from pathlib import Path
import pytest
from aws_design_sheet.checks.wafv2.inspection import evaluate_wafv2_inspection, GROUPS, FIELD_STATEMENTS
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


def check(statement,rule,kind='WebACL'):
    r=target('subject','AWS::WAFv2::'+kind,Rules=[{'Statement':statement}])
    return [x for x in evaluate_wafv2_inspection(linked_design(r),r) if x['rule_id']==rule]


def managed(name=GROUPS[0],vendor='AWS',**props):
    return {'ManagedRuleGroupStatement':{'Name':name,'VendorName':vendor,**props}}


@pytest.mark.parametrize('group',GROUPS)
@pytest.mark.parametrize('mode,expected',[
    ('absent','FAIL'),('empty','FAIL'),('matching','PASS'),('wrong','FAIL'),
    ('unknown','NEEDS_REVIEW'),('unknown_item','NEEDS_REVIEW'),
    ('unknown_object','NEEDS_REVIEW'),('repeated','NEEDS_REVIEW'),
    ('matching_unknown','PASS')])
def test_managed_configuration(group,mode,expected):
    configs={'empty':[],'matching':[{group:{}}],'wrong':[{}],'unknown':UNKNOWN,
             'unknown_item':[UNKNOWN],'unknown_object':[{group:UNKNOWN}],
             'repeated':[{group:{}},{group:{}}],'matching_unknown':[{group:{}},UNKNOWN]}
    props={} if mode=='absent' else {'ManagedRuleGroupConfigs':configs[mode]}
    assert check(managed(group,**props),'WAFV2_MANAGED_CONFIG_REQUIRED')[0]['verdict']==expected


@pytest.mark.parametrize('name,vendor,expected',[
    (GROUPS[0],'Other','NOT_APPLICABLE'),('AWSManagedRulesCommonRuleSet','AWS','NOT_APPLICABLE'),
    (UNKNOWN,'AWS','NEEDS_REVIEW'),(GROUPS[0],UNKNOWN,'NEEDS_REVIEW')])
def test_managed_applicability(name,vendor,expected):
    assert check(managed(name,vendor),'WAFV2_MANAGED_CONFIG_REQUIRED')[0]['verdict']==expected


@pytest.mark.parametrize('key',['LoginPath','PayloadType','UsernameField','PasswordField'])
def test_legacy_atp_is_not_missing_modern_config(key):
    assert check(managed(ManagedRuleGroupConfigs=[{key:UNKNOWN}]),'WAFV2_MANAGED_CONFIG_REQUIRED')[0]['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('form,suffix,success,failure',[
    ('StatusCode','Codes',200,400),('Header','Values','ok','bad'),
    ('Json','Values','ok','bad'),('BodyContains','Strings','ok','bad')])
@pytest.mark.parametrize('mode,expected',[
    ('distinct','PASS'),('cross','FAIL'),('within','FAIL'),('unknown','NEEDS_REVIEW'),
    ('duplicate_unknown','FAIL'),('wrong_type','NEEDS_REVIEW'),('missing','NEEDS_REVIEW')])
def test_response_uniqueness(form,suffix,success,failure,mode,expected):
    ok=[success];bad=[failure]
    if mode=='cross':bad=[success]
    if mode=='within':ok=[success,success]
    if mode=='unknown':bad=[UNKNOWN]
    if mode=='duplicate_unknown':ok=[success,success,UNKNOWN]
    if mode=='wrong_type':bad=[True] if form=='StatusCode' else [42]
    inspection={'Success'+suffix:ok,'Failure'+suffix:bad}
    if mode=='missing':inspection.pop('Failure'+suffix)
    node=managed(ManagedRuleGroupConfigs=[{GROUPS[0]:{'ResponseInspection':{form:inspection}}}])
    rows=check(node,'WAFV2_RESPONSE_INSPECTION_UNIQUE')
    assert len(rows)==1 and rows[0]['verdict']==expected


@pytest.mark.parametrize('group',GROUPS[:2])
def test_response_case_sensitive(group):
    config={'ResponseInspection':{'Header':{'SuccessValues':['ok'],'FailureValues':['OK']}}}
    assert check(managed(group,ManagedRuleGroupConfigs=[{group:config}]),'WAFV2_RESPONSE_INSPECTION_UNIQUE')[0]['verdict']=='PASS'


@pytest.mark.parametrize('field',['PhoneNumberFields','AddressFields'])
@pytest.mark.parametrize('identifier,expected',[
    ('/form/name','PASS'),('/a~1b/~0','PASS'),('/~01','PASS'),('/','PASS'),
    ('//','PASS'),('/01/-','PASS'),('/日本語','PASS'),('/a%20b','PASS'),
    ('name','FAIL'),('','FAIL'),('/a~','FAIL'),('/~2','FAIL'),('#/name','FAIL'),
    (UNKNOWN,'NEEDS_REVIEW'),('/${name}','NEEDS_REVIEW'),('/\ud800','NEEDS_REVIEW')])
def test_json_pointer_syntax(field,identifier,expected):
    config={'RequestInspection':{'PayloadType':'JSON',field:[{'Identifier':identifier}]}}
    node=managed(GROUPS[1],ManagedRuleGroupConfigs=[{GROUPS[1]:config}])
    assert check(node,'WAFV2_ACFP_JSON_POINTERS')[0]['verdict']==expected


@pytest.mark.parametrize('payload,expected',[('FORM_ENCODED','NOT_APPLICABLE'),(UNKNOWN,'NEEDS_REVIEW'),('OTHER','NEEDS_REVIEW')])
def test_pointer_requires_known_json_payload(payload,expected):
    config={'RequestInspection':{'PayloadType':payload,'PhoneNumberFields':[{'Identifier':'invalid~'}]}}
    assert check(managed(ManagedRuleGroupConfigs=[{GROUPS[1]:config}]),'WAFV2_ACFP_JSON_POINTERS')[0]['verdict']==expected


@pytest.mark.parametrize('kind',['WebACL','RuleGroup'])
@pytest.mark.parametrize('statement',FIELD_STATEMENTS)
def test_all_field_statement_kinds_nested(kind,statement):
    leaf={statement:{'FieldToMatch':{'Headers':{'MatchPattern':{'All':{},'IncludedHeaders':['x']}}}}}
    node={'AndStatement':{'Statements':[{'NotStatement':{'Statement':leaf}}]}}
    rows=check(node,'WAFV2_'+kind.upper()+'_FIELD_MATCH',kind)
    assert rows[-1]['verdict']=='FAIL' and '/NotStatement/Statement/' in rows[-1]['path']


@pytest.mark.parametrize('component,included,excluded',[
    ('Headers','IncludedHeaders','ExcludedHeaders'),('Cookies','IncludedCookies','ExcludedCookies'),
    ('JsonBody','IncludedPaths',None)])
@pytest.mark.parametrize('mode,expected',[
    ('all','PASS'),('included','PASS'),('both','FAIL'),('none','FAIL'),
    ('unknown','NEEDS_REVIEW'),('conditional','NEEDS_REVIEW'),('future','NEEDS_REVIEW')])
def test_match_pattern_union(component,included,excluded,mode,expected):
    patterns={'all':{'All':{}},'included':{included:['x']},'both':{'All':{},included:['x']},
              'none':{},'unknown':UNKNOWN,'conditional':{'All':{},included:UNKNOWN},'future':{'Future':{}}}
    leaf={'ByteMatchStatement':{'FieldToMatch':{component:{'MatchPattern':patterns[mode]}}}}
    assert check(leaf,'WAFV2_WEBACL_FIELD_MATCH')[-1]['verdict']==expected


@pytest.mark.parametrize('length,expected',[(30,'PASS'),(31,'NEEDS_REVIEW'),(64,'NEEDS_REVIEW'),(65,'FAIL')])
def test_query_name_documentation_conflict(length,expected):
    node={'ByteMatchStatement':{'FieldToMatch':{'SingleQueryArgument':{'Name':'a'*length}}}}
    assert check(node,'WAFV2_WEBACL_FIELD_MATCH')[-1]['verdict']==expected


@pytest.mark.parametrize('statement',[
    UNKNOWN,{'FutureStatement':{}},{'ByteMatchStatement':{},'GeoMatchStatement':{}},
    {'AndStatement':{'Statements':UNKNOWN}},{'NotStatement':UNKNOWN}])
def test_unknown_statement_held(statement):
    rows=check(statement,'WAFV2_WEBACL_FIELD_MATCH')
    assert rows and all(x['verdict']=='NEEDS_REVIEW' for x in rows)


@pytest.mark.parametrize('field,expected',[
    ({},'FAIL'),({'Body':{},'Method':{}},'FAIL'),(UNKNOWN,'NEEDS_REVIEW'),
    ({'Body':{},'Method':UNKNOWN},'NEEDS_REVIEW'),({'FutureField':{}},'NEEDS_REVIEW')])
def test_field_union(field,expected):
    assert check({'ByteMatchStatement':{'FieldToMatch':field}},'WAFV2_WEBACL_FIELD_MATCH')[0]['verdict']==expected


def test_absent_config_does_not_invent_inspection():
    for rule in ('WAFV2_RESPONSE_INSPECTION_UNIQUE','WAFV2_ACFP_JSON_POINTERS'):
        assert check(managed(),rule)==[]


def test_checker_integration():
    from aws_design_sheet.checker import Checker
    r=target('acl','AWS::WAFv2::WebACL',Rules=[{'Statement':managed()}])
    root=Path(__file__).resolve().parents[1]
    result=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))
    rows=[x for x in result['results'] if x['rule_id']=='WAFV2_MANAGED_CONFIG_REQUIRED']
    assert len(rows)==1 and rows[0]['verdict']=='FAIL' and rows[0]['source_urls']
