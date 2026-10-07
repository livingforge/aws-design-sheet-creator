from pathlib import Path
import pytest
from aws_design_sheet.checks.lex.bot_locales import evaluate_lex_bot_locales
from aws_design_sheet.checks.lightsail.container_services import evaluate_lightsail_container_services
from aws_design_sheet.checks.registry import combine
bot_services_checks = combine(evaluate_lex_bot_locales, evaluate_lightsail_container_services)
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


def check(kind,rule,**props):
    r=target('subject','AWS::'+kind,**props)
    return [x for x in bot_services_checks(linked_design(r),r) if x['rule_id']==rule]


@pytest.mark.parametrize('intents,expected',[
    ([{'ParentIntentSignature':'AMAZON.FallbackIntent'}],'PASS'),([{'Name':'custom'}],'FAIL'),
    ([], 'FAIL'),(UNKNOWN,'NEEDS_REVIEW'),([UNKNOWN],'NEEDS_REVIEW'),
    ([{'ParentIntentSignature':'AMAZON.FallbackIntent'},UNKNOWN],'PASS')])
def test_fallback(intents,expected):
    assert check('Lex::Bot','LEX_INLINE_FALLBACK',BotType='Bot',BotLocales=[{'LocaleId':'en_US','Intents':intents}])[0]['verdict']==expected


@pytest.mark.parametrize('mode',['import','network','multiple','type_omitted'])
def test_fallback_scope_held(mode):
    props={'BotType':'Bot','BotLocales':[{'LocaleId':'en_US','Intents':[]}]}
    if mode=='import':props['BotFileS3Location']={'S3Bucket':'bucket'}
    if mode=='network':props['BotType']='BotNetwork'
    if mode=='multiple':props['BotLocales'].append({'LocaleId':'ja_JP','Intents':[]})
    if mode=='type_omitted':props.pop('BotType')
    assert all(x['verdict']=='NEEDS_REVIEW' for x in check('Lex::Bot','LEX_INLINE_FALLBACK',**props))


@pytest.mark.parametrize('locale,enabled,expected',[
    ('en_US',True,'PASS'),('ja_JP',True,'FAIL'),('en_GB',True,'FAIL'),('en-US',True,'NEEDS_REVIEW'),
    (UNKNOWN,True,'NEEDS_REVIEW'),('ja_JP',False,'NOT_APPLICABLE'),('en_US','true','NEEDS_REVIEW')])
def test_multivalue(locale,enabled,expected):
    locales=[{'LocaleId':locale,'Intents':[{'Slots':[{'MultipleValuesSetting':{'AllowMultipleValues':enabled}}]}]}]
    assert check('Lex::Bot','LEX_MULTIVALUE_LOCALE',BotLocales=locales)[0]['verdict']==expected


def test_multivalue_enclosing_locale():
    locales=[{'LocaleId':locale,'Intents':[{'Slots':[{'MultipleValuesSetting':{'AllowMultipleValues':True}}]}]} for locale in ['en_US','ja_JP']]
    assert [x['verdict'] for x in check('Lex::Bot','LEX_MULTIVALUE_LOCALE',BotLocales=locales)]==['PASS','FAIL']


@pytest.mark.parametrize('power,protocol,expected',[
    ('nano','HTTP',['PASS','PASS']),('xlarge','UDP',['PASS','PASS']),('huge','http',['FAIL','FAIL']),
    (UNKNOWN,UNKNOWN,['NEEDS_REVIEW','NEEDS_REVIEW'])])
def test_container_values(power,protocol,expected):
    assert [x['verdict'] for x in check('Lightsail::Container','LIGHTSAIL_CONTAINER_VALUES',Power=power,ContainerServiceDeployment={'Containers':[{'Ports':[{'Protocol':protocol}]}]})]==expected


@pytest.mark.parametrize('key,n,expected',[
    ('IntervalSeconds',5,'PASS'),('IntervalSeconds',300,'PASS'),('IntervalSeconds',4,'FAIL'),('IntervalSeconds',301,'FAIL'),
    ('TimeoutSeconds',2,'PASS'),('TimeoutSeconds',60,'PASS'),('TimeoutSeconds',1,'FAIL'),('TimeoutSeconds',61,'FAIL'),
    ('IntervalSeconds',True,'NEEDS_REVIEW'),('TimeoutSeconds',UNKNOWN,'NEEDS_REVIEW'),
    ('SuccessCodes','200,499','PASS'),('SuccessCodes','200-499','PASS'),('SuccessCodes','199,200','FAIL'),
    ('SuccessCodes','200-500','FAIL'),('SuccessCodes','200-299,400','NEEDS_REVIEW'),
    ('SuccessCodes','499-200','NEEDS_REVIEW'),('SuccessCodes',UNKNOWN,'NEEDS_REVIEW')])
def test_health(key,n,expected):
    assert check('Lightsail::Container','LIGHTSAIL_CONTAINER_HEALTH',ContainerServiceDeployment={'PublicEndpoint':{'HealthCheckConfig':{key:n}}})[0]['verdict']==expected


@pytest.mark.parametrize('groups,expected',[
    ([['a.example','b.example'],['c.example','d.example']],'PASS'),
    ([['a.example','b.example'],['c.example','d.example','e.example']],'FAIL'),
    ([['a.example','A.example','a.example','a.example','a.example']],'NEEDS_REVIEW'),
    ([['a.example',UNKNOWN]],'NEEDS_REVIEW'),([UNKNOWN],'NEEDS_REVIEW'),
    ([['a.example','b.example','c.example','d.example','e.example'],UNKNOWN],'FAIL')])
def test_domain_count(groups,expected):
    assert check('Lightsail::Container','LIGHTSAIL_CONTAINER_DOMAINS',PublicDomainNames=[{'DomainNames':x} for x in groups])[0]['verdict']==expected


@pytest.mark.parametrize('name,expected',[('a.example','PASS'),('*.example','FAIL'),('${Name}','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_certificate_wildcards(name,expected):
    assert check('Lightsail::LoadBalancerTlsCertificate','LIGHTSAIL_CERTIFICATE_WILDCARDS',CertificateAlternativeNames=[name])[0]['verdict']==expected


def test_checker_integration():
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('subject','AWS::Lightsail::LoadBalancerTlsCertificate',CertificateAlternativeNames=['*.example.com'])
    result=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))
    row=next(x for x in result['results'] if x['rule_id']=='LIGHTSAIL_CERTIFICATE_WILDCARDS')
    assert row['verdict']=='FAIL' and row['source_urls'] and row['evidence_ids']
