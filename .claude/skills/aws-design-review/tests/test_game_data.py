from pathlib import Path
import pytest
from aws_design_sheet.checks.gamelift.data import evaluate_gamelift_data
from aws_design_sheet.checks.gameliftstreams.stream_home_location import evaluate_gameliftstreams_stream_home_location
from aws_design_sheet.checks.glue.identities import evaluate_glue_identities
from aws_design_sheet.checks.registry import combine
game_data_checks = combine(evaluate_gamelift_data, evaluate_gameliftstreams_stream_home_location, evaluate_glue_identities)
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('raw,expected', [('{}','PASS'), ('{"x":1}','PASS'), ('{//comment\n}','FAIL'), ('{"x":NaN}','FAIL'), ('{','FAIL'), (UNKNOWN,'NEEDS_REVIEW'), ({'Ref':'X'},'NEEDS_REVIEW'), ('['*200+'0'+']'*200,'NEEDS_REVIEW')])
def test_json(raw,expected):
    r=target('main','AWS::GameLift::MatchmakingRuleSet',RuleSetBody=raw)
    assert game_data_checks(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('mode', ['home','missing','empty','unknown','mixed','array_unknown','scope','omitted'])
def test_home(mode):
    raw=UNKNOWN if mode=='array_unknown' else [] if mode=='empty' else [{'LocationName':UNKNOWN if mode=='unknown' else 'us-east-1' if mode=='missing' else 'ap-northeast-1'}]
    if mode=='mixed':raw.append({'LocationName':UNKNOWN})
    r=target('main','AWS::GameLiftStreams::StreamGroup',**({} if mode=='omitted' else {'LocationConfigurations':raw}))
    if mode=='scope':r.scope.region='unknown'
    result=game_data_checks(linked_design(r),r)
    if mode=='omitted':assert not result
    else:assert result[0]['verdict']==('PASS' if mode in ('home','mixed') else 'FAIL' if mode in ('missing','empty') else 'NEEDS_REVIEW')


@pytest.mark.parametrize('mode', ['same','different','unknown','dynamic','scope','omitted'])
def test_catalog(mode):
    raw=UNKNOWN if mode=='unknown' else {'Ref':'X'} if mode=='dynamic' else '111111111111' if mode=='same' else 'catalog'
    r=target('main','AWS::Glue::Catalog',**({} if mode=='omitted' else {'Name':raw}))
    if mode=='scope':r.scope.account='unknown'
    result=game_data_checks(linked_design(r),r)
    if mode=='omitted':assert not result
    else:assert result[0]['verdict']==('FAIL' if mode=='same' else 'PASS' if mode=='different' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('quote,delimiter,expected', [('"',',','PASS'), (',',',','FAIL'), (' ', '\t','PASS'), (UNKNOWN,',','NEEDS_REVIEW'), ('"',UNKNOWN,'NEEDS_REVIEW'), ('ab',',','NEEDS_REVIEW'), ('\n',',','NEEDS_REVIEW'), ('',',','NEEDS_REVIEW')])
def test_csv(quote,delimiter,expected):
    r=target('main','AWS::Glue::Classifier',CsvClassifier={'QuoteSymbol':quote,'Delimiter':delimiter})
    assert game_data_checks(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('props', [{}, {'QuoteSymbol':'"'}, {'Delimiter':','}])
def test_csv_defaults(props):
    r=target('main','AWS::Glue::Classifier',CsvClassifier=props)
    result=game_data_checks(linked_design(r),r)
    assert (result[0]['verdict']=='NEEDS_REVIEW') if props else not result


@pytest.mark.parametrize('mode', ['same','region','account','environment','name','unknown','ancestor','conditional','ambiguous','missing','wrong_type','template','bucket_template','scope'])
def test_bucket(mode):
    from aws_design_sheet.models import TemplateContext
    r=target('main','AWS::GameLift::Build',StorageLocation=UNKNOWN if mode=='ancestor' else {'Bucket':UNKNOWN if mode=='unknown' else 'my-bucket'})
    b=target('bucket','AWS::S3::Bucket',BucketName='other-name' if mode=='name' else 'my-bucket')
    d=linked_design(r,[b],[] if mode=='missing' else [('StorageLocation/Bucket','bucket')])
    if mode in ('region','account','environment'):setattr(b.scope,mode,{'region':'us-east-1','account':'222222222222','environment':'other'}[mode])
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='ambiguous':d.relations.append(d.relations[0].model_copy(update={'id':'duplicate'}))
    if mode=='wrong_type':b.type='AWS::SNS::Topic'
    if mode=='template':r.template=TemplateContext(state='UNRESOLVED')
    if mode=='bucket_template':b.template=TemplateContext(state='UNRESOLVED')
    if mode=='scope':b.scope.account='unknown'
    assert game_data_checks(d,r)[0]['verdict']==('PASS' if mode=='same' else 'FAIL' if mode in ('region','account') else 'NEEDS_REVIEW')


def test_checker_catalog():
    r=target('main','AWS::Glue::Catalog',Name='111111111111')
    root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    assert any(f['rule_id']=='GLUE_CATALOG_ACCOUNT_NAME' and f['verdict']=='FAIL' for f in results)
