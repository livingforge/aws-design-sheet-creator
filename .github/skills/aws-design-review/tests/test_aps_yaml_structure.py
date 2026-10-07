import base64
import json
from pathlib import Path
import pytest
from aws_design_sheet.checks.common.bounded_yaml import bounded_yaml
from aws_design_sheet.checks.aps.yaml_structure import rules_file, scrape_file, alert_receivers, evaluate_aps_yaml_structure
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('case,expected', [('valid','PASS'),('invalid','FAIL'),('alias','NEEDS_REVIEW'),('tag','NEEDS_REVIEW'),('duplicate','NEEDS_REVIEW'),('complex_key','NEEDS_REVIEW'),('documents','NEEDS_REVIEW'),('depth','NEEDS_REVIEW'),('size','NEEDS_REVIEW'),('unknown','NEEDS_REVIEW'),('dynamic','NEEDS_REVIEW'),('nodes','NEEDS_REVIEW')])
def test_bounded_yaml(case, expected):
    raw={'valid':'yes: no\ndate: 2026-10-04', 'invalid':'a: [broken', 'alias':'a: &ref [1]\nb: *ref',
         'tag':'a: !!python/object/apply:os.system [echo]', 'duplicate':'a: 1\na: 2',
         'complex_key':'? [a, b]\n: value', 'documents':'---\na: 1\n---\nb: 2',
         'depth':'['*65+'x'+']'*65, 'size':'x'*256001, 'unknown':UNKNOWN,
         'dynamic':'a: ${value}', 'nodes':'['+','.join('1' for _ in range(10001))+']'}[case]
    result=bounded_yaml(raw)
    assert result[0]==expected
    if case=='valid':assert result[1]=={'yes':'no','date':'2026-10-04'}


@pytest.mark.parametrize('case,expected',[('record','PASS'),('alert','PASS'),('duplicate_group','FAIL'),('both','FAIL'),('neither','FAIL'),('no_expr','FAIL'),('unknown_shape','NEEDS_REVIEW'),('literal_expr_only','PASS')])
def test_rules(case,expected):
    rule={'record':'metric:name','expr':'sum(up)'}
    if case=='alert':rule={'alert':'Down','expr':'up == 0'}
    if case=='both':rule['alert']='Down'
    if case=='neither':rule.pop('record')
    if case=='no_expr':rule.pop('expr')
    if case=='literal_expr_only':rule['expr']='syntax not validated here'
    group={'name':'group','rules':[rule]}
    doc={'groups':[group,group] if case=='duplicate_group' else [group]}
    if case=='unknown_shape':doc={'groups':{}}
    assert rules_file(json.dumps(doc))==expected


@pytest.mark.parametrize('case,expected',[('valid','PASS'),('duplicate','FAIL'),('bad_yaml','FAIL'),('missing_name','NEEDS_REVIEW'),('noncanonical','NEEDS_REVIEW'),('invalid_utf8','NEEDS_REVIEW')])
def test_scrape(case,expected):
    raw=json.dumps({'scrape_configs':[{'job_name':'a'}, {'job_name':'a' if case=='duplicate' else 'b'}]})
    if case=='bad_yaml':raw='a: ['
    if case=='missing_name':raw='scrape_configs: [{}]'
    encoded=base64.b64encode(b'\xff' if case=='invalid_utf8' else raw.encode()).decode()
    if case=='noncanonical':encoded+='\n'
    assert scrape_file(encoded)==expected


@pytest.mark.parametrize('case,expected',[('valid','PASS'),('unknown_receiver','FAIL'),('nested_bad','FAIL'),('inherited','PASS'),('duplicate','FAIL'),('outer_shape','NEEDS_REVIEW'),('inner_invalid','FAIL')])
def test_alerts(case,expected):
    inner={'receivers':[{'name':'one'}], 'route':{'receiver':'one'}}
    if case=='unknown_receiver':inner['route']['receiver']='missing'
    if case in ('nested_bad','inherited'):inner['route']['routes']=[{'receiver':'missing'} if case=='nested_bad' else {'matchers':['a=b']}]
    if case=='duplicate':inner['receivers'].append({'name':'one'})
    raw=json.dumps({'alertmanager_config':'broken: [' if case=='inner_invalid' else json.dumps(inner)})
    if case=='outer_shape':raw='[]'
    assert alert_receivers(raw)==expected


@pytest.mark.parametrize('kind,props', [('APS::RuleGroupsNamespace',{'Data':'groups: [{name: g, rules: [{record: x}]}]'}),('APS::Scraper',{'ScrapeConfiguration':{'ConfigurationBlob':base64.b64encode(b'bad: [').decode()}}),('APS::Workspace',{'AlertManagerDefinition':'bad: ['})])
def test_checker(kind,props):
    r=target('main','AWS::'+kind,**props);d=linked_design(r)
    direct=evaluate_aps_yaml_structure(d,r)[0]
    root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results']
    assert direct['verdict']=='FAIL'
    assert any(f['rule_id']==direct['rule_id'] and f['verdict']=='FAIL' for f in results)
