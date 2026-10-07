import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.docdb.event_sources import evaluate_docdb_event_sources
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_template_dependencies import link


@pytest.mark.parametrize('mode',['db-instance','db-cluster','db-parameter-group','db-security-group','db-cluster-snapshot','future',None,UNKNOWN])
@pytest.mark.parametrize('case',['instance','cluster','external','conditional','template','scope'])
def test_source_types(mode,case):
    r=target('main','AWS::DocDB::EventSubscription',SourceIds=['source'],**({} if mode is None else {'SourceType':mode}))
    s=target('source','AWS::DocDB::DBCluster' if case=='cluster' else 'AWS::DocDB::DBInstance')
    d=linked_design(r,[s])
    if case!='external':link(d,r,'SourceIds/0',s)
    if case=='conditional':d.relations[-1].condition='maybe'
    if case=='template':s.template=TemplateContext(state='UNRESOLVED')
    if case=='scope':s.scope.region='us-east-1'
    expected='NEEDS_REVIEW'
    if case in ('instance','cluster') and isinstance(mode,str) and mode!='future':expected='PASS' if mode=='db-'+case else 'FAIL'
    assert evaluate_docdb_event_sources(d,r)[0]['verdict']==expected


def test_known_mismatch_survives_external_other_source():
    r=target('main','AWS::DocDB::EventSubscription',SourceType='db-cluster',SourceIds=['source','external'])
    s=target('source','AWS::DocDB::DBInstance');d=linked_design(r,[s],[('SourceIds/0','source')])
    assert evaluate_docdb_event_sources(d,r)[0]['verdict']=='FAIL'


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('main','AWS::DocDB::EventSubscription',SourceIds=['source'],SourceType='db-cluster')
    s=target('source','AWS::DocDB::DBInstance');d=linked_design(r,[s],[('SourceIds/0','source')])
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results']
    assert any(f['rule_id']=='DOCDB_EVENT_SOURCE_TYPES' and f['verdict']=='FAIL' for f in results)
