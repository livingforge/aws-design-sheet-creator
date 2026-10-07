from pathlib import Path
import pytest
from aws_design_sheet.checks.applicationautoscaling.metric_queries import evaluate_applicationautoscaling_metric_queries, arithmetic_refs
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


@pytest.mark.parametrize('text,refs',[('m1/m2',{'m1','m2'}),(' -m1 + 3.5*(m2^2)',{'m1','m2'}),('SUM(m1)',None),('SEARCH("x")',None),('m1 > 0',None),('${x}',None),('m1.__class__',None),('m1//2',None),('m1**2',None),('m1 +',None)])
def test_parser(text,refs):
    assert arithmetic_refs(text)==refs


def resource(queries,kind):
    return target('main','AWS::ApplicationAutoScaling::ScalingPolicy',**({'TargetTrackingScalingPolicyConfiguration':{'CustomizedMetricSpecification':{'Metrics':queries}}} if kind=='target' else {'PredictiveScalingPolicyConfiguration':{'MetricSpecifications':[{'CustomizedLoadMetricSpecification':{'MetricDataQueries':queries}}]}}))


@pytest.mark.parametrize('kind',['target','predictive'])
@pytest.mark.parametrize('case',['valid','reordered','missing_ref','cycle','functions','unknown','duplicate','invalid_id','two_returns','no_returns','metric_returns','unset','no_math','expression_unknown','scalar'])
def test_queries(kind,case):
    queries=[{'Id':'e1','Expression':'m1 / 2','ReturnData':True},{'Id':'m1','MetricStat':{},'ReturnData':False}]
    if case=='reordered':queries.reverse()
    if case=='missing_ref':queries[0]['Expression']='missing / 2'
    if case=='cycle':queries[0]['Expression']='e1 + m1'
    if case=='functions':queries[0]['Expression']='SUM(m1)'
    if case=='unknown':queries[1]['Id']=UNKNOWN
    if case=='duplicate':queries[1]['Id']='e1'
    if case=='invalid_id':queries[1]['Id']='M1'
    if case=='two_returns':queries[1]['ReturnData']=True
    if case=='no_returns':queries[0]['ReturnData']=False
    if case=='metric_returns':queries[0]['ReturnData']=False;queries[1]['ReturnData']=True
    if case=='unset':queries[1].pop('ReturnData')
    if case=='no_math':queries=queries[1:]
    if case=='expression_unknown':queries[0]['Expression']=UNKNOWN
    if case=='scalar':queries[0]['Expression']='1 + 2'
    r=resource(queries,kind);found={f['rule_id']:f['verdict'] for f in evaluate_applicationautoscaling_metric_queries(linked_design(r),r)}
    assert found['APPLICATION_SCALING_QUERY_IDS']==('FAIL' if case in ('duplicate','invalid_id') else 'NEEDS_REVIEW' if case=='unknown' else 'PASS')
    assert found['APPLICATION_SCALING_QUERY_RETURN_DATA']==('FAIL' if case in ('two_returns','no_returns','metric_returns') else 'NEEDS_REVIEW' if case in ('unset','expression_unknown') else 'NOT_APPLICABLE' if case=='no_math' else 'PASS')
    assert found['APPLICATION_SCALING_ARITHMETIC_GRAPH']==('FAIL' if case in ('missing_ref','cycle') else 'NEEDS_REVIEW' if case in ('functions','unknown','duplicate','invalid_id','expression_unknown') else 'PASS')


@pytest.mark.parametrize('queries',[UNKNOWN,[],[UNKNOWN],[{}]*501],ids=['unknown','empty','unknown_member','oversize'])
def test_bounded(queries):
    r=resource(queries,'target')
    assert all(f['verdict']=='NEEDS_REVIEW' for f in evaluate_applicationautoscaling_metric_queries(linked_design(r),r))


def test_checker_graph():
    r=resource([{'Id':'e','Expression':'missing+1','ReturnData':True}],'target')
    root=Path(__file__).resolve().parents[1]
    result=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    assert any(f['rule_id']=='APPLICATION_SCALING_ARITHMETIC_GRAPH' and f['verdict']=='FAIL' for f in result)
