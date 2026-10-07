import pytest
from aws_design_sheet.checks.appmesh.route_weight_sum import evaluate_appmesh_route_weight_sum
from aws_design_sheet.checks.bedrock.prompt_default_variant import evaluate_bedrock_prompt_default_variant
from aws_design_sheet.checks.cognito.default_callback import evaluate_cognito_default_callback
from aws_design_sheet.checks.cleanrooms.any_query_providers import evaluate_cleanrooms_any_query_providers
from aws_design_sheet.checks.sagemaker.pipeline_hostnames import evaluate_sagemaker_pipeline_hostnames
from aws_design_sheet.checks.registry import combine
weighted_selection_checks = combine(evaluate_appmesh_route_weight_sum, evaluate_bedrock_prompt_default_variant, evaluate_cognito_default_callback, evaluate_cleanrooms_any_query_providers, evaluate_sagemaker_pipeline_hostnames)
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


@pytest.mark.parametrize('kind',['HttpRoute','Http2Route','GrpcRoute','TcpRoute'])
@pytest.mark.parametrize('weights,expected',[
    ([50,50],'PASS'),([50,51],'FAIL'),([0,0],'PASS'),([10,50],'PASS'),
    ([101],'FAIL'),([-1,100],'FAIL'),([UNKNOWN,50],'NEEDS_REVIEW'),
    ([50,51,UNKNOWN],'FAIL'),([True,50],'NEEDS_REVIEW'),(['50',50],'NEEDS_REVIEW'),
    ([], 'NEEDS_REVIEW')])
def test_weight_sum(kind,weights,expected):
    r=target('route','AWS::AppMesh::Route',Spec={kind:{'Action':{'WeightedTargets':[{'Weight':w} for w in weights]}}})
    assert weighted_selection_checks(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('default,names,expected',[
    ('a',['a'],'PASS'),('a',['b'],'FAIL'),('a',['A'],'FAIL'),('a',[],'FAIL'),
    ('a',[UNKNOWN],'NEEDS_REVIEW'),('a',['a',UNKNOWN],'PASS'),
    (UNKNOWN,['a'],'NEEDS_REVIEW'),('a',['a','a'],'PASS')])
def test_default_variant(default,names,expected):
    r=target('prompt','AWS::Bedrock::Prompt',DefaultVariant=default,Variants=[{'Name':n} for n in names])
    assert weighted_selection_checks(linked_design(r),r)[0]['verdict']==expected


def test_missing_and_unknown_variants():
    r=target('prompt','AWS::Bedrock::Prompt',DefaultVariant='a')
    assert weighted_selection_checks(linked_design(r),r)[0]['verdict']=='FAIL'
    r=target('prompt','AWS::Bedrock::Prompt',DefaultVariant='a',Variants=UNKNOWN)
    assert weighted_selection_checks(linked_design(r),r)[0]['verdict']=='NEEDS_REVIEW'
    r=target('prompt','AWS::Bedrock::Prompt',Variants=[{'Name':'a'}])
    assert weighted_selection_checks(linked_design(r),r)==[]


@pytest.mark.parametrize('default,urls,expected',[
    ('https://example.com/a',['https://example.com/a'],'PASS'),
    ('https://example.com/a',['https://example.com/A'],'FAIL'),
    ('https://example.com',[],'FAIL'),('https://example.com',[UNKNOWN],'NEEDS_REVIEW'),
    ('https://example.com',['https://example.com',UNKNOWN],'PASS'),
    (UNKNOWN,['https://example.com'],'NEEDS_REVIEW')])
def test_cognito_callback(default,urls,expected):
    r=target('client','AWS::Cognito::UserPoolClient',DefaultRedirectURI=default,CallbackURLs=urls)
    assert weighted_selection_checks(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('analyses,providers,expected',[
    (['ANY_QUERY'],None,'FAIL'),(['ANY_QUERY'],[],'PASS'),
    (['ANY_QUERY'],UNKNOWN,'NEEDS_REVIEW'),(['ANY_QUERY',UNKNOWN],None,'FAIL'),
    (['ANY_JOB'],None,'NOT_APPLICABLE'),([UNKNOWN],None,'NEEDS_REVIEW'),
    (UNKNOWN,None,'NEEDS_REVIEW'),(['arn:aws:cleanrooms:region:account:template/id'],None,'NOT_APPLICABLE')])
def test_any_query_presence(analyses,providers,expected):
    custom={'AllowedAnalyses':analyses}
    if providers is not None:custom['AllowedAnalysisProviders']=providers
    r=target('table','AWS::CleanRooms::ConfiguredTable',AnalysisRules=[{'Policy':{'V1':{'Custom':custom}}}])
    assert weighted_selection_checks(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('containers,expected',[
    ([{},{}],'PASS'),([{'ContainerHostname':'a'},{'ContainerHostname':'b'}],'PASS'),
    ([{'ContainerHostname':'a'},{}],'FAIL'),([{},UNKNOWN],'NEEDS_REVIEW'),
    ([{'ContainerHostname':'a'},{},UNKNOWN],'FAIL'),
    ([{'ContainerHostname':UNKNOWN},{}],'NEEDS_REVIEW'),([], 'NEEDS_REVIEW')])
def test_pipeline_hostname_all_or_none(containers,expected):
    r=target('model','AWS::SageMaker::Model',Containers=containers,InferenceExecutionConfig={'Mode':'Serial'})
    assert weighted_selection_checks(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('mode',[None,UNKNOWN,'Direct'])
def test_pipeline_applicability_held(mode):
    props={} if mode is None else {'InferenceExecutionConfig':{'Mode':mode}}
    r=target('model','AWS::SageMaker::Model',Containers=[{'ContainerHostname':'a'},{}],**props)
    assert weighted_selection_checks(linked_design(r),r)[0]['verdict']=='NEEDS_REVIEW'


def test_primary_container_is_separate():
    r=target('model','AWS::SageMaker::Model',PrimaryContainer={'ContainerHostname':'a'})
    assert weighted_selection_checks(linked_design(r),r)==[]


def test_weighted_selection_checker_integration():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('prompt','AWS::Bedrock::Prompt',DefaultVariant='missing',Variants=[{'Name':'known'}])
    rows=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    row=next(x for x in rows if x['rule_id']=='BEDROCK_PROMPT_DEFAULT_VARIANT')
    assert row['verdict']=='FAIL' and row['source_urls'] and row['evidence_ids']
