"""Query-array boundaries, uncertain applicability and cross-item constraints."""
from pathlib import Path
import pytest
from aws_design_sheet.checks.applicationsignals.service_level_objective import QUERY_PATHS, evaluate_applicationsignals_service_level_objective
from aws_design_sheet.checks.bedrockagentcore.gateway_traffic_total import evaluate_bedrockagentcore_gateway_traffic_total
from aws_design_sheet.checks.cleanrooms.job_only_controls import evaluate_cleanrooms_job_only_controls
from aws_design_sheet.checks.cloudformation.template_and_stackset import evaluate_cloudformation_template_and_stackset
from aws_design_sheet.checks.cleanroomsml.custom_redaction import evaluate_cleanroomsml_custom_redaction
from aws_design_sheet.checks.bedrock.agent_override_parser import evaluate_bedrock_agent_override_parser
from aws_design_sheet.checks.registry import combine
query_collections_checks = combine(evaluate_applicationsignals_service_level_objective, evaluate_bedrockagentcore_gateway_traffic_total, evaluate_cleanrooms_job_only_controls, evaluate_cloudformation_template_and_stackset, evaluate_cleanroomsml_custom_redaction, evaluate_bedrock_agent_override_parser)
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


def evaluate(kind,rule,**props):
    r=target('subject','AWS::'+kind,**props)
    return [x for x in query_collections_checks(linked_design(r),r) if x['rule_id']==rule]


def query_props(path,queries):
    props={};node=props
    keys=path.split('/')[2:]
    for k in keys[:-1]:node=node.setdefault(k,{})
    node[keys[-1]]=queries
    return props


def query(id,expression=False,flag=False):
    return {'Id':id,**({'Expression':'m1'} if expression else {'MetricStat':{}}),'ReturnData':flag}


@pytest.mark.parametrize('path',QUERY_PATHS)
@pytest.mark.parametrize('metrics,expressions,expected',[(10,10,'PASS'),(11,0,'FAIL'),(0,11,'FAIL'),(11,10,'FAIL'),(1,1,'PASS')])
def test_query_array_counts(path,metrics,expressions,expected):
    items=[query('m'+str(i)) for i in range(metrics)]+[query('e'+str(i),True,i==0) for i in range(expressions)]
    assert evaluate('ApplicationSignals::ServiceLevelObjective','APPLICATIONSIGNALS_QUERY_ARRAY',**query_props(path,items))[0]['verdict']==expected


@pytest.mark.parametrize('items,expected',[
    ([query('a'),query('a')],'FAIL'),([query('a'),query('A')],'PASS'),
    ([query('a'),UNKNOWN],'NEEDS_REVIEW'),([query('a'),query('a'),UNKNOWN],'FAIL'),
    ([{'Id':'a','Expression':'x','MetricStat':{}}],'FAIL'),([{'Id':'a'}],'FAIL'),
    ([{'Id':'a','Expression':UNKNOWN}],'NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_query_shapes_and_unknowns(items,expected):
    assert evaluate('ApplicationSignals::ServiceLevelObjective','APPLICATIONSIGNALS_QUERY_ARRAY',**query_props(QUERY_PATHS[0],items))[0]['verdict']==expected


@pytest.mark.parametrize('items,expected',[
    ([query('e',True,True),query('m')],'PASS'),
    ([query('e',True,True),query('e2',True,True)],'FAIL'),
    ([query('e',True,False),query('m')],'FAIL'),
    ([query('e',True,True),query('m',False,True)],'FAIL'),
    ([{'Id':'e','Expression':'m'},query('m')],'NEEDS_REVIEW'),
    ([query('e',True,1),query('m')],'NEEDS_REVIEW'),
    ([query('e',True,True),UNKNOWN],'NEEDS_REVIEW'),
    ([query('e',True,True),query('e2',True,True),UNKNOWN],'FAIL'),
    ([query('m')],'NOT_APPLICABLE'),([], 'NEEDS_REVIEW')])
def test_return_data(items,expected):
    assert evaluate('ApplicationSignals::ServiceLevelObjective','APPLICATIONSIGNALS_QUERY_RETURN',**query_props(QUERY_PATHS[0],items))[0]['verdict']==expected


@pytest.mark.parametrize('path',QUERY_PATHS)
@pytest.mark.parametrize('name,value,expected',[
    ('Name','value','PASS'),(':Name','value','FAIL'),('Name',':value','PASS'),
    (' Name ',' value ','PASS'),('Name','   ','FAIL'),('Name','a\tb','FAIL'),
    ('Name','a\x7fb','FAIL'),('Name','日本語','FAIL'),('Name',UNKNOWN,'NEEDS_REVIEW')])
def test_dimensions(path,name,value,expected):
    item=query('m');item['MetricStat']={'Metric':{'Dimensions':[{'Name':name,'Value':value}]}}
    rows=evaluate('ApplicationSignals::ServiceLevelObjective','APPLICATIONSIGNALS_DIMENSION_TEXT',**query_props(path,[item]))
    assert ('FAIL' if any(x['verdict']=='FAIL' for x in rows) else 'NEEDS_REVIEW' if any(x['verdict']=='NEEDS_REVIEW' for x in rows) else 'PASS')==expected


@pytest.mark.parametrize('weights,expected',[
    ([1,99],'PASS'),([50,50],'PASS'),([50.0,50.0],'PASS'),([50,49],'FAIL'),
    ([0,100],'FAIL'),([50.5,49.5],'NEEDS_REVIEW'),([True,99],'NEEDS_REVIEW'),
    (['50',50],'NEEDS_REVIEW'),([UNKNOWN,50],'NEEDS_REVIEW'),
    ([float('nan'),50],'NEEDS_REVIEW'),([50], 'FAIL'),([], 'FAIL')])
def test_override_total(weights,expected):
    actions=[{'ConfigurationBundle':{'WeightedOverride':{'TrafficSplit':[{'Weight':w} for w in weights]}}}]
    assert evaluate('BedrockAgentCore::GatewayRule','AGENTCORE_GATEWAY_TRAFFIC_TOTAL',Actions=actions)[0]['verdict']==expected


@pytest.mark.parametrize('weights,expected',[([50,50],'NEEDS_REVIEW'),([50,40],'NEEDS_REVIEW'),([0,100],'FAIL'),([50],'FAIL')])
def test_weighted_route_sum_is_held(weights,expected):
    actions=[{'RouteToTarget':{'WeightedRoute':{'TrafficSplit':[{'Weight':w} for w in weights]}}}]
    assert evaluate('BedrockAgentCore::GatewayRule','AGENTCORE_GATEWAY_TRAFFIC_TOTAL',Actions=actions)[0]['verdict']==expected


@pytest.mark.parametrize('key',['AggregationThresholds','ComparisonControls'])
@pytest.mark.parametrize('analyses,control,expected',[
    (['ANY_JOB'],{},'FAIL'),(['ANY_JOB','ANY_JOB'],{},'FAIL'),
    (['ANY_JOB','ANY_QUERY'],{},'NOT_APPLICABLE'),(['ANY_QUERY'],{},'NOT_APPLICABLE'),
    (['ANY_JOB',UNKNOWN],{},'NEEDS_REVIEW'),(['arn:aws:cleanrooms:region:account:template/id'],{},'NEEDS_REVIEW'),
    ([],{},'NEEDS_REVIEW'),(['ANY_JOB'],UNKNOWN,'NEEDS_REVIEW')])
def test_job_only_controls(key,analyses,control,expected):
    custom={'AllowedAnalyses':analyses,key:control}
    props={'AnalysisRules':[{'Policy':{'V1':{'Custom':custom}}}]}
    assert evaluate('CleanRooms::ConfiguredTable','CLEANROOMS_JOB_ONLY_CONTROLS',**props)[0]['verdict']==expected


@pytest.mark.parametrize('mode,targets,expected',[
    ('SERVICE_MANAGED',{'OrganizationalUnitIds':['ou-abcd-12345678']},'PASS'),
    ('SERVICE_MANAGED',{},'FAIL'),('SERVICE_MANAGED',{'OrganizationalUnitIds':[]},'FAIL'),
    ('SERVICE_MANAGED',{'OrganizationalUnitIds':UNKNOWN},'NEEDS_REVIEW'),
    ('SELF_MANAGED',{'Accounts':['111111111111']},'PASS'),
    ('SELF_MANAGED',{'AccountsUrl':'s3://bucket/accounts.csv'},'PASS'),
    ('SELF_MANAGED',{'Accounts':[],'AccountsUrl':'s3://bucket/a'},'FAIL'),
    ('SELF_MANAGED',{},'FAIL'),('SELF_MANAGED',{'Accounts':UNKNOWN},'NEEDS_REVIEW'),
    ('SELF_MANAGED',{'Accounts':['111111111111'],'AccountsUrl':UNKNOWN},'NEEDS_REVIEW'),
    (UNKNOWN,{},'NEEDS_REVIEW'),('FUTURE',{},'NEEDS_REVIEW')])
def test_stackset_targets(mode,targets,expected):
    props={'PermissionModel':mode,'StackInstancesGroup':[{'DeploymentTargets':targets}]}
    assert evaluate('CloudFormation::StackSet','STACKSET_PERMISSION_TARGETS',**props)[0]['verdict']==expected


def test_independent_query_arrays():
    props=query_props(QUERY_PATHS[1],[query('same',True,True)])
    props['RequestBasedSli']['RequestBasedSliMetric']['MonitoredRequestCountMetric']={'GoodCountMetric':[query('same',True,True)]}
    rows=evaluate('ApplicationSignals::ServiceLevelObjective','APPLICATIONSIGNALS_QUERY_ARRAY',**props)
    assert len(rows)==2 and all(x['verdict']=='PASS' for x in rows)


def test_checker_integration():
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('slo','AWS::ApplicationSignals::ServiceLevelObjective',**query_props(QUERY_PATHS[0],[query('same'),query('same')]))
    rows=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    row=next(x for x in rows if x['rule_id']=='APPLICATIONSIGNALS_QUERY_ARRAY')
    assert row['verdict']=='FAIL' and row['source_urls'] and row['evidence_ids']


@pytest.mark.parametrize('policy',['TrainedModels','TrainedModelInferenceJobs'])
@pytest.mark.parametrize('entities,custom,expected',[
    (['CUSTOM'],{},'PASS'),(['CUSTOM'],None,'FAIL'),(['NUMBERS'],{},'FAIL'),
    (['NUMBERS'],None,'PASS'),(['ALL_PERSONALLY_IDENTIFIABLE_INFORMATION'],None,'PASS'),
    (['CUSTOM',UNKNOWN],None,'FAIL'),(['CUSTOM',UNKNOWN],{},'PASS'),
    ([UNKNOWN],{},'NEEDS_REVIEW'),(['FUTURE'],{},'NEEDS_REVIEW'),
    (['CUSTOM'],UNKNOWN,'NEEDS_REVIEW'),(UNKNOWN,None,'NEEDS_REVIEW')])
def test_custom_redaction(policy,entities,custom,expected):
    config={'EntitiesToRedact':entities}
    if custom is not None:config['CustomEntityConfig']=custom
    props={'PrivacyConfiguration':{'Policies':{policy:{'ContainerLogs':[{'LogRedactionConfiguration':config}]}}}}
    rows=evaluate('CleanRoomsML::ConfiguredModelAlgorithmAssociation','CLEANROOMSML_CUSTOM_REDACTION',**props)
    assert len(rows)==1 and rows[0]['verdict']==expected


@pytest.mark.parametrize('modes,function,expected',[
    (['OVERRIDDEN'],'arn:aws:lambda:us-east-1:111111111111:function:test','PASS'),
    (['OVERRIDDEN'],None,'FAIL'),(['DEFAULT'],None,'PASS'),
    (['DEFAULT'],'function','FAIL'),(['OVERRIDDEN',UNKNOWN],None,'FAIL'),
    (['OVERRIDDEN',UNKNOWN],'function','PASS'),([UNKNOWN],'function','NEEDS_REVIEW'),
    (['OVERRIDDEN'],UNKNOWN,'NEEDS_REVIEW'),([None],'function','NEEDS_REVIEW')])
def test_parser_override(modes,function,expected):
    config={'PromptConfigurations':[{} if m is None else {'ParserMode':m} for m in modes]}
    if function is not None:config['OverrideLambda']=function
    assert evaluate('Bedrock::Agent','BEDROCK_AGENT_OVERRIDE_PARSER',PromptOverrideConfiguration=config)[0]['verdict']==expected


@pytest.mark.parametrize('body,expected',[
    ('a'*51200,'PASS'),('a'*51201,'FAIL'),('あ'*17066+'aa','PASS'),
    ('あ'*17067,'FAIL'),('\ud800','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW'),
    ('${Template}','NEEDS_REVIEW'),('', 'FAIL'),({'Resources':{}},'NEEDS_REVIEW')],
    ids=['ascii-limit','ascii-over','utf8-limit','utf8-over','surrogate','unknown','substitution','empty','object'])
def test_template_body_utf8(body,expected):
    assert evaluate('CloudFormation::Stack','CLOUDFORMATION_TEMPLATE_BODY_BYTES',TemplateBody=body)[0]['verdict']==expected
