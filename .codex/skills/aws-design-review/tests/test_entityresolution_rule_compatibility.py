import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.entityresolution.rule_compatibility import evaluate_entityresolution_rule_compatibility
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


def fixture(source=None,destination=None,selected='SOURCE'):
    a=target('source','AWS::EntityResolution::IdNamespace',IdNamespaceName='source',Type='SOURCE',IdMappingWorkflowProperties=[{'IdMappingType':'RULE_BASED','RuleBasedProperties':{'RuleDefinitionTypes':['SOURCE','TARGET'] if source is None else source}}])
    b=target('target','AWS::EntityResolution::IdNamespace',IdNamespaceName='target',Type='TARGET',IdMappingWorkflowProperties=[{'IdMappingType':'RULE_BASED','RuleBasedProperties':{'RuleDefinitionTypes':['SOURCE','TARGET'] if destination is None else destination}}])
    rows=[{'Type':role,'InputSourceARN':'arn:aws:entityresolution:'+r.scope.region+':'+r.scope.account+':idnamespace/'+r.id} for r,role in [(a,'SOURCE'),(b,'TARGET')]]
    w=target('workflow','AWS::EntityResolution::IdMappingWorkflow',IdMappingTechniques={'IdMappingType':'RULE_BASED','RuleBasedProperties':{'RuleDefinitionType':selected}},InputSourceConfig=rows)
    d=linked_design(w,[a,b],[('InputSourceConfig/0/InputSourceARN',a.id),('InputSourceConfig/1/InputSourceARN',b.id)])
    return d,w,a,b


@pytest.mark.parametrize('source,destination,selected,workflow,namespace',[
    (['SOURCE'],['SOURCE'],'SOURCE','PASS','PASS'),
    (['TARGET'],['TARGET'],'TARGET','PASS','PASS'),
    (['SOURCE','TARGET'],['SOURCE'],'SOURCE','PASS','PASS'),
    (['SOURCE'],['TARGET'],'SOURCE','FAIL','FAIL'),
    (['SOURCE'],['SOURCE'],'TARGET','FAIL','PASS'),
    (['SOURCE'],['SOURCE'],UNKNOWN,'NEEDS_REVIEW','PASS'),
    (['SOURCE'],['TARGET'],UNKNOWN,'FAIL','FAIL'),
    ([],['SOURCE'],'SOURCE','NEEDS_REVIEW','NEEDS_REVIEW'),
    (UNKNOWN,['SOURCE'],'SOURCE','NEEDS_REVIEW','NEEDS_REVIEW'),
    (['OTHER'],['SOURCE'],'SOURCE','NEEDS_REVIEW','NEEDS_REVIEW'),
])
def test_rule_sets(source,destination,selected,workflow,namespace):
    d,w,a,b=fixture(source,destination,selected)
    assert evaluate_entityresolution_rule_compatibility(d,w)[0]['verdict']==workflow
    assert evaluate_entityresolution_rule_compatibility(d,a)[0]['verdict']==namespace


@pytest.mark.parametrize('mode',['cross_account','conditional','duplicate','external','region','template','arn_account','arn_name','input_role','unknown_parent'])
def test_reference_guards(mode):
    d,w,a,b=fixture()
    rows=next(f for f in w.fields if f.path=='/properties/InputSourceConfig').candidates[0]
    if mode=='cross_account':
        b.scope.account='999999999999';rows.value[1]['InputSourceARN']=rows.value[1]['InputSourceARN'].replace(a.scope.account,b.scope.account)
    if mode=='conditional':d.relations[-1].condition='maybe'
    if mode=='duplicate':d.relations.append(d.relations[-1].model_copy(update={'id':'duplicate'}))
    if mode=='external':d.relations.pop()
    if mode=='region':b.scope.region='us-east-1'
    if mode=='template':b.template=TemplateContext(state='UNRESOLVED')
    if mode=='arn_account':rows.value[1]['InputSourceARN']=rows.value[1]['InputSourceARN'].replace(b.scope.account,'999999999999')
    if mode=='arn_name':rows.value[1]['InputSourceARN']=rows.value[1]['InputSourceARN'].replace('idnamespace/target','idnamespace/wrong')
    if mode=='input_role':rows.value[1]['Type']='SOURCE'
    if mode=='unknown_parent':rows.value=UNKNOWN
    assert evaluate_entityresolution_rule_compatibility(d,w)[0]['verdict']==('PASS' if mode=='cross_account' else 'NEEDS_REVIEW')


def test_no_external_consumer_inference():
    d,w,a,b=fixture();d.resources.remove(w);d.relations=[]
    assert evaluate_entityresolution_rule_compatibility(d,a)[0]['verdict']=='NEEDS_REVIEW'


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1];d,w,a,b=fixture(['SOURCE'],['TARGET'])
    assert any(f['rule_id']=='ENTITY_MAPPING_RULE_DEFINITION_ALLOWED' and f['verdict']=='FAIL' for f in Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results'])
