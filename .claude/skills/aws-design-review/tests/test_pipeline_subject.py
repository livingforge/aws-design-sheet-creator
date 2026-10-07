from pathlib import Path
import pytest
from aws_design_sheet.checks.pcaconnectorad.subject_present import evaluate_pcaconnectorad_subject_present, FLAGS
from aws_design_sheet.checks.codepipeline.artifact_ordering import evaluate_codepipeline_artifact_ordering
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from aws_design_sheet.checks.registry import combine
pipeline_subject_checks=combine(evaluate_pcaconnectorad_subject_present,evaluate_codepipeline_artifact_ordering)

def rows(kind,rule,**props):
 r=target('subject','AWS::'+kind,**props)
 return [x for x in pipeline_subject_checks(linked_design(r),r) if x['rule_id']==rule]

@pytest.mark.parametrize('version',[2,3,4])
@pytest.mark.parametrize('key',FLAGS)
def test_subject_true(version,key):
 flags={k:False for k in FLAGS};flags[key]=True
 assert rows('PCAConnectorAD::Template','PCACONNECTORAD_SUBJECT_PRESENT',Definition={'TemplateV'+str(version):{'SubjectNameFlags':flags}})[0]['verdict']=='PASS'

@pytest.mark.parametrize('version',[2,3,4])
@pytest.mark.parametrize('mode,expected',[('false','FAIL'),('empty','NEEDS_REVIEW'),('unknown','NEEDS_REVIEW'),('integer','NEEDS_REVIEW'),('future','NEEDS_REVIEW'),('partial_true','PASS')])
def test_subject_holds(version,mode,expected):
 flags={k:False for k in FLAGS}
 if mode=='empty':flags={}
 if mode=='unknown':flags[FLAGS[0]]=UNKNOWN
 if mode=='integer':flags[FLAGS[0]]=1
 if mode=='future':flags['FutureFlag']=True
 if mode=='partial_true':flags={FLAGS[0]:True}
 assert rows('PCAConnectorAD::Template','PCACONNECTORAD_SUBJECT_PRESENT',Definition={'TemplateV'+str(version):{'SubjectNameFlags':flags}})[0]['verdict']==expected

@pytest.mark.parametrize('producer,consumer,expected',[(1,2,'PASS'),(2,1,'FAIL'),(1,1,'FAIL'),(None,2,'PASS'),(None,None,'FAIL'),(UNKNOWN,2,'NEEDS_REVIEW'),(True,2,'NEEDS_REVIEW')])
def test_same_stage(producer,consumer,expected):
 a={'OutputArtifacts':[{'Name':'a'}]};b={'InputArtifacts':[{'Name':'a'}]}
 if producer is not None:a['RunOrder']=producer
 if consumer is not None:b['RunOrder']=consumer
 # Array order does not establish execution order.
 assert rows('CodePipeline::Pipeline','CODEPIPELINE_INPUT_PRECEDES',Stages=[{'Actions':[b,a]}])[0]['verdict']==expected

@pytest.mark.parametrize('mode,expected',[('earlier','PASS'),('later','FAIL'),('missing','FAIL'),('self','FAIL'),('duplicate','NEEDS_REVIEW'),('unknown_output','NEEDS_REVIEW'),('unknown_stage','NEEDS_REVIEW')])
def test_pipeline_resolution(mode,expected):
 a={'OutputArtifacts':[{'Name':'a'}]};b={'InputArtifacts':[{'Name':'a'}]}
 stages=[{'Actions':[a]},{'Actions':[b]}]
 if mode=='later':stages.reverse()
 if mode=='missing':stages=[{'Actions':[b]}]
 if mode=='self':stages=[{'Actions':[{**a,**b}]}]
 if mode=='duplicate':stages[0]['Actions'].append(a)
 if mode=='unknown_output':stages[0]['Actions'].append({'OutputArtifacts':UNKNOWN})
 if mode=='unknown_stage':stages.insert(0,UNKNOWN)
 assert rows('CodePipeline::Pipeline','CODEPIPELINE_INPUT_PRECEDES',Stages=stages)[0]['verdict']==expected

@pytest.mark.parametrize('names,primary,expected',[
 (['a','b'],None,'FAIL'),(['a','b'],'a','PASS'),(['a','b'],'c','FAIL'),
 (['a',UNKNOWN],'c','NEEDS_REVIEW'),(['a',UNKNOWN],'a','PASS'),
 (['a'],None,'NEEDS_REVIEW'),(['a'],UNKNOWN,'NEEDS_REVIEW'),(['a'],'b','FAIL')])
def test_primary(names,primary,expected):
 a={'ActionTypeId':{'Provider':'CodeBuild'},'InputArtifacts':[{'Name':n} for n in names]}
 if primary is not None:a['Configuration']={'PrimarySource':primary}
 assert rows('CodePipeline::Pipeline','CODEPIPELINE_PRIMARY_SOURCE',Stages=[{'Actions':[a]}])[0]['verdict']==expected

def test_checker():
 from aws_design_sheet.checker import Checker
 root=Path(__file__).resolve().parents[1]
 r=target('subject','AWS::PCAConnectorAD::Template',Definition={'TemplateV2':{'SubjectNameFlags':{k:False for k in FLAGS}}})
 result=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
 row=next(x for x in result if x['rule_id']=='PCACONNECTORAD_SUBJECT_PRESENT')
 assert row['verdict']=='FAIL' and row['source_urls'] and row['evidence_ids']
