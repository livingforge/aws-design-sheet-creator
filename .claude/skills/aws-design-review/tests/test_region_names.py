from pathlib import Path
import pytest
from aws_design_sheet.checks.codepipeline.artifact_regions import evaluate_codepipeline_artifact_regions
from aws_design_sheet.checks.timestream.region_names import evaluate_timestream_region_names
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from aws_design_sheet.checks.registry import combine
region_names_checks=combine(evaluate_codepipeline_artifact_regions,evaluate_timestream_region_names)
HOME='ap-northeast-1'

def result(d,r):return region_names_checks(d,r)[0]['verdict']

@pytest.mark.parametrize('regions,stores,expected',[
 ([HOME],[HOME],'PASS'),(['us-east-1'],[HOME,'us-east-1'],'PASS'),
 (['us-east-1'],[HOME],'FAIL'),(['us-east-1'],['us-east-1'],'FAIL'),
 (['us-east-1'],None,'FAIL'),([HOME],None,'NOT_APPLICABLE'),
 ([UNKNOWN],[HOME],'NEEDS_REVIEW'),([None],[HOME],'NEEDS_REVIEW'),
 (['us-east-1'],[HOME,UNKNOWN],'NEEDS_REVIEW'),
 ([HOME],[],'FAIL'),([HOME],UNKNOWN,'NEEDS_REVIEW'),
 ([UNKNOWN],[],'FAIL'),([],[HOME],'NEEDS_REVIEW')])
def test_regions(regions,stores,expected):
 props={'Stages':[{'Actions':[{} if r is None else {'Region':r} for r in regions]}]}
 if stores is not None:props['ArtifactStores']=stores if isinstance(stores,dict) else [{'Region':r} for r in stores]
 r=target('pipeline','AWS::CodePipeline::Pipeline',**props)
 assert result(linked_design(r),r)==expected

@pytest.mark.parametrize('kind,key',[('Table','TableName'),('ScheduledQuery','ScheduledQueryName')])
@pytest.mark.parametrize('name,expected',[('same','FAIL'),('different','PASS'),(UNKNOWN,'NEEDS_REVIEW'),(None,'NEEDS_REVIEW')])
def test_names(kind,key,name,expected):
 r=target('one','AWS::Timestream::'+kind,DatabaseName='database',**{key:'same'})
 other=target('two',r.type,DatabaseName='database',**({key:name} if name is not None else {}))
 assert result(linked_design(r,[other]),r)==expected

@pytest.mark.parametrize('mode,expected',[('other_db','PASS'),('unknown_db','NEEDS_REVIEW'),('other_region','PASS'),('other_account','PASS'),('unknown_scope','NEEDS_REVIEW')])
def test_table_scope(mode,expected):
 r=target('one','AWS::Timestream::Table',TableName='same',DatabaseName='database')
 other=target('two',r.type,TableName='same',DatabaseName='different' if mode=='other_db' else UNKNOWN if mode=='unknown_db' else 'database')
 if mode=='other_region':other.scope.region='us-east-1'
 if mode=='other_account':other.scope.account='222222222222'
 if mode=='unknown_scope':r.scope.region=other.scope.region='unknown'
 assert result(linked_design(r,[other]),r)==expected

@pytest.mark.parametrize('mode,expected',[('same','FAIL'),('mixed','NEEDS_REVIEW'),('conditional','NEEDS_REVIEW'),('cross_scope','NEEDS_REVIEW')])
def test_database_links(mode,expected):
 r=target('one','AWS::Timestream::Table',TableName='same')
 other=target('two',r.type,TableName='same',DatabaseName='database')
 db=target('database','AWS::Timestream::Database',DatabaseName='database')
 d=linked_design(r,[other,db],[('DatabaseName',db.id)])
 if mode!='mixed':
  rel=d.relations[0].model_copy(deep=True);rel.id='other';rel.source_resource_id=other.id;d.relations.append(rel)
 if mode=='conditional':d.relations[0].condition='Maybe'
 if mode=='cross_scope':db.scope.region='us-east-1'
 assert result(d,r)==expected

def test_unknown_pipeline_scope():
 r=target('pipeline','AWS::CodePipeline::Pipeline',Stages=[{'Actions':[{'Region':HOME}]}],ArtifactStores=[{'Region':HOME}]);r.scope.region='unknown'
 assert result(linked_design(r),r)=='NEEDS_REVIEW'

def test_checker():
 from aws_design_sheet.checker import Checker
 root=Path(__file__).resolve().parents[1]
 r=target('one','AWS::Timestream::Table',DatabaseName='database',TableName='same')
 other=target('two',r.type,DatabaseName='database',TableName='same')
 rows=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r,[other]))['results']
 row=next(x for x in rows if x['rule_id']=='TIMESTREAM_TABLE_NAME_UNIQUE')
 assert row['verdict']=='FAIL' and row['source_urls'] and row['evidence_ids']
