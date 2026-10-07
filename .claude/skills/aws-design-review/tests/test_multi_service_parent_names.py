from pathlib import Path
import pytest
from aws_design_sheet.checks.multi_service.parent_names import evaluate_multi_service_parent_names, SPECS
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN

def setup(kind,mode='same',name='same'):
 _,key,selectors,expected=SPECS[kind]
 r=target('one',kind,**{key:'same'});other=target('two',kind,**{key:name})
 p=target('parent',expected);q=target('otherparent',expected)
 links=[] if mode=='literal' else [(selectors[0],p.id)]
 d=linked_design(r,[other,p,q],links)
 if d.relations:
  rel=d.relations[0].model_copy(deep=True);rel.id='other';rel.source_resource_id=other.id;rel.target_resource_id=q.id if mode=='different' else p.id;d.relations.append(rel)
 if mode=='conditional':d.relations[0].condition='Maybe'
 if mode=='cross_scope':p.scope.region='us-east-1'
 if mode=='unknown_scope':r.scope.region=other.scope.region='unknown'
 if mode=='other_account':other.scope.account='222222222222'
 return d,r

@pytest.mark.parametrize('kind',list(SPECS))
@pytest.mark.parametrize('name,expected',[('same','FAIL'),('different','PASS'),(UNKNOWN,'NEEDS_REVIEW'),(None,'NEEDS_REVIEW')])
def test_names(kind,name,expected):
 d,r=setup(kind,name=name)
 assert evaluate_multi_service_parent_names(d,r)[0]['verdict']==expected

@pytest.mark.parametrize('kind',list(SPECS))
@pytest.mark.parametrize('mode,expected',[('different','PASS'),('conditional','NEEDS_REVIEW'),('cross_scope','NEEDS_REVIEW'),('literal','NEEDS_REVIEW'),('unknown_scope','NEEDS_REVIEW'),('other_account','PASS')])
def test_parent_holds(kind,mode,expected):
 d,r=setup(kind,mode)
 assert evaluate_multi_service_parent_names(d,r)[0]['verdict']==expected

@pytest.mark.parametrize('mode,expected',[('same','FAIL'),('conflict','NEEDS_REVIEW'),('conditional','NEEDS_REVIEW')])
def test_vector_two_selectors(mode,expected):
 d,r=setup('AWS::S3Vectors::Index')
 rel=d.relations[0].model_copy(deep=True);rel.id='second';rel.source_path='/properties/VectorBucketName';rel.target_resource_id='otherparent' if mode=='conflict' else 'parent'
 if mode=='conditional':rel.condition='Maybe'
 d.relations.append(rel)
 assert evaluate_multi_service_parent_names(d,r)[0]['verdict']==expected

def test_checker():
 from aws_design_sheet.checker import Checker
 root=Path(__file__).resolve().parents[1]
 d,r=setup('AWS::Cases::Layout')
 rows=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results']
 row=next(x for x in rows if x['rule_id']=='CASES_LAYOUT_NAME_UNIQUE')
 assert row['verdict']=='FAIL' and row['source_urls'] and row['evidence_ids']
