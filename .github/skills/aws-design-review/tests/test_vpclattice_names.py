from pathlib import Path
import pytest
from aws_design_sheet.checks.vpclattice.names import evaluate_vpclattice_names
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN

def setup(kind,key,a,b,mode='same'):
 r=target('one','AWS::VpcLattice::'+kind,**{key:a});other=target('two',r.type,**{key:b})
 parent_kind='Service' if kind=='Listener' else 'Listener'
 p=target('parent','AWS::VpcLattice::'+parent_kind);q=target('otherparent',p.type)
 selector='ServiceIdentifier' if kind=='Listener' else 'ListenerIdentifier'
 d=linked_design(r,[other,p,q],[] if kind=='Service' or mode=='literal' else [(selector,p.id)])
 if d.relations:
  rel=d.relations[0].model_copy(deep=True);rel.id='other';rel.source_resource_id=other.id;rel.target_resource_id=q.id if mode=='different_parent' else p.id;d.relations.append(rel)
 if mode=='conditional':d.relations[0].condition='Maybe'
 if mode=='scope':p.scope.region='us-east-1'
 if mode=='different_region':other.scope.region='us-east-1'
 if mode=='unknown_scope':r.scope.region=other.scope.region='unknown'
 return d,r

def verdict(d,r,key):return next(x for x in evaluate_vpclattice_names(d,r) if x['path']=='/properties/'+key)['verdict']

@pytest.mark.parametrize('kind',['Listener','Rule','Service'])
@pytest.mark.parametrize('a,b,expected',[('same','same','FAIL'),('one','two','PASS'),('same',UNKNOWN,'NEEDS_REVIEW'),(UNKNOWN,'same','NEEDS_REVIEW'),('same',None,'NEEDS_REVIEW')])
def test_names(kind,a,b,expected):
 d,r=setup(kind,'Name',a,b)
 assert verdict(d,r,'Name')==expected

@pytest.mark.parametrize('a,b,expected',[(1,1,'FAIL'),(1,100,'PASS'),(100,100,'FAIL'),(True,1,'NEEDS_REVIEW'),(1,1.0,'NEEDS_REVIEW'),(0,0,'NEEDS_REVIEW'),(101,101,'NEEDS_REVIEW'),(1,UNKNOWN,'NEEDS_REVIEW')])
def test_priorities(a,b,expected):
 d,r=setup('Rule','Priority',a,b)
 assert verdict(d,r,'Priority')==expected

@pytest.mark.parametrize('kind',['Listener','Rule'])
@pytest.mark.parametrize('mode,expected',[('different_parent','PASS'),('conditional','NEEDS_REVIEW'),('scope','NEEDS_REVIEW'),('literal','NEEDS_REVIEW'),('different_region','PASS'),('unknown_scope','NEEDS_REVIEW')])
def test_parent_scope(kind,mode,expected):
 d,r=setup(kind,'Name','same','same',mode)
 assert verdict(d,r,'Name')==expected

def test_checker():
 from aws_design_sheet.checker import Checker
 root=Path(__file__).resolve().parents[1]
 d,r=setup('Rule','Priority',10,10)
 rows=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results']
 row=next(x for x in rows if x['rule_id']=='VPCLATTICE_RULE_PRIORITY_UNIQUE')
 assert row['verdict']=='FAIL' and row['source_urls'] and row['evidence_ids']
