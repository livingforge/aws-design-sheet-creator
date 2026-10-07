import pytest
from aws_design_sheet.checks.elasticache.global_cache_mode import evaluate_elasticache_global_cache_mode
from aws_design_sheet.checks.elasticache.cluster_mode import evaluate_elasticache_cluster_mode
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


@pytest.mark.parametrize('context',['valid','cross_region','wrong_region','wrong_name','external','conditional','duplicate','scope','unknown_mode','unknown_id'])
@pytest.mark.parametrize('flag',[True,False,UNKNOWN])
def test_global_members(context,flag):
    region='us-east-1' if context=='cross_region' else 'ap-northeast-1'
    r=target('main','AWS::ElastiCache::GlobalReplicationGroup',Members=[{'ReplicationGroupId':UNKNOWN if context=='unknown_id' else 'group-name','ReplicationGroupRegion':region}],AutomaticFailoverEnabled=flag)
    g=target('group','AWS::ElastiCache::ReplicationGroup',ReplicationGroupId='other-name' if context=='wrong_name' else 'group-name',ClusterMode=UNKNOWN if context=='unknown_mode' else 'enabled');g.scope.region=region
    d=linked_design(r,[g],[] if context=='external' else [('Members/0/ReplicationGroupId','group')]*(2 if context=='duplicate' else 1))
    if context=='wrong_region':g.scope.region='us-west-2'
    if context=='scope':g.scope.account='222222222222'
    if context=='conditional':d.relations[0].condition='maybe'
    expected='PASS' if flag is True else 'FAIL' if flag is False else 'NEEDS_REVIEW'
    assert evaluate_elasticache_global_cache_mode(d,r)[0]['verdict']==(expected if context in ('valid','cross_region') else 'NEEDS_REVIEW')


@pytest.mark.parametrize('ids,count,expected',[
 (['0001','0002'],None,'FAIL'),(['1','0001'],None,'NEEDS_REVIEW'),
 (['0001',UNKNOWN],None,'NEEDS_REVIEW'),(['0001','0002',UNKNOWN],None,'FAIL'),
 (['0001','0002'],1,'NEEDS_REVIEW'),(['0001','0002'],2,'FAIL'),
 (['0001','invalid'],None,'NEEDS_REVIEW')])
def test_configured_shards(ids,count,expected):
    props={'NodeGroupConfiguration':[{'NodeGroupId':x} for x in ids]}
    if count is not None:props['NumNodeGroups']=count
    r=target('main','AWS::ElastiCache::ReplicationGroup',**props)
    assert evaluate_elasticache_cluster_mode(linked_design(r),r)[0]['verdict']==expected


@pytest.mark.parametrize('count,flag,expected',[(2,False,'FAIL'),(2,True,'PASS'),(1,False,'NEEDS_REVIEW'),(True,False,'NEEDS_REVIEW'),(UNKNOWN,False,'NEEDS_REVIEW'),(2,UNKNOWN,'NEEDS_REVIEW'),(2,None,'NEEDS_REVIEW')])
def test_global_shard_count(count,flag,expected):
    props={'GlobalNodeGroupCount':count}
    if flag is not None:props['AutomaticFailoverEnabled']=flag
    r=target('main','AWS::ElastiCache::GlobalReplicationGroup',**props)
    assert evaluate_elasticache_global_cache_mode(linked_design(r),r)[0]['verdict']==expected


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('main','AWS::ElastiCache::GlobalReplicationGroup',GlobalNodeGroupCount=2,AutomaticFailoverEnabled=False)
    found=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    assert any(f['rule_id']=='GLOBALREPLICATIONGROUP_INFERRED_FAILOVER' and f['verdict']=='FAIL' for f in found)
