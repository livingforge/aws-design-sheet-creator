import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('ids,servers,conditional,expected',[
    (['10.0.0.1','10.0.0.2'],['0x0000000000000001']*2,False,'FAIL'),
    (['10.0.0.1','10.0.0.1'],['0x0000000000000001']*2,False,'NEEDS_REVIEW'),
    (['10.0.0.1','10.0.0.2'],['0x0000000000000001','0x0000000000000002'],False,'NEEDS_REVIEW'),
    (['10.0.0.1',UNKNOWN],['0x0000000000000001']*2,False,'NEEDS_REVIEW'),
    (['10.0.0.1','10.0.0.2'],['0x0000000000000001']*2,True,'NEEDS_REVIEW'),
])
@pytest.mark.parametrize('separate',[False,True])
def test_quic_server_collision(ids,servers,conditional,expected,separate):
    entries=[{'Id':identity,'QuicServerId':server} for identity,server in zip(ids,servers)]
    groups=[target('g0','AWS::ElasticLoadBalancingV2::TargetGroup',Protocol='QUIC',TargetType='ip',Targets=entries[:1] if separate else entries)]
    if separate:
        groups.append(target('g1','AWS::ElasticLoadBalancingV2::TargetGroup',Protocol='QUIC',TargetType='ip',Targets=entries[1:]))
    action={'Type':'forward','ForwardConfig':{'TargetGroups':[{'TargetGroupArn':{'Ref':g.id}} for g in groups]}}
    main=target('listener','AWS::ElasticLoadBalancingV2::Listener',Protocol='QUIC',DefaultActions=[action])
    data=linked_design(main,groups,[(f'DefaultActions/0/ForwardConfig/TargetGroups/{i}/TargetGroupArn',g.id) for i,g in enumerate(groups)])
    if conditional:
        data.relations[0].condition='optional'
    rows={r['rule_id']:r['verdict'] for r in run_resource_checks(data,main)}
    assert rows['ELBV2_QUIC_SERVER_ID_DUPLICATE']==expected


@pytest.mark.parametrize('behavior,headers,conditional,expected',[
    ('whitelist',['Authorization'],False,'PASS'),
    ('whitelist',['authorization'],False,'PASS'),
    ('whitelist',['X-Custom'],False,'FAIL'),
    ('whitelist',[UNKNOWN],False,'NEEDS_REVIEW'),
    ('none',[],False,'FAIL'),
    ('whitelist',['Authorization'],True,'NEEDS_REVIEW'),
    (UNKNOWN,[],False,'NEEDS_REVIEW'),
])
@pytest.mark.parametrize('default',[False,True])
@pytest.mark.parametrize('group',[False,True])
def test_oac_cache_authorization(behavior,headers,conditional,expected,default,group):
    cache={'TargetOriginId':'origin','CachePolicyId':{'Ref':'policy'}}
    config={'Origins':[{'Id':'origin','OriginAccessControlId':{'Ref':'oac'}}]}
    if group:
        cache['TargetOriginId']='failover'
        config['Origins'].append({'Id':'backup'})
        config['OriginGroups']={'Items':[{'Id':'failover','Members':{'Items':[{'OriginId':'origin'},{'OriginId':'backup'}]}}]}
    cache_path='DistributionConfig/'+('DefaultCacheBehavior' if default else 'CacheBehaviors/0')
    config.update({'DefaultCacheBehavior':cache} if default else {'CacheBehaviors':[cache]})
    main=target('distribution','AWS::CloudFront::Distribution',DistributionConfig=config)
    oac=target('oac','AWS::CloudFront::OriginAccessControl',OriginAccessControlConfig={'SigningBehavior':'no-override'})
    policy=target('policy','AWS::CloudFront::CachePolicy',CachePolicyConfig={'ParametersInCacheKeyAndForwardedToOrigin':{'HeadersConfig':{'HeaderBehavior':behavior,'Headers':headers}}})
    data=linked_design(main,[oac,policy],[('DistributionConfig/Origins/0/OriginAccessControlId','oac'),(cache_path+'/CachePolicyId','policy')])
    if conditional:
        data.relations[1].condition='optional'
    row=next(r for r in run_resource_checks(data,main) if r['rule_id']=='CLOUDFRONT_OAC_AUTHORIZATION_CACHE')
    assert row['verdict']==expected
    assert row['severity']=='WARNING'


@pytest.mark.parametrize('ambiguity',['member','group','origin'])
def test_origin_group_ambiguity_does_not_prove_missing_authorization(ambiguity):
    config={'Origins':[{'Id':'primary','OriginAccessControlId':{'Ref':'oac'}},{'Id':'secondary'}],
            'OriginGroups':{'Items':[{'Id':'group','Members':{'Items':[{'OriginId':'primary'},{'OriginId':'secondary'}]}}]},
            'DefaultCacheBehavior':{'TargetOriginId':'group','CachePolicyId':{'Ref':'policy'}}}
    if ambiguity=='member':
        config['OriginGroups']['Items'][0]['Members']['Items'][1]['OriginId']=UNKNOWN
    elif ambiguity=='group':
        config['OriginGroups']['Items'].append({'Id':'group'})
    else:
        config['Origins'].append({'Id':'group'})
    main=target('distribution','AWS::CloudFront::Distribution',DistributionConfig=config)
    oac=target('oac','AWS::CloudFront::OriginAccessControl',OriginAccessControlConfig={'SigningBehavior':'no-override'})
    policy=target('policy','AWS::CloudFront::CachePolicy',CachePolicyConfig={'ParametersInCacheKeyAndForwardedToOrigin':{'HeadersConfig':{'HeaderBehavior':'none'}}})
    data=linked_design(main,[oac,policy],[('DistributionConfig/Origins/0/OriginAccessControlId','oac'),('DistributionConfig/DefaultCacheBehavior/CachePolicyId','policy')])
    row=next(r for r in run_resource_checks(data,main) if r['rule_id']=='CLOUDFRONT_OAC_AUTHORIZATION_CACHE')
    assert row['verdict']=='NEEDS_REVIEW'
