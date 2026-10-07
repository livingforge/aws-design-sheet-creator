import pytest
from aws_design_sheet.checks.common.context_values import _Context
from aws_design_sheet.checks.elasticbeanstalk.relations import same_app
from aws_design_sheet.checks.elasticbeanstalk.inheritance import effective_stack
from aws_design_sheet.models import TemplateContext
from test_autoscaling_group_and_scaling_policy import target,linked_design
from test_template_dependencies import link


@pytest.mark.parametrize('route',['source','environment','environment_template'])
@pytest.mark.parametrize('mode',['known','conditional','cycle','template','platform','app_mismatch'])
def test_inherited_stack(route,mode):
    root=target('root','AWS::ElasticBeanstalk::ConfigurationTemplate',ApplicationName='app')
    leaf=target('leaf',root.type,ApplicationName='other' if mode=='app_mismatch' else 'app',SolutionStackName='stack-v1')
    env=target('env','AWS::ElasticBeanstalk::Environment',ApplicationName='app',TemplateName='leaf')
    if route=='source':
        root=target('root',root.type,ApplicationName='app',SourceConfiguration={'ApplicationName':'app','TemplateName':'leaf'})
        d=linked_design(root,[leaf], [('SourceConfiguration/TemplateName','leaf')])
    else:
        root=target('root',root.type,ApplicationName='app',EnvironmentId='env')
        if route=='environment':env=target('env',env.type,ApplicationName='app',SolutionStackName='stack-v1')
        d=linked_design(root,[env,leaf],[('EnvironmentId','env')])
        if route=='environment_template':link(d,env,'TemplateName',leaf)
    actual_leaf=env if route=='environment' else leaf
    if mode=='conditional':d.relations[0].condition='maybe'
    if mode=='cycle':
        actual_leaf.fields=[f for f in actual_leaf.fields if f.path!='/properties/SolutionStackName']
        link(d,actual_leaf,'TemplateName' if actual_leaf.type.endswith('Environment') else 'EnvironmentId',root)
    if mode=='template':actual_leaf.template=TemplateContext(state='UNRESOLVED')
    if mode=='platform':
        root.fields.append(target('p',root.type,PlatformArn='arn:platform').fields[0])
    expected='stack-v1' if mode=='known' or (mode=='app_mismatch' and route=='environment') else None
    assert effective_stack(_Context(d,root),root,same_app)==expected


def test_cycle_and_depth_are_bounded():
    nodes=[target('t'+str(i),'AWS::ElasticBeanstalk::ConfigurationTemplate',ApplicationName='app',SourceConfiguration={'ApplicationName':'app','TemplateName':'next'}) for i in range(40)]
    d=linked_design(nodes[0],nodes[1:],[])
    for a,b in zip(nodes,nodes[1:]+nodes[:1]):link(d,a,'SourceConfiguration/TemplateName',b)
    assert effective_stack(_Context(d,nodes[0]),nodes[0],same_app) is None


@pytest.mark.parametrize('stack,expected',[('stack-v1','PASS'),('stack-v2','FAIL')])
def test_checker_inherited_comparison(stack,expected):
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    r=target('main','AWS::ElasticBeanstalk::ConfigurationTemplate',SolutionStackName='stack-v1',SourceConfiguration={'ApplicationName':'app','TemplateName':'source'})
    source=target('source',r.type,ApplicationName='app',EnvironmentId='env')
    env=target('env','AWS::ElasticBeanstalk::Environment',ApplicationName='app',SolutionStackName=stack)
    d=linked_design(r,[source,env],[('SourceConfiguration/TemplateName','source')]);link(d,source,'EnvironmentId',env)
    root=Path(__file__).resolve().parents[1]
    assert any(f['resource_id']=='main' and f['rule_id']=='BEANSTALK_SOURCE_SOLUTION_STACK' and f['verdict']==expected for f in Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results'])
