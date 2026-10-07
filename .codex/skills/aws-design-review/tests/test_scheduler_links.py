from pathlib import Path
import pytest
from aws_design_sheet.checks.pcaconnectorscep.challenge_connector import evaluate_pcaconnectorscep_challenge_connector
from aws_design_sheet.checks.pcs.node_idle_slurm_version import evaluate_pcs_node_idle_slurm_version
from aws_design_sheet.checks.networkfirewall.rule_order_match import evaluate_networkfirewall_rule_order_match
from aws_design_sheet.checks.registry import combine
scheduler_links_checks = combine(evaluate_pcaconnectorscep_challenge_connector, evaluate_pcs_node_idle_slurm_version, evaluate_networkfirewall_rule_order_match)
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('mode',['omitted','intune','unknown','empty','external','conditional','ambiguous','scope','template','target_template'])
def test_scep(mode):
    r=target('main','AWS::PCAConnectorSCEP::Challenge',ConnectorArn='connector')
    c=target('connector','AWS::PCAConnectorSCEP::Connector',**({} if mode=='omitted' else {'MobileDeviceManagement':UNKNOWN if mode=='unknown' else {} if mode=='empty' else {'Intune':{'TenantId':'tenant','Domain':'domain'}}}))
    d=linked_design(r,[c],[] if mode=='external' else [('ConnectorArn','connector')])
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='ambiguous':d.relations.append(d.relations[0].model_copy(update={'id':'duplicate'}))
    if mode=='scope':c.scope.account='222222222222'
    if mode=='template':r.template=TemplateContext(state='UNRESOLVED')
    if mode=='target_template':c.template=TemplateContext(state='UNRESOLVED')
    assert scheduler_links_checks(d,r)[0]['verdict']==('PASS' if mode=='omitted' else 'FAIL' if mode=='intune' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('version,verdict',[('25.11','PASS'),('26.05','PASS'),('24.11','FAIL'),('25.05','FAIL'),('25.11.1','NEEDS_REVIEW'),('25.9','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_slurm(version,verdict):
    r=target('main','AWS::PCS::ComputeNodeGroup',ClusterId='cluster',SlurmConfiguration={'ScaleDownIdleTimeInSeconds':60})
    c=target('cluster','AWS::PCS::Cluster',Scheduler={'Type':'SLURM','Version':version})
    assert scheduler_links_checks(linked_design(r,[c],[('ClusterId','cluster')]),r)[0]['verdict']==verdict


@pytest.mark.parametrize('mode',['external','conditional','unknown_setting','default_type','template'])
def test_slurm_held(mode):
    r=target('main','AWS::PCS::ComputeNodeGroup',ClusterId='cluster',SlurmConfiguration={'ScaleDownIdleTimeInSeconds':UNKNOWN if mode=='unknown_setting' else 60})
    c=target('cluster','AWS::PCS::Cluster',Scheduler={'Version':'24.11',**({} if mode=='default_type' else {'Type':'SLURM'})})
    d=linked_design(r,[c],[] if mode=='external' else [('ClusterId','cluster')])
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='template':c.template=TemplateContext(state='UNRESOLVED')
    assert scheduler_links_checks(d,r)[0]['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('mode',['same','different','unknown_policy','unknown_group','omitted_group','stateless','external','conditional','ambiguous','scope','template','group_template'])
def test_order(mode):
    r=target('main','AWS::NetworkFirewall::FirewallPolicy',FirewallPolicy={'StatefulEngineOptions':{'RuleOrder':UNKNOWN if mode=='unknown_policy' else 'STRICT_ORDER'},'StatefulRuleGroupReferences':[{'ResourceArn':'group'}]})
    g=target('group','AWS::NetworkFirewall::RuleGroup',Type='STATELESS' if mode=='stateless' else 'STATEFUL',RuleGroup={} if mode=='omitted_group' else {'StatefulRuleOptions':{'RuleOrder':UNKNOWN if mode=='unknown_group' else 'DEFAULT_ACTION_ORDER' if mode=='different' else 'STRICT_ORDER'}})
    d=linked_design(r,[g],[] if mode=='external' else [('FirewallPolicy/StatefulRuleGroupReferences/0/ResourceArn','group')])
    if mode=='conditional':d.relations[0].condition='Maybe'
    if mode=='ambiguous':d.relations.append(d.relations[0].model_copy(update={'id':'duplicate'}))
    if mode=='scope':g.scope.account='222222222222'
    if mode=='template':r.template=TemplateContext(state='UNRESOLVED')
    if mode=='group_template':g.template=TemplateContext(state='UNRESOLVED')
    assert scheduler_links_checks(d,r)[0]['verdict']==('PASS' if mode=='same' else 'FAIL' if mode=='different' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('kind',['AWS::PCAConnectorSCEP::Challenge','AWS::PCS::ComputeNodeGroup','AWS::NetworkFirewall::FirewallPolicy'])
def test_absent(kind):
    r=target('main',kind)
    assert not scheduler_links_checks(linked_design(r),r)


def test_checker_scep():
    r=target('main','AWS::PCAConnectorSCEP::Challenge',ConnectorArn='connector')
    c=target('connector','AWS::PCAConnectorSCEP::Connector',MobileDeviceManagement={'Intune':{}})
    root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r,[c],[('ConnectorArn','connector')]))['results']
    assert any(f['rule_id']=='SCEP_CHALLENGE_GENERAL_CONNECTOR' and f['verdict']=='FAIL' for f in results)
