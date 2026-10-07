import json
import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.fms.json import evaluate_fms_json
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


def evaluate(kind,data,template=False):
    r=target('main','AWS::FMS::Policy',SecurityServicePolicyData={'Type':kind,'ManagedServiceData':data if isinstance(data,str) else json.dumps({'type':kind,**data})})
    if template:r.template=TemplateContext(state='UNRESOLVED')
    return evaluate_fms_json(linked_design(r),r)[0]['verdict']


@pytest.mark.parametrize('key,low,high',[('preProcessRuleGroups',1,99),('postProcessRuleGroups',9901,10000)])
@pytest.mark.parametrize('which',['below','low','high','above','bool','float','string','unknown','missing'])
def test_priority_boundaries(key,low,high,which):
    v={'below':low-1,'low':low,'high':high,'above':high+1,'bool':True,'float':float(low),'string':str(low),'unknown':UNKNOWN}.get(which)
    row={} if which=='missing' else {'priority':v}
    expected='FAIL' if which in ('below','above') else 'PASS' if which in ('low','high') else 'NEEDS_REVIEW'
    assert evaluate('DNS_FIREWALL',{key:[row]})==expected


@pytest.mark.parametrize('config,expected',[
    ({'automaticResponseStatus':'ENABLED','automaticResponseAction':'COUNT'},'PASS'),
    ({'automaticResponseStatus':'ENABLED','automaticResponseAction':'BLOCK'},'PASS'),
    ({'automaticResponseStatus':'ENABLED'},'FAIL'),
    ({'automaticResponseStatus':'ENABLED','automaticResponseAction':'ALLOW'},'FAIL'),
    ({'automaticResponseStatus':'ENABLED','automaticResponseAction':UNKNOWN},'NEEDS_REVIEW'),
    ({'automaticResponseStatus':'DISABLED','automaticResponseAction':'BLOCK'},'NOT_APPLICABLE'),
    ({'automaticResponseStatus':'IGNORED'},'NOT_APPLICABLE'),
    ({},'NOT_APPLICABLE'),
    ({'automaticResponseStatus':'OTHER'},'NEEDS_REVIEW'),
])
def test_shield_required_does_not_mean_prohibited(config,expected):
    assert evaluate('SHIELD_ADVANCED',{'automaticResponseConfiguration':config})==expected


@pytest.mark.parametrize('logs,redactions,expected',[(1,20,'PASS'),(2,20,'FAIL'),(1,21,'FAIL'),(0,0,'PASS')])
def test_logging_counts(logs,redactions,expected):
    assert evaluate('WAFV2',{'loggingConfiguration':{'logDestinationConfigs':['arn']*logs,'redactedFields':[{'redactedFieldType':'Method'}]*redactions}})==expected


@pytest.mark.parametrize('raw',[
    '{}','null','[]','{','{"type":"DNS_FIREWALL","type":"DNS_FIREWALL"}',
    '{"type":"DNS_FIREWALL","x":NaN}',
    '{"type":"DNS_FIREWALL","preProcessRuleGroups":[{"priority":2,"priority":1}]}',
    '{"type":"DNS_FIREWALL","x":"${Value}"}',
    '{"type":"DNS_FIREWALL","x":{"Fn::If":[]}}',
    '{"type":"DNS_FIREWALL","x":'+ '['*100+'0'+']'*100+'}',
    '{"type":"DNS_FIREWALL","x":"'+ 'x'*30000+'"}',
])
def test_untrusted_json(raw):
    assert evaluate('DNS_FIREWALL',raw)=='NEEDS_REVIEW'


def test_unknown_template():
    assert evaluate('DNS_FIREWALL',{'preProcessRuleGroups':[{'priority':0}]},template=True)=='NEEDS_REVIEW'


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('main','AWS::FMS::Policy',SecurityServicePolicyData={'Type':'DNS_FIREWALL','ManagedServiceData':'{"type":"DNS_FIREWALL","preProcessRuleGroups":[{"priority":0}]}'})
    assert any(f['rule_id']=='FMS_DNS_RULE_PRIORITY' and f['verdict']=='FAIL' for f in Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results'])
