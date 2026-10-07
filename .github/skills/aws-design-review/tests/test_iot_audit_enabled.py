import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.iot.audit_enabled import evaluate_iot_audit_enabled, CHECKS
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN


@pytest.mark.parametrize('name',list(CHECKS))
@pytest.mark.parametrize('flag,expected',[(True,'PASS'),(False,'FAIL'),(None,'FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_every_documented_check(name,flag,expected):
    r=target('scheduled','AWS::IoT::ScheduledAudit',TargetCheckNames=[name])
    c=target('config','AWS::IoT::AccountAuditConfiguration',AccountId='111111111111',AuditCheckConfigurations={} if flag is None else {CHECKS[name]:{'Enabled':flag}})
    d=linked_design(r,[c])
    assert evaluate_iot_audit_enabled(d,r)[0]['verdict']==expected
    assert evaluate_iot_audit_enabled(d,c)[0]['verdict']==('FAIL' if expected=='FAIL' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('context',['missing','duplicate','scope','account','template','scheduled_template','future'])
def test_incomplete_or_ambiguous_evidence(context):
    r=target('scheduled','AWS::IoT::ScheduledAudit',TargetCheckNames=['FUTURE_CHECK' if context=='future' else 'LOGGING_DISABLED_CHECK'])
    c=target('config','AWS::IoT::AccountAuditConfiguration',AccountId='222222222222' if context=='account' else '111111111111',AuditCheckConfigurations={'LoggingDisabledCheck':{'Enabled':False}})
    d=linked_design(r,[] if context=='missing' else [c])
    if context=='duplicate':d.resources.append(c.model_copy(update={'id':'other'}))
    if context=='scope':c.scope.region='us-east-1'
    if context=='template':c.template=TemplateContext(state='UNRESOLVED')
    if context=='scheduled_template':r.template=TemplateContext(state='UNRESOLVED')
    assert evaluate_iot_audit_enabled(d,r)[0]['verdict']=='NEEDS_REVIEW'


def test_known_disabled_witness_with_unknown_check():
    r=target('scheduled','AWS::IoT::ScheduledAudit',TargetCheckNames=[UNKNOWN,'LOGGING_DISABLED_CHECK'])
    c=target('config','AWS::IoT::AccountAuditConfiguration',AccountId='111111111111',AuditCheckConfigurations={'LoggingDisabledCheck':{'Enabled':False}})
    d=linked_design(r,[c])
    assert evaluate_iot_audit_enabled(d,r)[0]['verdict']=='FAIL'


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('scheduled','AWS::IoT::ScheduledAudit',TargetCheckNames=['DEVICE_CERTIFICATE_AGE_CHECK'])
    c=target('config','AWS::IoT::AccountAuditConfiguration',AccountId='111111111111',AuditCheckConfigurations={'DeviceCertificateAgeCheck':{'Enabled':False}})
    d=linked_design(r,[c]);found=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(d)['results']
    assert all(any(f['rule_id']==rule and f['verdict']=='FAIL' for f in found) for rule in ('IOT_SCHEDULED_AUDIT_ENABLED_CHECKS','IOT_ACCOUNT_AUDIT_USED_CHECKS'))
