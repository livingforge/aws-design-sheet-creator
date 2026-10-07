from pathlib import Path
import pytest
from aws_design_sheet.checks.opensearchservice.tls_policy_values import TLS, evaluate_opensearchservice_tls_policy_values
from aws_design_sheet.checks.personalize.hpo_job_ceilings import evaluate_personalize_hpo_job_ceilings
from aws_design_sheet.checks.pinpoint.application_limits import evaluate_pinpoint_application_limits
from aws_design_sheet.checks.registry import combine
training_limits_checks = combine(evaluate_personalize_hpo_job_ceilings, evaluate_pinpoint_application_limits, evaluate_opensearchservice_tls_policy_values)
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('key,maximum',[('MaxNumberOfTrainingJobs',40),('MaxParallelTrainingJobs',10)])
@pytest.mark.parametrize('case',['max','over','zero','negative','leading_zero','fraction','unknown','dynamic','disabled','omitted_hpo'])
def test_hpo(key,maximum,case):
    raw=str(maximum) if case=='max' else '0' if case=='zero' else '-1' if case=='negative' else '01' if case=='leading_zero' else '1.5' if case=='fraction' else UNKNOWN if case=='unknown' else '${jobs}' if case=='dynamic' else str(maximum+1)
    r=target('main','AWS::Personalize::Solution',SolutionConfig={'HpoConfig':{'HpoResourceConfig':{key:raw}}},**({} if case=='omitted_hpo' else {'PerformHPO':case!='disabled'}))
    assert training_limits_checks(linked_design(r),r)[0]['verdict']==('PASS' if case=='max' else 'FAIL' if case=='over' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('key,raw,verdict',[('Daily',100,'PASS'),('Daily',101,'FAIL'),('Daily',-1,'NEEDS_REVIEW'),('Total',100,'PASS'),('Total',101,'FAIL'),('MaximumDuration',60,'PASS'),('MaximumDuration',59,'FAIL'),('MessagesPerSecond',1,'PASS'),('MessagesPerSecond',20000,'PASS'),('MessagesPerSecond',0,'FAIL'),('MessagesPerSecond',20001,'FAIL'),('Daily',True,'NEEDS_REVIEW'),('Daily',1.5,'NEEDS_REVIEW'),('Daily',UNKNOWN,'NEEDS_REVIEW')])
def test_limits(key,raw,verdict):
    r=target('main','AWS::Pinpoint::ApplicationSettings',Limits={key:raw})
    assert training_limits_checks(linked_design(r),r)[0]['verdict']==verdict


@pytest.mark.parametrize('raw,verdict',[(v,'PASS') for v in TLS]+[('TLS1.2','FAIL'),(UNKNOWN,'NEEDS_REVIEW'),('${policy}','NEEDS_REVIEW')])
def test_tls(raw,verdict):
    r=target('main','AWS::OpenSearchService::Domain',DomainEndpointOptions={'TLSSecurityPolicy':raw})
    assert training_limits_checks(linked_design(r),r)[0]['verdict']==verdict


@pytest.mark.parametrize('kind',['AWS::Personalize::Solution','AWS::Pinpoint::ApplicationSettings','AWS::OpenSearchService::Domain'])
def test_absent(kind):
    r=target('main',kind)
    assert not training_limits_checks(linked_design(r),r)


def test_checker_limit():
    r=target('main','AWS::Pinpoint::ApplicationSettings',Limits={'MessagesPerSecond':20001})
    root=Path(__file__).resolve().parents[1]
    results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    assert any(f['rule_id']=='PINPOINT_APPLICATION_LIMITS' and f['verdict']=='FAIL' for f in results)
