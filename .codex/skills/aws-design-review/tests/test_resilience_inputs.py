from pathlib import Path
import pytest
from aws_design_sheet.checks.redshiftserverless.performance_level import evaluate_redshiftserverless_performance_level
from aws_design_sheet.checks.resiliencehub.app_json_syntax import evaluate_resiliencehub_app_json_syntax
from aws_design_sheet.checks.redshift.log_bucket_region import evaluate_redshift_log_bucket_region
from aws_design_sheet.checks.registry import combine
resilience_inputs_checks = combine(evaluate_redshiftserverless_performance_level, evaluate_resiliencehub_app_json_syntax, evaluate_redshift_log_bucket_region)
from aws_design_sheet.checker import Checker
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN


@pytest.mark.parametrize('raw,verdict',[(n,'PASS') for n in (1,25,50,75,100)]+[(0,'FAIL'),(26,'FAIL'),(101,'FAIL'),(True,'NEEDS_REVIEW'),(25.0,'NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW')])
def test_level(raw,verdict):
 r=target('main','AWS::RedshiftServerless::Workgroup',PricePerformanceTarget={'Level':raw})
 assert resilience_inputs_checks(linked_design(r),r)[0]['verdict']==verdict


@pytest.mark.parametrize('raw,verdict',[('{}','PASS'),('null','PASS'),('{','FAIL'),('[NaN]','FAIL'),('${body}','NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW'),(' '*256001,'NEEDS_REVIEW')],ids=['object','null','invalid','nan','dynamic','unknown','oversize'])
def test_json(raw,verdict):
 r=target('main','AWS::ResilienceHub::App',AppTemplateBody=raw)
 assert resilience_inputs_checks(linked_design(r),r)[0]['verdict']==verdict


@pytest.mark.parametrize('case',['same','different','external','conditional','duplicate','name_mismatch','unknown_name','cross_account','wrong_type'])
def test_bucket(case):
 r=target('main','AWS::Redshift::Cluster',LoggingProperties={'BucketName':UNKNOWN if case=='unknown_name' else 'log-bucket'})
 b=target('bucket','AWS::SQS::Queue' if case=='wrong_type' else 'AWS::S3::Bucket',BucketName='other-bucket' if case=='name_mismatch' else 'log-bucket')
 if case=='different':b.scope.region='us-east-1'
 if case=='cross_account':b.scope.account='222222222222'
 links=[] if case=='external' else [('LoggingProperties/BucketName','bucket')]
 if case=='duplicate':links+=links
 d=linked_design(r,[b],links)
 if case=='conditional':d.relations[0].condition='condition'
 assert resilience_inputs_checks(d,r)[0]['verdict']==('PASS' if case in ('same','cross_account') else 'FAIL' if case=='different' else 'NEEDS_REVIEW')


@pytest.mark.parametrize('kind',['AWS::RedshiftServerless::Workgroup','AWS::ResilienceHub::App','AWS::Redshift::Cluster'])
def test_absent(kind):
 r=target('main',kind);assert not resilience_inputs_checks(linked_design(r),r)


def test_checker():
 r=target('main','AWS::RedshiftServerless::Workgroup',PricePerformanceTarget={'Level':26})
 root=Path(__file__).resolve().parents[1]
 results=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
 assert any(f['rule_id']=='REDSHIFT_SERVERLESS_PERFORMANCE_LEVEL' and f['verdict']=='FAIL' for f in results)
