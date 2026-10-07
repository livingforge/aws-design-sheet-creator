import pytest
from aws_design_sheet.models import TemplateContext
from aws_design_sheet.checks.datasync.report_versions import evaluate_datasync_report_versions
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_template_dependencies import link


@pytest.mark.parametrize('status,expected',[('Enabled','PASS'),('Suspended','NOT_APPLICABLE'),(UNKNOWN,'NEEDS_REVIEW'),('omitted','NEEDS_REVIEW')])
@pytest.mark.parametrize('context',['local','external','conditional','scope','template'])
def test_destination_versioning(status,expected,context):
    r=target('main','AWS::DataSync::Task',DestinationLocationArn='location',TaskReportConfig={'ObjectVersionIds':'INCLUDE'})
    location=target('location','AWS::DataSync::LocationS3',S3BucketArn='bucket')
    bucket=target('bucket','AWS::S3::Bucket',**({} if status=='omitted' else {'VersioningConfiguration':{'Status':status}}))
    d=linked_design(r,[location,bucket],[('DestinationLocationArn','location')])
    if context!='external':link(d,location,'S3BucketArn',bucket)
    if context=='conditional':d.relations[-1].condition='maybe'
    if context=='scope':bucket.scope.region='us-east-1'
    if context=='template':bucket.template=TemplateContext(state='UNRESOLVED')
    assert evaluate_datasync_report_versions(d,r)[0]['verdict']==(expected if context=='local' else 'NEEDS_REVIEW')


def test_report_bucket_is_not_transfer_destination():
    r=target('main','AWS::DataSync::Task',TaskReportConfig={'ObjectVersionIds':'INCLUDE','Destination':{'S3':{'S3BucketArn':'report'}}})
    b=target('report','AWS::S3::Bucket',VersioningConfiguration={'Status':'Enabled'})
    d=linked_design(r,[b],[('TaskReportConfig/Destination/S3/S3BucketArn','report')])
    assert evaluate_datasync_report_versions(d,r)[0]['verdict']=='NEEDS_REVIEW'


@pytest.mark.parametrize('raw,expected',[('NONE','NOT_APPLICABLE'),(UNKNOWN,'NEEDS_REVIEW'),('future','NEEDS_REVIEW')])
def test_option(raw,expected):
    r=target('main','AWS::DataSync::Task',TaskReportConfig={'ObjectVersionIds':raw})
    assert evaluate_datasync_report_versions(linked_design(r),r)[0]['verdict']==expected


def test_checker_dispatch():
    from pathlib import Path
    from aws_design_sheet.checker import Checker
    root=Path(__file__).resolve().parents[1]
    r=target('main','AWS::DataSync::Task',TaskReportConfig={'ObjectVersionIds':'INCLUDE'})
    found=Checker(root/'schemas',root/'profiles/vpc-subnet.json').check(linked_design(r))['results']
    assert any(f['rule_id']=='DATASYNC_REPORT_OBJECT_VERSION_APPLICABILITY' and f['verdict']=='NEEDS_REVIEW' for f in found)
