import pytest
from aws_design_sheet.checks.docdb.cluster_and_subnet_group import evaluate_docdb_cluster_and_subnet_group
from aws_design_sheet.checks.docdbelastic.cluster_values import evaluate_docdbelastic_cluster_values
from aws_design_sheet.checks.efs.filesystem_modes import evaluate_efs_filesystem_modes
from aws_design_sheet.checks.config.bucket_object_lock import evaluate_config_bucket_object_lock
from aws_design_sheet.checks.registry import combine
from test_autoscaling_group_and_scaling_policy import target,linked_design,UNKNOWN
from test_template_dependencies import link
document_storage_checks = combine(evaluate_docdb_cluster_and_subnet_group, evaluate_docdbelastic_cluster_values, evaluate_efs_filesystem_modes, evaluate_config_bucket_object_lock)


@pytest.mark.parametrize('retention,want', [({'Mode':'GOVERNANCE','Days':1},'FAIL'),({'Mode':'COMPLIANCE','Years':1},'FAIL'),({},'NEEDS_REVIEW'),(UNKNOWN,'NEEDS_REVIEW'),({'Mode':'GOVERNANCE','Days':UNKNOWN},'NEEDS_REVIEW'),({'Mode':'GOVERNANCE','Days':True},'NEEDS_REVIEW'),({'Mode':'GOVERNANCE','Days':1,'Years':1},'NEEDS_REVIEW')])
def test_shared_documented_prohibition(retention,want):
    c=target('channel','AWS::Config::DeliveryChannel')
    b=target('bucket','AWS::S3::Bucket',ObjectLockEnabled=True,ObjectLockConfiguration={'Rule':{'DefaultRetention':retention}})
    d=linked_design(c,[b]);link(d,c,'S3BucketName',b)
    assert document_storage_checks(d,c)[0]['verdict']==want


def test_conflicting_literal_identity():
    c=target('channel','AWS::Config::DeliveryChannel',S3BucketName='other')
    b=target('bucket','AWS::S3::Bucket',BucketName='bucket',ObjectLockEnabled=False)
    d=linked_design(c,[b]);link(d,c,'S3BucketName',b)
    assert document_storage_checks(d,c)[0]['verdict']=='NEEDS_REVIEW'


def test_disabled_flag_with_lock_configuration():
    c=target('channel','AWS::Config::DeliveryChannel')
    b=target('bucket','AWS::S3::Bucket',ObjectLockEnabled=False,ObjectLockConfiguration=UNKNOWN)
    d=linked_design(c,[b]);link(d,c,'S3BucketName',b)
    assert document_storage_checks(d,c)[0]['verdict']=='NEEDS_REVIEW'
