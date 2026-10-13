"""Checks for AWS::Config::DeliveryChannel."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, read
from ..common.literals import literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'CONFIG_BUCKET_OBJECT_LOCK': [CF+'aws-resource-config-deliverychannel.html', CF+'aws-resource-s3-bucket.html', CF+'aws-properties-s3-bucket-defaultretention.html', 'https://docs.aws.amazon.com/config/latest/developerguide/manage-delivery-channel.html'],
}


@resource_check('AWS::Config::DeliveryChannel')
def evaluate_config_bucket_object_lock(design, resource):
    ctx = _Context(design, resource)
    results = []
    def emit(rule, path, verdict, reason):
        finding = ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at'] = '2026-10-04'
        results.append(finding)
    if resource.type == 'AWS::Config::DeliveryChannel':
        path = '/properties/S3BucketName'
        raw = value(ctx,resource,path)
        if raw is not ABSENT:
            bucket = linked(ctx,resource,path,'AWS::S3::Bucket')
            raw_name = read(ctx,resource,path)
            if bucket and raw_name is not ABSENT and (not literal(raw_name) or raw_name != value(ctx,bucket,'/properties/BucketName')):
                bucket = None
            locked = value(ctx,bucket,'/properties/ObjectLockEnabled') if bucket else None
            config = value(ctx,bucket,'/properties/ObjectLockConfiguration') if bucket else None
            verdict = 'PASS' if locked is False and config is ABSENT else 'NEEDS_REVIEW'
            if locked is True:
                base = '/properties/ObjectLockConfiguration/Rule/DefaultRetention/'
                mode = value(ctx,bucket,base+'Mode')
                days,years = value(ctx,bucket,base+'Days'),value(ctx,bucket,base+'Years')
                if mode in ('GOVERNANCE','COMPLIANCE') and ((type(days) is int and days>0 and years is ABSENT) or (type(years) is int and years>0 and days is ABSENT)):
                    verdict = 'FAIL'
            emit('CONFIG_BUCKET_OBJECT_LOCK',path,verdict,'CF documentation prohibits Object Lock, while the Config guide narrows it to enabled default retention. Reject the shared explicit condition; lock-enabled buckets without proven default retention remain NEEDS_REVIEW. Omitted/live state, contradictory identities and external permissions remain held.')
    return results
