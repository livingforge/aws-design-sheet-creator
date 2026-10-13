"""S3 Express access-point name zone against the linked directory bucket."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, read
from ..common.literals import literal
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={'S3EXPRESS_ACCESS_POINT_BUCKET_ZONE':[CF+'aws-resource-s3express-accesspoint.html',CF+'aws-resource-s3express-directorybucket.html','https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-points-directory-buckets.html']}


def zone_id(raw):
    return literal(raw) and re.fullmatch(r'[a-z0-9]+(?:-[a-z0-9]+)*-az[0-9]+',raw)


def name_zone(raw,suffix):
    if not literal(raw):return None
    parts=raw.rsplit('--',2)
    if len(parts)!=3 or parts[2]!=suffix or not re.fullmatch(r'[a-z0-9][a-z0-9-]*',parts[0]) or not zone_id(parts[1]):return None
    return parts[1]


def match_zone(ctx,r):
    name=value(ctx,r,'/properties/Name')
    if name is ABSENT:return 'NOT_APPLICABLE'
    az=name_zone(name,'xa-s3')
    if not resolved(r) or az is None:return 'NEEDS_REVIEW'
    bucket=linked(ctx,r,'/properties/Bucket','AWS::S3Express::DirectoryBucket')
    if not resolved(bucket):return 'NEEDS_REVIEW'
    raw=read(ctx,r,'/properties/Bucket');bucket_name=value(ctx,bucket,'/properties/BucketName')
    if raw is not ABSENT and (not literal(raw) or raw!=bucket_name):return 'NEEDS_REVIEW'
    owner=value(ctx,r,'/properties/BucketAccountId')
    if owner is not ABSENT and owner!=bucket.scope.account:return 'NEEDS_REVIEW'
    location=value(ctx,bucket,'/properties/LocationName')
    if not zone_id(location):return 'NEEDS_REVIEW'
    if bucket_name is not ABSENT and name_zone(bucket_name,'x-s3')!=location:return 'NEEDS_REVIEW'
    return 'PASS' if az==location else 'FAIL'


@resource_check('AWS::S3Express::AccessPoint')
def evaluate_s3express_zone(design,resource):
    if resource.type!='AWS::S3Express::AccessPoint':return []
    ctx=_Context(design,resource)
    f=ctx.finding('S3EXPRESS_ACCESS_POINT_BUCKET_ZONE','/properties/Name',match_zone(ctx,resource),'An explicit access point name contains the Zone ID of the linked directory bucket LocationName. Supports declared AZ and Local Zone IDs without deriving them from Region names. Generated names, unknown values, contradictory bucket name/location and ambiguous bucket identity remain reviewable. PASS validates declared zone matching only, not permissions or availability.')
    f['source_checked_at']='2026-10-04';return [f]
