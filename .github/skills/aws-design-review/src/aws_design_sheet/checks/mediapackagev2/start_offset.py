"""Checks for AWS::MediaPackageV2::OriginEndpoint."""
import math
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'MEDIAPACKAGE_START_OFFSET': [CF+'aws-properties-mediapackagev2-originendpoint-starttag.html'],
}


def number(raw):return type(raw) is int or type(raw) is float and math.isfinite(raw)


@resource_check('AWS::MediaPackageV2::OriginEndpoint')
def evaluate_mediapackagev2_start_offset(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(p):return value(ctx,resource,p)
    def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
    if resource.type=='AWS::MediaPackageV2::OriginEndpoint':
        segment=get('/properties/Segment/SegmentDurationSeconds')
        for kind in ('HlsManifests','LowLatencyHlsManifests'):
            for base in expand(ctx,resource,'/properties/'+kind+'/*'):
                p=base+'/StartTag/TimeOffset';offset=get(p);duration=get(base+'/ManifestWindowSeconds')
                if offset is ABSENT:continue
                v='NEEDS_REVIEW'
                if number(offset) and number(segment) and number(duration) and segment>0 and duration>0:
                    if offset>0:v='PASS' if offset<duration-3*segment else 'FAIL'
                    elif offset<0:v='PASS' if 3*segment<abs(offset)<duration else 'FAIL'
                emit('MEDIAPACKAGE_START_OFFSET',p,v,'compares explicit configured durations with strict positive/negative offset bounds; zero, omitted durations, invalid or unresolved inputs held; runtime rounded segments separate')
    return results
