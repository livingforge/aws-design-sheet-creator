"""Checks for AWS::MediaPackageV2::OriginEndpoint."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

SOURCES = {
    'MEDIAPACKAGE_MANIFEST_NAMES': ['https://docs.aws.amazon.com/cli/latest/reference/mediapackagev2/create-origin-endpoint.html'],
}


@resource_check('AWS::MediaPackageV2::OriginEndpoint')
def evaluate_mediapackagev2_manifest_names(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::MediaPackageV2::OriginEndpoint':
        groups=[];pending=False;present=False
        for key in ('HlsManifests','LowLatencyHlsManifests'):
            path='/properties/'+key;raw=get(path);names=set()
            if raw is not ABSENT:
                present=True
                if not isinstance(raw,list):pending=True
                for i in range(len(raw)) if isinstance(raw,list) else ():
                    name=get(path+'/'+str(i)+'/ManifestName')
                    if literal(name):names.add(name)
                    else:pending=True
            groups.append(names)
        if present:
            emit('MEDIAPACKAGE_MANIFEST_NAMES','/properties','FAIL' if groups[0]&groups[1] else 'NEEDS_REVIEW' if pending else 'PASS','literal HLS and low-latency HLS manifest names cannot coincide across the two arrays; defaults and unknown names are not inferred')
    return results
