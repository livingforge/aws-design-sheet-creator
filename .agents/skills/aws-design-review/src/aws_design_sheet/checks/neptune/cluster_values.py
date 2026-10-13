"""Checks for AWS::Neptune::EventSubscription, AWS::Neptune::GlobalCluster."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'NEPTUNE_EVENT_SOURCE_IDS': ['https://docs.aws.amazon.com/neptune/latest/apiref/API_CreateEventSubscription.html'],
    'NEPTUNE_GLOBAL_MIN_VERSION': [CF+'aws-resource-neptune-globalcluster.html'],
}


@resource_check('AWS::Neptune::EventSubscription', 'AWS::Neptune::GlobalCluster')
def evaluate_neptune_cluster_values(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::Neptune::EventSubscription':
        for path in expand(ctx,resource,'/properties/SourceIds/*'):
            raw=get(path);verdict='NEEDS_REVIEW'
            if literal(raw):verdict='PASS' if re.fullmatch(r'[A-Za-z][A-Za-z0-9-]*',raw) and not raw.endswith('-') and '--' not in raw else 'FAIL'
            emit('NEPTUNE_EVENT_SOURCE_IDS',path,verdict,'literal source identifiers must start with an ASCII letter, contain only ASCII letters/digits/hyphens and have no final or consecutive hyphens; actual sources and unknown values remain separate')
    if resource.type=='AWS::Neptune::GlobalCluster':
        path='/properties/EngineVersion';raw=get(path)
        if raw is not ABSENT:
            verdict='NEEDS_REVIEW'
            if isinstance(raw,str) and re.fullmatch(r'[0-9]{1,9}(?:\.[0-9]{1,9}){3}',raw):
                verdict='PASS' if tuple(map(int,raw.split('.')))>=(1,2,0,0) else 'FAIL'
            emit('NEPTUNE_GLOBAL_MIN_VERSION',path,verdict,'explicit four-part numeric engine version must be at least 1.2.0.0; suffixes, shortened versions, inheritance and regional/service availability remain under review')
    return results
