"""Checks for AWS::FSx::FileSystem."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'FSX_LUSTRE_BUCKET': [CF+'aws-properties-fsx-filesystem-lustreconfiguration.html'],
    'FSX_WINDOWS_ALIASES': [CF+'aws-properties-fsx-filesystem-windowsconfiguration.html'],
    'FSX_LUSTRE_THROUGHPUT_MULTIPLE': [CF+'aws-properties-fsx-filesystem-lustreconfiguration.html'],
}


def bucket(raw):
    if not literal(raw):return None
    match=re.fullmatch(r's3://([a-z0-9][a-z0-9.-]*[a-z0-9])(?:/[^\r\n]*)?',raw)
    return match[1] if match else None


@resource_check('AWS::FSx::FileSystem')
def evaluate_fsx_file_system(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::FSx::FileSystem':
        root='/properties/LustreConfiguration';path=root+'/ExportPath';raw=get(path)
        if raw is not ABSENT:
            exported=bucket(raw);imported=bucket(get(root+'/ImportPath'))
            verdict='NEEDS_REVIEW' if exported is None or imported is None else 'PASS' if exported==imported else 'FAIL'
            emit('FSX_LUSTRE_BUCKET',path,verdict,'explicit s3:// export/import paths must identify the same bucket; omitted defaults, nonstandard URI forms, unresolved references and actual bucket access remain under review')
        path=root+'/ThroughputCapacity';raw=get(path)
        if raw is not ABSENT:
            verdict='NEEDS_REVIEW'
            if get('/properties/StorageType')=='INTELLIGENT_TIERING' and type(raw) is int:
                verdict='PASS' if raw>=4000 and raw%4000==0 else 'FAIL'
            emit('FSX_LUSTRE_THROUGHPUT_MULTIPLE',path,verdict,'explicit Intelligent-Tiering Lustre throughput must be at least 4000 and divisible by 4000; requiredness and other storage classes remain separate')
        for path in expand(ctx,resource,'/properties/WindowsConfiguration/Aliases/*'):
            raw=get(path);verdict='NEEDS_REVIEW'
            if literal(raw) and raw.isascii() and '\\' not in raw and not raw.endswith('.'):
                # Do not infer whether internal labels may start/end with a hyphen.
                if raw.startswith('-') or raw.endswith('-') or not re.fullmatch(r'[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+',raw):verdict='FAIL'
                elif any(x.startswith('-') or x.endswith('-') for x in raw.split('.')):verdict='NEEDS_REVIEW'
                else:verdict='PASS'
            emit('FSX_WINDOWS_ALIASES',path,verdict,'checks literal ASCII hostname.domain aliases and whole-name hyphen boundaries; internal label boundaries, root dots, escaped/non-ASCII names and unknown values remain under review')
    return results
