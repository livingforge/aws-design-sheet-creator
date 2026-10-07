"""Lustre legacy repository settings versus explicit repository associations."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import literal
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={'FSX_LUSTRE_REPOSITORY_SETTINGS':[CF+'aws-properties-fsx-filesystem-lustreconfiguration.html',CF+'aws-resource-fsx-datarepositoryassociation.html']}
KEYS=('AutoImportPolicy','ExportPath','ImportedFileChunkSize','ImportPath','CopyTagsToBackups')


@resource_check('AWS::FSx::FileSystem')
def evaluate_fsx_repository_settings(design,resource):
    if resource.type!='AWS::FSx::FileSystem':return []
    ctx=_Context(design,resource);kind=value(ctx,resource,'/properties/FileSystemType')
    if literal(kind) and kind!='LUSTRE':return []
    association=False
    if resolved(resource):
        association=any(r.type=='AWS::FSx::DataRepositoryAssociation' and resolved(r) and linked(ctx,r,'/properties/FileSystemId',resource.type) is resource for r in design.resources)
    results=[]
    for key in KEYS:
        path='/properties/LustreConfiguration/'+key;raw=value(ctx,resource,path)
        verdict='NEEDS_REVIEW'
        if resolved(resource) and kind=='LUSTRE':
            if raw is ABSENT:verdict='PASS'
            elif association:
                valid=(raw is True) if key=='CopyTagsToBackups' else (type(raw) is int) if key=='ImportedFileChunkSize' else literal(raw)
                if valid:verdict='FAIL'
        f=ctx.finding('FSX_LUSTRE_REPOSITORY_SETTINGS',path,verdict,'Lustre AutoImportPolicy, ExportPath, ImportedFileChunkSize and ImportPath are unsupported with a data repository association; copying backup tags is unavailable. Explicit same-scope unconditional associations establish incompatibility. Omitted fields pass this exclusion only; an explicit false backup-tag flag remains reviewable because the source does not distinguish disabled use from omitted default. Absent design associations do not prove absence of external associations.')
        f['source_checked_at']='2026-10-04';results.append(f)
    return results
