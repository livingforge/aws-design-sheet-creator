"""DMS endpoint settings whose applicability depends on explicit task consumers."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import literal
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
TASKS={'AWS::DMS::ReplicationTask':'MigrationType','AWS::DMS::ReplicationConfig':'ReplicationType'}
COMMON=[CF+'aws-resource-dms-replicationtask.html',CF+'aws-resource-dms-replicationconfig.html']
SOURCES={
 'DMS_SOURCE_CDC_PATH':COMMON+[CF+'aws-properties-dms-endpoint-s3settings.html','https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Source.S3.html'],
 'DMS_REDSHIFT_EXPLICIT_IDS_APPLICABILITY':COMMON+[CF+'aws-properties-dms-endpoint-redshiftsettings.html'],
 'DMS_BOOLEAN_MAPPING_PAIR':COMMON+[CF+'aws-properties-dms-endpoint-redshiftsettings.html',CF+'aws-properties-dms-endpoint-postgresqlsettings.html'],
}


def consumers(ctx,r,side):
    path='/properties/'+side+'EndpointArn'
    for task in ctx.design.resources:
        if task.type not in TASKS:continue
        refs=[ref for ref in ctx.design.relations if ref.source_resource_id==task.id and ref.source_path==path and ref.target_resource_id==r.id]
        if refs:yield task if resolved(task) and linked(ctx,task,path,r.type) is r else None


def extra_settings(ctx,r):
    raw=value(ctx,r,'/properties/ExtraConnectionAttributes')
    return raw is not ABSENT and raw!=''


def aggregate(verdicts):
    if 'FAIL' in verdicts:return 'FAIL'
    if not verdicts or 'NEEDS_REVIEW' in verdicts:return 'NEEDS_REVIEW'
    return 'PASS' if 'PASS' in verdicts else 'NOT_APPLICABLE'


def cdc_path(ctx,r):
    verdicts=[]
    for task in consumers(ctx,r,'Source'):
        mode=value(ctx,task,'/properties/'+TASKS[task.type]) if task else None
        fmt=value(ctx,r,'/properties/S3Settings/DataFormat')
        raw=value(ctx,r,'/properties/S3Settings/CdcPath')
        if mode not in ('full-load','cdc','full-load-and-cdc') or extra_settings(ctx,r):verdicts.append('NEEDS_REVIEW');continue
        if fmt in ('parquet','Parquet'):
            verdicts.append('PASS' if raw is ABSENT else 'FAIL' if literal(raw) else 'NEEDS_REVIEW');continue
        if fmt is not ABSENT and fmt not in ('csv','Csv'):verdicts.append('NEEDS_REVIEW');continue
        if mode=='full-load':verdicts.append('NOT_APPLICABLE');continue
        if raw is ABSENT or raw=='':verdicts.append('FAIL')
        else:verdicts.append('PASS' if literal(raw) else 'NEEDS_REVIEW')
    return aggregate(verdicts)


def explicit_ids(ctx,r):
    if extra_settings(ctx,r):return 'NEEDS_REVIEW'
    flag=value(ctx,r,'/properties/RedshiftSettings/ExplicitIds')
    if flag is ABSENT or flag is False:return 'NOT_APPLICABLE'
    if flag is not True:return 'NEEDS_REVIEW'
    verdicts=[]
    for task in consumers(ctx,r,'Target'):
        mode=value(ctx,task,'/properties/'+TASKS[task.type]) if task else None
        verdicts.append('PASS' if mode=='full-load' else 'NOT_APPLICABLE' if mode=='cdc' else 'NEEDS_REVIEW')
    if 'PASS' in verdicts and 'NOT_APPLICABLE' in verdicts:return 'NEEDS_REVIEW'
    return aggregate(verdicts)


def boolean_flag(ctx,r):
    engine=value(ctx,r,'/properties/EngineName')
    group={'postgres':'PostgreSqlSettings','redshift':'RedshiftSettings'}.get(engine) if isinstance(engine,str) else None
    if group is None or extra_settings(ctx,r):return None
    raw=value(ctx,r,'/properties/'+group+'/MapBooleanAsBoolean')
    return False if raw is ABSENT else raw if type(raw) is bool else None


def boolean_pair(ctx,r,side):
    own=boolean_flag(ctx,r)
    if own is False:return 'NOT_APPLICABLE'
    if own is None:return 'NEEDS_REVIEW'
    verdicts=[]
    for task in consumers(ctx,r,side):
        other=linked(ctx,task,'/properties/'+('Target' if side=='Source' else 'Source')+'EndpointArn',r.type) if task else None
        opposite='target' if side=='Source' else 'source'
        if not resolved(other) or value(ctx,other,'/properties/EndpointType')!=opposite:verdicts.append('NEEDS_REVIEW');continue
        flag=boolean_flag(ctx,other)
        verdicts.append('PASS' if flag is True else 'NOT_APPLICABLE' if flag is False else 'NEEDS_REVIEW')
    # Mixed consumers cannot certify that the requested conversion takes effect on all.
    if 'PASS' in verdicts and 'NOT_APPLICABLE' in verdicts:return 'NEEDS_REVIEW'
    return aggregate(verdicts)


@resource_check('AWS::DMS::Endpoint')
def evaluate_dms_task_settings(design,resource):
    if resource.type!='AWS::DMS::Endpoint':return []
    ctx=_Context(design,resource);results=[]
    engine=value(ctx,resource,'/properties/EngineName');side=value(ctx,resource,'/properties/EndpointType')
    specs=[]
    if engine=='s3' and side=='source':specs.append(('DMS_SOURCE_CDC_PATH','/properties/S3Settings/CdcPath',cdc_path))
    if engine=='redshift' and side=='target':specs.append(('DMS_REDSHIFT_EXPLICIT_IDS_APPLICABILITY','/properties/RedshiftSettings/ExplicitIds',explicit_ids))
    if engine in ('postgres','redshift') and side in ('source','target'):
        group='PostgreSqlSettings' if engine=='postgres' else 'RedshiftSettings'
        specs.append(('DMS_BOOLEAN_MAPPING_PAIR','/properties/'+group+'/MapBooleanAsBoolean',lambda c,r:boolean_pair(c,r,side.title())))
    for rule,path,fn in specs:
        verdict=fn(ctx,resource) if resolved(resource) else 'NEEDS_REVIEW'
        f=ctx.finding(rule,path,verdict,'Evaluate only explicit same-scope replication task/configuration consumers. CSV/default CDC S3 sources require CdcPath; Parquet sources must omit it. ExplicitIds is full-load-only; combined full-load-and-CDC semantics remain reviewable. Boolean conversion takes effect only when both endpoints enable it; disabled conversion is NOT_APPLICABLE, not a rejected deployment. Extra connection attributes and external consumers are not inferred.')
        f['source_checked_at']='2026-10-04';results.append(f)
    return results
