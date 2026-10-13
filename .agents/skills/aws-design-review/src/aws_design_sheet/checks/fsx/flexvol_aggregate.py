"""Explicit FlexVol aggregate cardinality, independent of live capacity."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={'FSX_FLEXVOL_SINGLE_AGGREGATE':[CF+'aws-properties-fsx-volume-aggregateconfiguration.html',CF+'aws-properties-fsx-volume-ontapconfiguration.html']}


@resource_check('AWS::FSx::Volume')
def evaluate_fsx_flexvol_aggregate(design,resource):
    if resource.type!='AWS::FSx::Volume':return []
    ctx=_Context(design,resource);kind=value(ctx,resource,'/properties/VolumeType')
    if literal(kind) and kind!='ONTAP':return []
    base='/properties/OntapConfiguration';path=base+'/AggregateConfiguration/Aggregates'
    style=value(ctx,resource,base+'/VolumeStyle');raw=value(ctx,resource,path);verdict='NEEDS_REVIEW'
    if kind=='ONTAP' and (resource.template is None or resource.template.state.value=='KNOWN'):
        if style=='FLEXGROUP' or raw is ABSENT:verdict='NOT_APPLICABLE'
        elif style=='FLEXVOL' and isinstance(raw,list):verdict='PASS' if len(raw)==1 else 'FAIL'
    f=ctx.finding('FSX_FLEXVOL_SINGLE_AGGREGATE',path,verdict,'An explicitly specified FlexVol aggregate list has exactly one entry. This verifies cardinality only; aggregate name format is separately checked, and existence or capacity is external. Missing volume-style defaults, unknown containers and unresolved templates remain reviewable.')
    f['source_checked_at']='2026-10-04';return [f]
