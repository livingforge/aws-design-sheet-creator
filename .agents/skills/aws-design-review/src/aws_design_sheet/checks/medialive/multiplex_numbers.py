"""Known program-number collisions within a declared MediaLive multiplex."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, read
from ..common.literals import literal
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={'MEDIALIVE_MULTIPLEX_PROGRAM_NUMBER_COLLISION':[CF+'aws-properties-medialive-multiplexprogram-multiplexprogramsettings.html','https://docs.aws.amazon.com/medialive/latest/ug/multiplex-create.html']}


def multiplex(ctx,r):
    if not resolved(r):return None
    path='/properties/MultiplexId';raw=read(ctx,r,path)
    refs=[ref for ref in ctx.design.relations if ref.source_resource_id==r.id and ref.source_path==path]
    if refs:
        other=linked(ctx,r,path,'AWS::MediaLive::Multiplex')
        return ('resource',other.id) if resolved(other) and raw is ABSENT else None
    return ('literal',raw) if literal(raw) and raw else None


def collision(ctx,r):
    own=multiplex(ctx,r);number=value(ctx,r,'/properties/MultiplexProgramSettings/ProgramNumber');name=value(ctx,r,'/properties/ProgramName')
    if own is None or type(number) is not int or not 0<=number<=65535 or not literal(name) or not name:return 'NEEDS_REVIEW'
    for other in ctx.design.resources:
        if other.id==r.id or other.type!=r.type or other.scope!=r.scope:continue
        if multiplex(ctx,other)!=own:continue
        other_name=value(ctx,other,'/properties/ProgramName');other_number=value(ctx,other,'/properties/MultiplexProgramSettings/ProgramNumber')
        if literal(other_name) and other_name and other_name!=name and type(other_number) is int and other_number==number:return 'FAIL'
    return 'NEEDS_REVIEW'


@resource_check('AWS::MediaLive::Multiplexprogram')
def evaluate_medialive_multiplex_numbers(design,resource):
    if resource.type!='AWS::MediaLive::Multiplexprogram':return []
    ctx=_Context(design,resource)
    f=ctx.finding('MEDIALIVE_MULTIPLEX_PROGRAM_NUMBER_COLLISION','/properties/MultiplexProgramSettings/ProgramNumber',collision(ctx,resource),'Program numbers must be unique. Two distinct declared program names with the same number in the same identified multiplex are a collision. Matching literal multiplex IDs or unambiguous logical references establish the comparison scope. Absence of a known collision never certifies uniqueness because external program inventory can be incomplete.')
    f['source_checked_at']='2026-10-04';return [f]
