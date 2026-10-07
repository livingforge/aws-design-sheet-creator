"""Explicit normalization consumers and cleartext subtype grouping."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, read
from ..common.literals import literal
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={'ENTITY_NORMALIZATION_SUBTYPE_GROUPS':[CF+'aws-properties-entityresolution-schemamapping-schemainputattribute.html',CF+'aws-properties-entityresolution-matchingworkflow-inputsource.html','https://docs.aws.amazon.com/entityresolution/latest/userguide/create-schema-mapping.html','https://docs.aws.amazon.com/entityresolution/latest/userguide/create-matching-workflow-provider.html']}
FAMILIES={t:family for family,types in [('NAME',['NAME_FIRST','NAME_MIDDLE','NAME_LAST']),('ADDRESS',['ADDRESS_STREET1','ADDRESS_STREET2','ADDRESS_STREET3','ADDRESS_CITY','ADDRESS_STATE','ADDRESS_COUNTRY','ADDRESS_POSTALCODE']),('PHONE',['PHONE_NUMBER','PHONE_COUNTRYCODE'])] for t in types}


def schema(ctx,workflow,path):
    if not resolved(workflow):return None
    other=linked(ctx,workflow,path,'AWS::EntityResolution::SchemaMapping')
    if not resolved(other):return None
    raw=read(ctx,workflow,path)
    if raw is not ABSENT:
        m=re.fullmatch(r'arn:aws(?:-[a-z0-9-]+)?:entityresolution:([a-z0-9-]+):([0-9]{12}):schemamapping/([A-Za-z0-9_-]+)',raw) if literal(raw) else None
        if not m or (m[1],m[2],m[3])!=(other.scope.region,other.scope.account,value(ctx,other,'/properties/SchemaName')):return None
    return other


def normalization(ctx,r):
    seen=False;pending=False
    for workflow in ctx.design.resources:
        if workflow.type!='AWS::EntityResolution::MatchingWorkflow':continue
        refs=[ref for ref in ctx.design.relations if ref.source_resource_id==workflow.id and ref.target_resource_id==r.id and re.fullmatch(r'/properties/InputSourceConfig/[0-9]+/SchemaArn',ref.source_path)]
        for ref in refs:
            if schema(ctx,workflow,ref.source_path) is not r:pending=True;continue
            flag=value(ctx,workflow,ref.source_path.rsplit('/',1)[0]+'/ApplyNormalization')
            if flag is True:return True
            if flag is False:seen=True
            else:pending=True
    return False if seen and not pending else None


def groups(ctx,r):
    mode=normalization(ctx,r)
    if mode is False:return 'NOT_APPLICABLE'
    if mode is None:return 'NEEDS_REVIEW'
    raw=value(ctx,r,'/properties/MappedInputFields')
    if not isinstance(raw,list) or not 1<=len(raw)<=35:return 'NEEDS_REVIEW'
    fields=[];pending=False;seen=False
    for i in range(len(raw)):
        base=f'/properties/MappedInputFields/{i}/'
        typ=value(ctx,r,base+'Type');name=value(ctx,r,base+'GroupName');hashed=value(ctx,r,base+'Hashed')
        fields.append((typ,name,hashed))
    for typ,name,hashed in fields:
        if not literal(typ):pending=True;continue
        if typ not in FAMILIES:continue
        if hashed is not False:pending=True;continue
        if name is ABSENT or name=='':return 'FAIL'
        if not literal(name):pending=True;continue
        members=[item for item in fields if item[1]==name]
        # Console documentation explicitly permits custom group names. Do not
        # turn API prose labels NAME/ADDRESS/PHONE into a closed name enum.
        if len(members)<2 or any(not isinstance(t,str) or FAMILIES.get(t)!=FAMILIES[typ] or h is not False for t,_,h in members):pending=True
        else:seen=True
    return 'NEEDS_REVIEW' if pending else 'PASS' if seen else 'NOT_APPLICABLE'


@resource_check('AWS::EntityResolution::SchemaMapping')
def evaluate_entityresolution_normalization_groups(design,resource):
    if resource.type!='AWS::EntityResolution::SchemaMapping':return []
    ctx=_Context(design,resource)
    f=ctx.finding('ENTITY_NORMALIZATION_SUBTYPE_GROUPS','/properties/MappedInputFields',groups(ctx,resource),'A declared workflow with ApplyNormalization true requires cleartext NAME/ADDRESS/PHONE subtypes to be grouped. Custom group names are allowed by the console guide; NAME/ADDRESS/PHONE prose is not treated as an exclusive group-name enum. This check recognizes groups of at least two explicit cleartext subtypes of one family. Missing grouping fails; unknown hashing, singleton/mixed groups, external consumers and ambiguous fields remain reviewable. PASS concerns grouping, not runtime normalization results.')
    f['source_checked_at']='2026-10-04';return [f]
