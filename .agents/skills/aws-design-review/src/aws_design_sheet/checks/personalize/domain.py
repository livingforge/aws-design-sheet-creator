"""Domain schema compatibility via explicit dataset consumers."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, read
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={'PERSONALIZE_SCHEMA_GROUP_DOMAIN':[CF+'aws-resource-personalize-schema.html',CF+'aws-resource-personalize-dataset.html',CF+'aws-resource-personalize-datasetgroup.html']}


def domain(ctx,r):
    if not resolved(r):return 'NEEDS_REVIEW'
    own=value(ctx,r,'/properties/Domain');seen=False;pending=False;required=False
    for dataset in ctx.design.resources:
        if dataset.type!='AWS::Personalize::Dataset':continue
        refs=[ref for ref in ctx.design.relations if ref.source_resource_id==dataset.id and ref.source_path=='/properties/SchemaArn' and ref.target_resource_id==r.id]
        if not refs:continue
        seen=True
        if not resolved(dataset) or read(ctx,dataset,'/properties/SchemaArn') is not ABSENT or linked(ctx,dataset,'/properties/SchemaArn',r.type) is not r:
            pending=True;continue
        group=linked(ctx,dataset,'/properties/DatasetGroupArn','AWS::Personalize::DatasetGroup')
        if not resolved(group) or read(ctx,dataset,'/properties/DatasetGroupArn') is not ABSENT:
            pending=True;continue
        wanted=value(ctx,group,'/properties/Domain')
        if wanted is ABSENT:continue
        if wanted not in ('ECOMMERCE','VIDEO_ON_DEMAND'):pending=True;continue
        required=True
        if own is ABSENT or own in ('ECOMMERCE','VIDEO_ON_DEMAND') and own!=wanted:return 'FAIL'
        if own!=wanted:pending=True
    if not seen or pending:return 'NEEDS_REVIEW'
    return 'PASS' if required else 'NOT_APPLICABLE'


@resource_check('AWS::Personalize::Schema')
def evaluate_personalize_domain(design,resource):
    if resource.type!='AWS::Personalize::Schema':return []
    ctx=_Context(design,resource)
    f=ctx.finding('PERSONALIZE_SCHEMA_GROUP_DOMAIN','/properties/Domain',domain(ctx,resource),'Each explicitly linked dataset in a Domain dataset group requires its schema to declare the same domain. Custom groups do not establish this requirement. Unknown or conditional consumers, literal ARN identity and missing groups remain reviewable; PASS concerns declared consumers, not completeness of external inventory or Avro validity.')
    f['source_checked_at']='2026-10-04';return [f]
