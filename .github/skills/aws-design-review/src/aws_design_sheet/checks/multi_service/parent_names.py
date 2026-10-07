"""Scoped name duplicates proved by explicit same-parent design references."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import known_scope, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SPECS={
 'AWS::Connect::DataTable':('CONNECT_TABLE_NAME_UNIQUE','Name',('InstanceArn',),'AWS::Connect::Instance'),
 'AWS::Connect::DataTableAttribute':('CONNECT_ATTRIBUTE_NAME_UNIQUE','Name',('DataTableArn',),'AWS::Connect::DataTable'),
 'AWS::S3Vectors::Index':('S3VECTORS_INDEX_NAME_UNIQUE','IndexName',('VectorBucketArn','VectorBucketName'),'AWS::S3Vectors::VectorBucket'),
 'AWS::Cases::CaseRule':('CASES_RULE_NAME_UNIQUE','Name',('DomainId',),'AWS::Cases::Domain'),
 'AWS::Cases::Layout':('CASES_LAYOUT_NAME_UNIQUE','Name',('DomainId',),'AWS::Cases::Domain'),
 'AWS::PCAConnectorAD::Template':('PCACONNECTORAD_TEMPLATE_NAME_UNIQUE','Name',('ConnectorArn',),'AWS::PCAConnectorAD::Connector')}
SOURCES={spec[0]:[CF+'aws-resource-'+kind.removeprefix('AWS::').replace('::','-').lower()+'.html'] for kind,spec in SPECS.items()}


def parent(ctx,resource,selectors,expected):
 if not known_scope(resource):return None
 identities=[]
 for key in selectors:
  path='/properties/'+key
  if value(ctx,resource,path) is ABSENT:continue
  target=linked(ctx,resource,path,expected)
  if target is None:return None
  identities.append(target.id)
 return identities[0] if identities and len(set(identities))==1 else None


@resource_check(
    'AWS::Connect::DataTable',
    'AWS::Connect::DataTableAttribute',
    'AWS::S3Vectors::Index',
    'AWS::Cases::CaseRule',
    'AWS::Cases::Layout',
    'AWS::PCAConnectorAD::Template',
)
def evaluate_multi_service_parent_names(design,resource):
 if resource.type not in SPECS:return []
 rule,key,selectors,expected=SPECS[resource.type];ctx=_Context(design,resource)
 path='/properties/'+key;raw=value(ctx,resource,path);own=parent(ctx,resource,selectors,expected)
 pending=not literal(raw) or own is None;duplicate=False
 for other in design.resources:
  if other.id==resource.id or other.type!=resource.type or other.scope!=resource.scope:continue
  name=value(ctx,other,path)
  if literal(raw) and literal(name) and raw!=name:continue
  identity=parent(ctx,other,selectors,expected)
  if own and identity and own!=identity:continue
  if literal(raw) and raw==name and own and identity==own:duplicate=True
  else:pending=True
 reason='checks exact explicit name duplicates within same scope and explicitly linked parent; literal/conditional/ambiguous parent identities, generated names and external resources remain unverified'
 if resource.type.startswith('AWS::Cases::'):reason+='; uniqueness is stated in pinned CloudFormation schema Name description, not repeated in current reference prose'
 return [ctx.finding(rule,path,'FAIL' if duplicate else 'NEEDS_REVIEW' if pending else 'PASS',reason)]
