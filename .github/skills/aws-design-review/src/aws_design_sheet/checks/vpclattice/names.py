"""Design-local VPC Lattice uniqueness with explicit parent references."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.literals import known_scope, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={
 'VPCLATTICE_LISTENER_NAME_UNIQUE':[CF+'aws-resource-vpclattice-listener.html'],
 'VPCLATTICE_RULE_NAME_UNIQUE':[CF+'aws-resource-vpclattice-rule.html'],
 'VPCLATTICE_RULE_PRIORITY_UNIQUE':[CF+'aws-resource-vpclattice-rule.html'],
 'VPCLATTICE_SERVICE_NAME_UNIQUE':[CF+'aws-resource-vpclattice-service.html']}


def parent(ctx,resource,kind):
 if not known_scope(resource):return None
 if kind=='Service':return ('scope',)
 key,expected=('ServiceIdentifier','Service') if kind=='Listener' else ('ListenerIdentifier','Listener')
 target=linked(ctx,resource,'/properties/'+key,'AWS::VpcLattice::'+expected)
 return ('resource',target.id) if target else None


@resource_check('AWS::VpcLattice::Service','AWS::VpcLattice::Listener','AWS::VpcLattice::Rule')
def evaluate_vpclattice_names(design,resource):
 kind=resource.type.removeprefix('AWS::VpcLattice::')
 if resource.type!='AWS::VpcLattice::'+kind or kind not in ('Service','Listener','Rule'):return []
 ctx=_Context(design,resource);results=[];own=parent(ctx,resource,kind)
 for key in ('Name','Priority') if kind=='Rule' else ('Name',):
  path='/properties/'+key
  def known(x):return type(x) is int and 1<=x<=100 if key=='Priority' else literal(x)
  raw=value(ctx,resource,path);pending=not known(raw) or own is None;duplicate=False
  for other in design.resources:
   if other.id==resource.id or other.type!=resource.type or other.scope!=resource.scope:continue
   other_value=value(ctx,other,path)
   if known(raw) and known(other_value) and raw!=other_value:continue
   identity=parent(ctx,other,kind)
   if own and identity and own!=identity:continue
   if known(raw) and known(other_value) and raw==other_value and own and identity==own:duplicate=True
   else:pending=True
  rule='VPCLATTICE_'+kind.upper()+'_'+key.upper()+'_UNIQUE'
  verdict='FAIL' if duplicate else 'NEEDS_REVIEW' if pending else 'PASS'
  results.append(ctx.finding(rule,path,verdict,'checks explicit names or integer priorities among same-scope design resources with explicit same-parent links; generated/unknown values, literal or conditional parent references, service/listener consistency and external/account-wide resources remain unverified'))
 return results
