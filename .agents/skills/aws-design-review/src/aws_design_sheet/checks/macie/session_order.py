"""Macie session creation order within an explicitly identified template."""
from ...template_dependencies import members, ordering
from ..registry import resource_check
from ..common.context_values import _Context
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={'MACIE_SESSION_DEPENDENCY':[CF+'aws-resource-macie-'+kind+'.html' for kind in ('allowlist','customdataidentifier','findingsfilter','session')]+[CF+'aws-attribute-dependson.html']}
TYPES=('AWS::Macie::AllowList','AWS::Macie::CustomDataIdentifier','AWS::Macie::FindingsFilter')


@resource_check('AWS::Macie::AllowList', 'AWS::Macie::CustomDataIdentifier', 'AWS::Macie::FindingsFilter')
def evaluate_macie_session_order(design,resource):
    if resource.type not in TYPES:return []
    ctx=_Context(design,resource);rule='MACIE_SESSION_DEPENDENCY'
    sessions=[r for r in members(design,resource) if r.type=='AWS::Macie::Session' and resolved(r)] if resolved(resource) else []
    if len(sessions)==1:
        try:f=ordering(ctx,rule,sessions)
        except RecursionError:f=ctx.finding(rule,'/template/depends_on','NEEDS_REVIEW','Dependency graph exceeds supported traversal depth.')
    else:f=ctx.finding(rule,'/template/depends_on','NEEDS_REVIEW','No unique explicit same-template, same-scope Macie session is available.')
    f['reason']+=' Macie session must be created before this resource. Explicit DependsOn and transitive/property-reference ordering can establish this prerequisite. Missing template membership, incomplete dependency declarations, external/pre-existing sessions and ambiguous session resources remain reviewable. PASS does not certify deployed session state.'
    f['source_checked_at']='2026-10-04';return [f]
