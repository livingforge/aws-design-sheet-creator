"""WAF Classic predicate kinds and explicitly referenced match-set resources."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, read
from ..common.literals import expand, literal
from ..common.scoped_resolution import resolved

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={'WAF_CLASSIC_PREDICATE_TARGET':[CF+'aws-properties-'+p+'-predicate.html' for p in ('waf-rule','wafregional-rule','wafregional-ratebasedrule')]}
KINDS={'IPMatch':'IPSet','ByteMatch':'ByteMatchSet','SqlInjectionMatch':'SqlInjectionMatchSet','SizeConstraint':'SizeConstraintSet','XssMatch':'XssMatchSet','GeoMatch':'GeoMatchSet','RegexMatch':'RegexMatchSet'}
TYPES={'AWS::WAF::Rule':'Predicates','AWS::WAFRegional::Rule':'Predicates','AWS::WAFRegional::RateBasedRule':'MatchPredicates'}


def predicate(ctx,r,path):
    if not resolved(r):return 'NEEDS_REVIEW'
    kind=value(ctx,r,path+'/Type')
    if not literal(kind):return 'NEEDS_REVIEW'
    if kind not in KINDS:return 'FAIL'
    # These match-set types are not available in the pinned CF resource inventory.
    # In particular RegexPatternSet is not a RegexMatchSet.
    if kind=='RegexMatch' or kind=='GeoMatch' and r.type=='AWS::WAF::Rule':return 'NEEDS_REVIEW'
    source=path+'/DataId'
    if read(ctx,r,source) is not ABSENT:return 'NEEDS_REVIEW'
    refs=[ref for ref in ctx.design.relations if ref.source_resource_id==r.id and ref.source_path==source]
    if len(refs)!=1 or refs[0].condition:return 'NEEDS_REVIEW'
    matches=[other for other in ctx.design.resources if other.id==refs[0].target_resource_id]
    if len(matches)!=1 or not resolved(matches[0]):return 'NEEDS_REVIEW'
    other=matches[0]
    if linked(ctx,r,source,other.type) is not other:return 'NEEDS_REVIEW'
    expected='::'.join(r.type.split('::')[:2])+'::'+KINDS[kind]
    return 'PASS' if other.type==expected else 'FAIL'


@resource_check('AWS::WAF::Rule', 'AWS::WAFRegional::Rule', 'AWS::WAFRegional::RateBasedRule')
def evaluate_waf_predicates(design,resource):
    if resource.type not in TYPES:return []
    ctx=_Context(design,resource);out=[];root='/properties/'+TYPES[resource.type]
    for path in expand(ctx,resource,root+'/*'):
        verdict=predicate(ctx,resource,path) if path!=root else 'NEEDS_REVIEW'
        f=ctx.finding('WAF_CLASSIC_PREDICATE_TARGET',path,verdict,'A WAF Classic predicate uses a documented Type and an explicitly referenced match-set resource of the corresponding kind and WAF scope. RegexMatchSet cannot be replaced by RegexPatternSet; unavailable CF target kinds remain reviewable. Literal physical IDs, unknown or conditional references and external match sets remain reviewable. PASS covers declared type compatibility only, not live service availability.')
        f['source_checked_at']='2026-10-04';out.append(f)
    return out
