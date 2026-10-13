"""Nested WAF transform limits and explicit local reference scope checks."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, known_scope
from .inspection import API, CF, COMPONENTS, FIELD_STATEMENTS, exclusive
from .portal import byte_match_paths

CUSTOM=('Cookie','Header','QueryArgument','QueryString','UriPath')
REFERENCES={'IPSetReferenceStatement':'IPSet','RegexPatternSetReferenceStatement':'RegexPatternSet','RuleGroupReferenceStatement':'RuleGroup'}
GUIDE='https://docs.aws.amazon.com/waf/latest/developerguide/'
SOURCES={}
for kind in ('WEBACL','RULEGROUP'):
    SOURCES['WAFV2_'+kind+'_PREPARSE_LIMIT']=[API+'API_'+s+'.html' for s in FIELD_STATEMENTS]+[API+'API_PreParseTextTransformation.html']
    SOURCES['WAFV2_'+kind+'_TRANSFORM_PRIORITY']=[API+'API_TextTransformation.html']+[API+'API_'+s+'.html' for s in FIELD_STATEMENTS]
    SOURCES['WAFV2_'+kind+'_RATE_KEY_PRIORITY']=[API+'API_TextTransformation.html']+[API+'API_RateLimit'+k+'.html' for k in CUSTOM]
SOURCES['WAFV2_WEBACL_REFERENCE_SCOPE']=[GUIDE+'waf-ip-set-managing.html',GUIDE+'waf-regex-pattern-set-managing.html',GUIDE+'waf-rule-group-creating.html',CF+'aws-resource-wafv2-webacl.html',CF+'aws-resource-wafv2-rulegroup.html']


def priorities(ctx,resource,path):
    raw=value(ctx,resource,path)
    if raw is ABSENT or raw==[]:return 'FAIL'
    if not isinstance(raw,list):return 'NEEDS_REVIEW'
    seen=set();pending=False
    for i in range(len(raw)):
        priority=value(ctx,resource,path+'/'+str(i)+'/Priority')
        if type(priority) is not int:pending=True;continue
        if priority<0 or priority in seen:return 'FAIL'
        seen.add(priority)
    return 'NEEDS_REVIEW' if pending else 'PASS'


def preparse(ctx,resource,path):
    raw=value(ctx,resource,path+'/PreParseTextTransformations')
    if not isinstance(raw,list):return 'NEEDS_REVIEW'
    if len(raw)>10:return 'FAIL'
    if not raw:return 'PASS'
    field=path+'/FieldToMatch'
    if exclusive(ctx,resource,field,COMPONENTS)!='PASS':return 'NEEDS_REVIEW'
    component=value(ctx,resource,field)
    return 'PASS' if next(iter(component)) in ('SingleQueryArgument','AllQueryArguments') else 'FAIL'


def reference_scope(ctx,resource,path,kind):
    other=linked(ctx,resource,path+'/Arn','AWS::WAFv2::'+kind)
    if not other or not known_scope(resource) or not known_scope(other):return 'NEEDS_REVIEW'
    own=value(ctx,resource,'/properties/Scope');their=value(ctx,other,'/properties/Scope')
    if own not in ('REGIONAL','CLOUDFRONT') or their not in ('REGIONAL','CLOUDFRONT'):return 'NEEDS_REVIEW'
    if own==their:return 'PASS'
    # The rule-group guide explicitly allows global groups for regional apps.
    # Do not extrapolate the stricter IP/regex set rule to this case.
    if kind=='RuleGroup' and own=='REGIONAL':return 'NEEDS_REVIEW'
    return 'FAIL'


@resource_check('AWS::WAFv2::WebACL', 'AWS::WAFv2::RuleGroup')
def evaluate_wafv2_transforms(design,resource):
    if resource.type not in ('AWS::WAFv2::WebACL','AWS::WAFv2::RuleGroup'):return []
    ctx=_Context(design,resource);results=[];prefix='WAFV2_'+resource.type.split('::')[-1].upper()
    def emit(suffix,path,verdict,reason):results.append(ctx.finding(prefix+suffix,path,verdict,reason))
    kinds=FIELD_STATEMENTS+('RateBasedStatement',)+tuple(REFERENCES)
    for path,known in byte_match_paths(ctx,resource,kinds):
        if not known:
            emit('_TRANSFORM_PRIORITY',path,'NEEDS_REVIEW','unresolved or ambiguous nested statement');continue
        kind=path.rsplit('/',1)[-1]
        if kind in FIELD_STATEMENTS:
            emit('_TRANSFORM_PRIORITY',path+'/TextTransformations',priorities(ctx,resource,path+'/TextTransformations'),'nonempty normal transformation array requires unique nonnegative integer priorities; nonconsecutive values are allowed; transformation contents remain separate')
            if value(ctx,resource,path+'/PreParseTextTransformations') is not ABSENT:
                emit('_PREPARSE_LIMIT',path+'/PreParseTextTransformations',preparse(ctx,resource,path),'at most ten pre-parse transformations, supported only for SingleQueryArgument/AllQueryArguments; duplicate pre-parse priorities are not rejected without an explicit source')
        if kind=='RateBasedStatement':
            for p in expand(ctx,resource,path+'/CustomKeys/*'):
                raw=value(ctx,resource,p)
                if not isinstance(raw,dict) or len(raw)!=1:
                    emit('_RATE_KEY_PRIORITY',p,'NEEDS_REVIEW','unresolved or ambiguous custom aggregate key');continue
                key=next(iter(raw))
                if key in CUSTOM:
                    q=p+'/'+key+'/TextTransformations'
                    emit('_RATE_KEY_PRIORITY',q,priorities(ctx,resource,q),'priorities must be unique nonnegative integers within each custom key transformation list; priorities across different keys are independent')
                elif key not in ('ASN','ForwardedIP','HTTPMethod','IP','JA3Fingerprint','JA4Fingerprint','LabelNamespace'):
                    emit('_RATE_KEY_PRIORITY',p,'NEEDS_REVIEW','unknown custom aggregate key kind')
        if kind in REFERENCES and resource.type=='AWS::WAFv2::WebACL':
            emit('_REFERENCE_SCOPE',path+'/Arn',reference_scope(ctx,resource,path,REFERENCES[kind]),'explicit unconditional local reference Scope must be compatible with web ACL Scope; global RuleGroup to regional web ACL remains under review due to guide wording; external, conditional and cross-design-scope links remain unresolved')
    return results
