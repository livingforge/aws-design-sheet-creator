"""Checks for AWS::WAFv2::RuleGroup, AWS::WAFv2::WebACL."""
import base64
import binascii
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, literal

SOURCES = {
    'WAFV2_WEBACL_SEARCH_BYTES': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-wafv2-webacl-bytematchstatement.html',
        'https://docs.aws.amazon.com/waf/latest/APIReference/API_ByteMatchStatement.html',
    ],
    'WAFV2_WEBACL_INSERT_HEADER_NAMES': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-wafv2-webacl-customrequesthandling.html',
    ],
    'WAFV2_WEBACL_RESPONSE_BODY_KEY': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-wafv2-webacl-customresponse.html',
    ],
    'WAFV2_RULEGROUP_SEARCH_BYTES': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-wafv2-rulegroup-bytematchstatement.html',
        'https://docs.aws.amazon.com/waf/latest/APIReference/API_ByteMatchStatement.html',
    ],
    'WAFV2_RULEGROUP_INSERT_HEADER_NAMES': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-wafv2-rulegroup-customrequesthandling.html',
    ],
    'WAFV2_RULEGROUP_RESPONSE_BODY_KEY': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-wafv2-rulegroup-customresponse.html',
    ],
}


def byte_match_paths(ctx,resource,statement_kinds=('ByteMatchStatement',)):
    """Iterate only documented statement containers; ambiguous nodes are held."""
    pending=list(reversed(list(expand(ctx,resource,'/properties/Rules/*/Statement'))))
    while pending:
        path=pending.pop();raw=value(ctx,resource,path)
        if not isinstance(raw,dict) or len(raw)!=1:
            yield path,False
            continue
        kind=next(iter(raw));base=path+'/'+kind
        if kind in statement_kinds:yield base,True
        if kind in ('AndStatement','OrStatement'):
            pending.extend(reversed(list(expand(ctx,resource,base+'/Statements/*'))))
        elif kind=='NotStatement':pending.append(base+'/Statement')
        elif kind in ('RateBasedStatement','ManagedRuleGroupStatement'):
            nested=base+'/ScopeDownStatement'
            if value(ctx,resource,nested) is not ABSENT:pending.append(nested)
        elif kind not in statement_kinds and kind not in ('ByteMatchStatement','SqliMatchStatement','XssMatchStatement','SizeConstraintStatement','GeoMatchStatement','RuleGroupReferenceStatement','IPSetReferenceStatement','RegexPatternSetReferenceStatement','LabelMatchStatement','RegexMatchStatement','AsnMatchStatement'):
            yield path,False


def search_bytes(ctx,resource,path,known):
    if not known:return 'NEEDS_REVIEW'
    text=value(ctx,resource,path+'/SearchString');encoded=value(ctx,resource,path+'/SearchStringBase64')
    # The documented either/or does not settle precedence when both are supplied.
    if (text is ABSENT)==(encoded is ABSENT):return 'NEEDS_REVIEW'
    raw=encoded if text is ABSENT else text
    if not isinstance(raw,str) or '${' in raw or '{{' in raw:return 'NEEDS_REVIEW'
    try:data=base64.b64decode(raw,validate=True) if text is ABSENT else raw.encode('utf8')
    except (ValueError,binascii.Error):return 'NEEDS_REVIEW'
    return 'FAIL' if len(data)>200 else 'PASS'


def insert_names(ctx,resource,path):
    raw=value(ctx,resource,path);pending=not isinstance(raw,list);names=[]
    for i in range(len(raw)) if isinstance(raw,list) else ():
        name=value(ctx,resource,path+'/'+str(i)+'/Name')
        if literal(name):names.append(name)
        else:pending=True
    if len(names)!=len(set(names)):return 'FAIL'
    # Exact duplicates are unambiguous; case-fold-only collisions remain separate.
    pending|=len({n.lower() for n in names})!=len(names)
    return 'NEEDS_REVIEW' if pending else 'PASS'


def response_body_key(ctx,resource,path):
    key=value(ctx,resource,path);bodies=value(ctx,resource,'/properties/CustomResponseBodies')
    if not literal(key):return 'NEEDS_REVIEW'
    if bodies is ABSENT:return 'FAIL'
    if not isinstance(bodies,dict):return 'NEEDS_REVIEW'
    if key in bodies:return 'PASS'
    return 'FAIL' if all(literal(k) for k in bodies) else 'NEEDS_REVIEW'


@resource_check('AWS::WAFv2::WebACL', 'AWS::WAFv2::RuleGroup')
def evaluate_wafv2_portal(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    kind=resource.type.split('::')[-1]
    if resource.type in ('AWS::WAFv2::WebACL','AWS::WAFv2::RuleGroup'):
        prefix='WAFV2_'+kind.upper()
        for path,known in byte_match_paths(ctx,resource):
            emit(prefix+'_SEARCH_BYTES',path,search_bytes(ctx,resource,path,known),'search value is at most 200 UTF-8 bytes or decoded Base64 bytes through known nested statement containers; simultaneous fields, invalid Base64/Unicode and ambiguous/unknown statements remain under review')
        actions=list(expand(ctx,resource,'/properties/Rules/*/Action'))
        if kind=='WebACL' and get('/properties/DefaultAction') is not ABSENT:actions.append('/properties/DefaultAction')
        for action in actions:
            for name in ('Allow','Count','Captcha','Challenge'):
                path=action+'/'+name+'/CustomRequestHandling/InsertHeaders'
                if get(path) is not ABSENT:
                    emit(prefix+'_INSERT_HEADER_NAMES',path,insert_names(ctx,resource,path),'exact duplicate inserted header names are forbidden within each action; case-only collisions and unknown names remain under review; action compatibility is separate')
            path=action+'/Block/CustomResponse/CustomResponseBodyKey'
            if get(path) is not ABSENT:
                emit(prefix+'_RESPONSE_BODY_KEY',path,response_body_key(ctx,resource,path),'literal response-body key must exist in this resource CustomResponseBodies map; unknown maps/keys remain under review; body content validity and action compatibility are separate')
    return results
