"""Bounded WAF inspection checks; unresolved configuration stays under review."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT, UNKNOWN
from ..common.literals import expand, literal
from .portal import byte_match_paths

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
API='https://docs.aws.amazon.com/waf/latest/APIReference/'
SOURCES={
    'WAFV2_MANAGED_CONFIG_REQUIRED':[CF+'aws-properties-wafv2-webacl-managedrulegroupstatement.html',CF+'aws-properties-wafv2-webacl-managedrulegroupconfig.html'],
    'WAFV2_RESPONSE_INSPECTION_UNIQUE':[CF+'aws-properties-wafv2-webacl-responseinspection'+name+'.html' for name in ('statuscode','header','json','bodycontains')],
    'WAFV2_ACFP_JSON_POINTERS':[API+'API_PhoneNumberField.html',API+'API_AddressField.html'],
}
for kind in ('webacl','rulegroup'):
    SOURCES['WAFV2_'+kind.upper()+'_FIELD_MATCH']=[CF+'aws-properties-wafv2-'+kind+'-'+name+'.html' for name in ('fieldtomatch','headermatchpattern','cookiematchpattern','jsonmatchpattern','singlequeryargument')]
GROUPS=('AWSManagedRulesATPRuleSet','AWSManagedRulesACFPRuleSet','AWSManagedRulesAntiDDoSRuleSet','AWSManagedRulesBotControlRuleSet')
LEGACY=('LoginPath','PayloadType','UsernameField','PasswordField')
FIELD_STATEMENTS=('ByteMatchStatement','SqliMatchStatement','XssMatchStatement','SizeConstraintStatement','RegexPatternSetReferenceStatement','RegexMatchStatement')
COMPONENTS=('AllQueryArguments','Body','Cookies','HeaderOrder','Headers','JA3Fingerprint','JA4Fingerprint','JsonBody','Method','QueryString','SingleHeader','SingleQueryArgument','UriFragment','UriPath')


def required_config(ctx,resource,path):
    name=value(ctx,resource,path+'/Name');vendor=value(ctx,resource,path+'/VendorName')
    if not literal(name) or not literal(vendor):return 'NEEDS_REVIEW'
    if vendor!='AWS' or name not in GROUPS:return 'NOT_APPLICABLE'
    base=path+'/ManagedRuleGroupConfigs';raw=value(ctx,resource,base)
    if raw is ABSENT:return 'FAIL'
    if not isinstance(raw,list):return 'NEEDS_REVIEW'
    matches=0;pending=False;legacy=False
    for i in range(len(raw)):
        p=base+'/'+str(i);entry=value(ctx,resource,p)
        if not isinstance(entry,dict):pending=True;continue
        if any(k not in GROUPS+LEGACY for k in entry):pending=True
        item=value(ctx,resource,p+'/'+name)
        if isinstance(item,dict):matches+=1
        elif item is not ABSENT:pending=True
        legacy|=name=='AWSManagedRulesATPRuleSet' and any(value(ctx,resource,p+'/'+k) is not ABSENT for k in LEGACY)
    if matches>1 or legacy:return 'NEEDS_REVIEW'
    if matches==1:return 'PASS'
    return 'NEEDS_REVIEW' if pending else 'FAIL'


def response_unique(ctx,resource,path,kind):
    suffix='Codes' if kind=='StatusCode' else 'Strings' if kind=='BodyContains' else 'Values'
    seen=set();pending=False;duplicate=False
    for prefix in ('Success','Failure'):
        p=path+'/'+prefix+suffix;raw=value(ctx,resource,p)
        if not isinstance(raw,list) or not raw:pending=True;continue
        for i in range(len(raw)):
            item=value(ctx,resource,p+'/'+str(i))
            known=type(item) is int if kind=='StatusCode' else literal(item)
            if not known:pending=True;continue
            if item in seen:duplicate=True
            seen.add(item)
    return 'FAIL' if duplicate else 'NEEDS_REVIEW' if pending else 'PASS'


def json_pointer(raw):
    # RFC 6901 section 3, linked by AWS PhoneNumberField and AddressField.
    # This checks string syntax, not resolution against a request document.
    if not isinstance(raw,str) or '${' in raw or '{{' in raw:return 'NEEDS_REVIEW'
    if any(0xd800<=ord(c)<=0xdfff for c in raw):return 'NEEDS_REVIEW'
    return 'PASS' if raw.startswith('/') and not re.search(r'~(?![01])',raw) else 'FAIL'


def exclusive(ctx,resource,path,choices):
    raw=value(ctx,resource,path)
    if raw is ABSENT:return 'FAIL'
    if not isinstance(raw,dict):return 'NEEDS_REVIEW'
    pending=any(k not in choices for k in raw);known=0
    for k in choices:
        item=value(ctx,resource,path+'/'+k)
        if item is UNKNOWN:pending=True
        elif item is not ABSENT:known+=1
    if known>1:return 'FAIL'
    return 'NEEDS_REVIEW' if pending else 'PASS' if known==1 else 'FAIL'


def field_findings(ctx,resource,path):
    base=path+'/FieldToMatch';verdict=exclusive(ctx,resource,base,COMPONENTS)
    yield base,verdict
    if verdict!='PASS':return
    for name,choices in (('Headers',('All','IncludedHeaders','ExcludedHeaders')),('Cookies',('All','IncludedCookies','ExcludedCookies')),('JsonBody',('All','IncludedPaths'))):
        if value(ctx,resource,base+'/'+name) is not ABSENT:
            p=base+'/'+name+'/MatchPattern'
            yield p,exclusive(ctx,resource,p,choices)
    p=base+'/SingleQueryArgument'
    if value(ctx,resource,p) is not ABSENT:
        name=value(ctx,resource,p+'/Name')
        # Parent prose says 30; child schema/documentation says 64.
        verdict='NEEDS_REVIEW'
        if literal(name):verdict='PASS' if len(name)<=30 else 'FAIL' if len(name)>64 else 'NEEDS_REVIEW'
        yield p+'/Name',verdict


@resource_check('AWS::WAFv2::WebACL', 'AWS::WAFv2::RuleGroup')
def evaluate_wafv2_inspection(design,resource):
    if resource.type not in ('AWS::WAFv2::WebACL','AWS::WAFv2::RuleGroup'):return []
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    field_rule='WAFV2_'+resource.type.split('::')[-1].upper()+'_FIELD_MATCH'
    for path,known in byte_match_paths(ctx,resource,FIELD_STATEMENTS):
        if not known:emit(field_rule,path,'NEEDS_REVIEW','ambiguous or unresolved statement container');continue
        for p,verdict in field_findings(ctx,resource,path):
            emit(field_rule,p,verdict,'single field component and exclusive Headers/Cookies/JsonBody match pattern; SingleQueryArgument length 31..64 has conflicting documentation; other nested constraints remain separate')
    if resource.type!='AWS::WAFv2::WebACL':return results
    for root in expand(ctx,resource,'/properties/Rules/*/Statement'):
        statement=get(root)
        if not isinstance(statement,dict) or len(statement)!=1:
            emit('WAFV2_MANAGED_CONFIG_REQUIRED',root,'NEEDS_REVIEW','unresolved or ambiguous top-level managed rule applicability');continue
        if 'ManagedRuleGroupStatement' not in statement:continue
        base=root+'/ManagedRuleGroupStatement'
        emit('WAFV2_MANAGED_CONFIG_REQUIRED',base,required_config(ctx,resource,base),'known AWS threat mitigation group requires matching configuration object; legacy ATP fields, repeated objects and unresolved applicability remain under review; configuration contents and availability are separate')
        configs=base+'/ManagedRuleGroupConfigs'
        raw=get(configs)
        if raw is ABSENT:continue
        if not isinstance(raw,list):
            for rule in ('WAFV2_RESPONSE_INSPECTION_UNIQUE','WAFV2_ACFP_JSON_POINTERS'):
                emit(rule,configs,'NEEDS_REVIEW','unresolved managed configuration array')
            continue
        for i in range(len(raw)):
            entry=configs+'/'+str(i)
            for group in GROUPS[:2]:
                p=entry+'/'+group
                if get(p) is ABSENT:continue
                response=p+'/ResponseInspection'
                if get(response) is not ABSENT:
                    obj=get(response)
                    forms=('StatusCode','Header','Json','BodyContains')
                    if not isinstance(obj,dict) or not obj or any(k not in forms for k in obj):
                        emit('WAFV2_RESPONSE_INSPECTION_UNIQUE',response,'NEEDS_REVIEW','unresolved response inspection form')
                    else:
                        for kind in forms:
                            q=response+'/'+kind
                            if get(q) is not ABSENT:
                                emit('WAFV2_RESPONSE_INSPECTION_UNIQUE',q,response_unique(ctx,resource,q,kind),'exact typed values must be unique within and across success/failure arrays; case is significant; unknown values remain under review; CloudFront applicability is separate')
                if group!='AWSManagedRulesACFPRuleSet':continue
                request=p+'/RequestInspection';payload=get(request+'/PayloadType')
                for field in ('PhoneNumberFields','AddressFields'):
                    for q in expand(ctx,resource,request+'/'+field+'/*'):
                        verdict='NOT_APPLICABLE' if payload=='FORM_ENCODED' else json_pointer(get(q+'/Identifier')) if payload=='JSON' else 'NEEDS_REVIEW'
                        emit('WAFV2_ACFP_JSON_POINTERS',q,verdict,'JSON payload phone/address identifiers require slash-prefixed JSON pointer tokens with ~0/~1 escapes; unknown payloads remain under review; form names and request document resolution are separate')
    return results
