"""Legacy byte-match field enums and UTF-8 target byte bounds."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, literal
from .size_constraints import TRANSFORMS

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={prefix+'_BYTE_FIELD_LIMITS':[CF+'aws-properties-'+service+'-bytematchset-bytematchtuple.html',CF+'aws-properties-'+service+'-bytematchset-fieldtomatch.html'] for prefix,service in [('WAF','waf'),('WAFREGIONAL','wafregional')]}
FIELDS=('URI','QUERY_STRING','HEADER','METHOD','BODY','SINGLE_QUERY_ARG','ALL_QUERY_ARGS')


@resource_check('AWS::WAF::ByteMatchSet', 'AWS::WAFRegional::ByteMatchSet')
def evaluate_waf_byte_match_fields(design,resource):
    if resource.type not in ('AWS::WAF::ByteMatchSet','AWS::WAFRegional::ByteMatchSet'):return []
    prefix='WAF' if resource.type=='AWS::WAF::ByteMatchSet' else 'WAFREGIONAL'
    ctx=_Context(design,resource);results=[];seen=set()
    for suffix,allowed in [('TextTransformation',TRANSFORMS),('FieldToMatch/Type',FIELDS),('TargetString',None)]:
        pattern='/properties/ByteMatchTuples/*/'+suffix
        for path in expand(ctx,resource,pattern):
            if path in seen:continue
            seen.add(path);raw=value(ctx,resource,path);verdict='NEEDS_REVIEW'
            if path.count('/')==pattern.count('/'):
                if raw is ABSENT and suffix=='TargetString':continue
                if isinstance(raw,str) and (literal(raw) or raw==''):
                    if allowed is not None:verdict='PASS' if raw in allowed else 'FAIL'
                    else:
                        try:verdict='PASS' if len(raw.encode('utf8'))<=50 else 'FAIL'
                        except UnicodeEncodeError:pass
            results.append(ctx.finding(prefix+'_BYTE_FIELD_LIMITS',path,verdict,
                'Documented legacy field/transformation enums and TargetString maximum of 50 UTF-8 bytes. This is a design-value check, not a claim of current service availability. Unknown collection structure, substitutions and invalid Unicode remain reviewable; TargetStringBase64 is outside this check.'))
    return results
