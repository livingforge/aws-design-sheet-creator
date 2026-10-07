"""Source-backed WAF Classic scalar constraints missing from the pinned schema."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.literals import expand, literal
from ..common.scoped_resolution import resolved
from .byte_match_fields import FIELDS
from .size_constraints import TRANSFORMS

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={
 'WAF_CLASSIC_BYTE_NAME_DATA':[CF+'aws-'+p+'-'+s+'-bytematchset'+suffix+'.html' for s in ('waf','wafregional') for p,suffix in [('resource',''),('properties','-fieldtomatch')]],
 'WAF_CLASSIC_SQL_ENUMS':[CF+'aws-properties-waf-sqlinjectionmatchset-'+s+'.html' for s in ('sqlinjectionmatchtuple','fieldtomatch')],
}


def scalar_findings(design,resource):
    if resource.type in ('AWS::WAF::ByteMatchSet','AWS::WAFRegional::ByteMatchSet'):
        rule='WAF_CLASSIC_BYTE_NAME_DATA'
        specs=[('Name',None),('ByteMatchTuples/*/FieldToMatch/Data',None)]
    elif resource.type=='AWS::WAF::SqlInjectionMatchSet':
        rule='WAF_CLASSIC_SQL_ENUMS'
        specs=[('SqlInjectionMatchTuples/*/TextTransformation',TRANSFORMS),('SqlInjectionMatchTuples/*/FieldToMatch/Type',FIELDS)]
    else:return []
    ctx=_Context(design,resource);out=[];seen=set()
    for suffix,allowed in specs:
        pattern='/properties/'+suffix
        for path in expand(ctx,resource,pattern):
            if path in seen:continue
            seen.add(path);raw=value(ctx,resource,path);verdict='NEEDS_REVIEW'
            exact=re.fullmatch(re.escape(pattern).replace(r'\*',r'\d+'),path)
            if resolved(resource) and exact and isinstance(raw,str) and (literal(raw) or raw==''):
                if allowed is not None:verdict='PASS' if raw in allowed else 'FAIL'
                elif raw.isascii() and '\r' not in raw and '\n' not in raw:
                    verdict='PASS' if 1<=len(raw)<=128 and re.fullmatch(r'.*\S.*',raw,re.ASCII) else 'FAIL'
            f=ctx.finding(rule,path,verdict,'Documented Classic scalar constraint: ByteMatchSet Name and present FieldToMatch.Data have length 1..128 and pattern .*\\S.*; SQL field types and transformations use the documented allowed values. Unknown ancestors and substitutions remain reviewable. Non-ASCII and line-break pattern semantics remain reviewable. Required/conditional presence and other contextual constraints are separate; PASS does not imply service availability.')
            f['source_checked_at']='2026-10-04';out.append(f)
    return out


@resource_check('AWS::WAF::ByteMatchSet','AWS::WAF::SqlInjectionMatchSet')
def evaluate_waf_scalar_values(design,resource):return scalar_findings(design,resource)


@resource_check('AWS::WAFRegional::ByteMatchSet')
def evaluate_wafregional_scalar_values(design,resource):return scalar_findings(design,resource)
