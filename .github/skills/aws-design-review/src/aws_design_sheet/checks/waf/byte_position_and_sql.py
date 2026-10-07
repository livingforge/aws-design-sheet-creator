"""Checks for these resource types:

- AWS::WAF::ByteMatchSet
- AWS::WAFRegional::ByteMatchSet
- AWS::WAFRegional::SqlInjectionMatchSet
"""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.literals import expand, literal
from .size_constraints import TRANSFORMS

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'WAF_BYTE_POSITION_VALUES': [CF+'aws-properties-waf-bytematchset-bytematchtuple.html'],
    'WAFREGIONAL_BYTE_POSITION_VALUES': [CF+'aws-properties-wafregional-bytematchset-bytematchtuple.html'],
    'WAFREGIONAL_SQL_TRANSFORMATION': [CF+'aws-properties-wafregional-sqlinjectionmatchset-sqlinjectionmatchtuple.html'],
}
POSITIONS=('CONTAINS','CONTAINS_WORD','EXACTLY','STARTS_WITH','ENDS_WITH')


def legacy_enums(design,resource,specs):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    if resource.type in specs:
        rule,pattern,allowed=specs[resource.type]
        for path in expand(ctx,resource,pattern):
            raw=value(ctx,resource,path)
            leaf=not resource.type.endswith('::ByteMatchSet') or path.count('/')==pattern.count('/')
            emit(rule,path,'NEEDS_REVIEW' if not leaf or not literal(raw) else 'PASS' if raw in allowed else 'FAIL','documented legacy enum only; other match fields, target byte length, context constraints and post-support service availability remain held')
    return results


@resource_check('AWS::WAF::ByteMatchSet')
def evaluate_waf_byte_position_and_sql(design,resource):
    return legacy_enums(design,resource,{
        'AWS::WAF::ByteMatchSet':('WAF_BYTE_POSITION_VALUES','/properties/ByteMatchTuples/*/PositionalConstraint',POSITIONS),
    })


@resource_check('AWS::WAFRegional::ByteMatchSet','AWS::WAFRegional::SqlInjectionMatchSet')
def evaluate_wafregional_byte_position_and_sql(design,resource):
    return legacy_enums(design,resource,{
        'AWS::WAFRegional::ByteMatchSet':('WAFREGIONAL_BYTE_POSITION_VALUES','/properties/ByteMatchTuples/*/PositionalConstraint',POSITIONS),
        'AWS::WAFRegional::SqlInjectionMatchSet':('WAFREGIONAL_SQL_TRANSFORMATION','/properties/SqlInjectionMatchTuples/*/TextTransformation',TRANSFORMS),
    })
