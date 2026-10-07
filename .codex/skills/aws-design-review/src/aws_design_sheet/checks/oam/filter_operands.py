"""Checks for AWS::Oam::Link."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

SOURCES = {
    'OAM_FILTER_OPERANDS': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-oam-link-linkfilter.html',
    ],
}


def filter_operand_count(raw, field):
 # Deliberately limited grammar: no escaped quotes or expression grouping.
 # Quoted AND/OR and IN list members must never be counted as connectors.
 if not literal(raw) or '\\' in raw:return None
 quoted=r"'[^']*'"
 atom=field+r'\s+(?:(?:=|!=|LIKE|NOT\s+LIKE)\s*'+quoted+r'|(?:IN|NOT\s+IN)\s*\(\s*'+quoted+r'(?:\s*,\s*'+quoted+r')*\s*\))'
 expression=r'\s*'+atom+r'(?:\s+(?:AND|OR)\s+'+atom+r')*\s*'
 if not re.fullmatch(expression,raw):return None
 return len(re.findall(r'\b(?:AND|OR)\b',re.sub(quoted,"''",raw)))


@resource_check('AWS::Oam::Link')
def evaluate_oam_filter_operands(design,resource):
 ctx=_Context(design,resource);results=[]
 def get(p):return value(ctx,resource,p)
 def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
 if resource.type=='AWS::Oam::Link':
  for kind,field in [('LogGroupConfiguration','LogGroupName'),('MetricConfiguration','Namespace')]:
   p='/properties/LinkConfiguration/'+kind+'/Filter';raw=get(p)
   if raw is ABSENT:continue
   count=filter_operand_count(raw,field)
   emit('OAM_FILTER_OPERANDS',p,'NEEDS_REVIEW' if count is None else 'PASS' if count<=5 else 'FAIL','counts at most five AND/OR operands in a fully recognized flat filter grammar; quoted words and IN members excluded; grouping, escapes, update wildcard and unsupported syntax held')
 return results
