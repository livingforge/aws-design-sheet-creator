"""Bounded scanner for Lex's explicitly unsupported regex operators."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.literals import expand, literal

SOURCES={'LEX_SLOT_REGEX_UNSUPPORTED_OPERATORS':['https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-lex-bot-slotvalueregexfilter.html']}


def operators(raw):
    if not literal(raw) or len(raw)>300:return 'NEEDS_REVIEW'
    i=0;forbidden=False
    while i<len(raw):
        c=raw[i]
        if c=='\\':
            if i+1>=len(raw):return 'NEEDS_REVIEW'
            if raw[i+1].isalpha() and raw[i+1] not in 'AbBdDsSwWZafnrtvuxU':return 'NEEDS_REVIEW'
            i+=2;continue
        if c=='[':
            j=i+1
            if j<len(raw) and raw[j]=='^':j+=1
            if j<len(raw) and raw[j]==']':j+=1
            while j<len(raw) and raw[j]!=']':
                if raw[j]=='[':return 'NEEDS_REVIEW'
                if raw[j]=='\\':j+=1
                j+=1
            if j>=len(raw):return 'NEEDS_REVIEW'
            i=j+1;continue
        if raw.startswith('(?',i):return 'NEEDS_REVIEW'
        if c=='+' and i>0 and raw[i-1] in '?}':return 'NEEDS_REVIEW'
        if c in '*+.':forbidden=True
        if c=='{' and re.match(r'\{[0-9]*,\}',raw[i:]):forbidden=True
        i+=1
    try:re.compile(raw)
    except (re.error,OverflowError,ValueError):return 'NEEDS_REVIEW'
    return 'FAIL' if forbidden else 'PASS'


@resource_check('AWS::Lex::Bot')
def evaluate_lex_regex_operators(design,resource):
    if resource.type!='AWS::Lex::Bot':return []
    ctx=_Context(design,resource);results=[]
    pattern='/properties/BotLocales/*/SlotTypes/*/ValueSelectionSetting/RegexFilter/Pattern'
    for path in expand(ctx,resource,pattern):
        verdict=operators(value(ctx,resource,path)) if path.count('/')==pattern.count('/') else 'NEEDS_REVIEW'
        f=ctx.finding('LEX_SLOT_REGEX_UNSUPPORTED_OPERATORS',path,verdict,
            'Lex does not support unbounded *, +, {n,} repeaters or wildcard dot. Escaped literals and character-class members are not those operators. Bounded standard syntax is scanned without matching user input; advanced groups, dialect-specific or malformed syntax remain reviewable. PASS covers only this operator restriction.')
        f['source_checked_at']='2026-10-04';results.append(f)
    return results
