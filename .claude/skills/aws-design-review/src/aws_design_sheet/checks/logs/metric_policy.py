"""Local metric extraction policy limits and explicit selection-set collisions."""
import json
import re
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT

URL='https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutAccountPolicy.html'
SOURCES={rule:[URL] for rule in ('LOGS_METRIC_POLICY_COUNT','LOGS_METRIC_POLICY_OVERLAP',
    'LOGS_METRIC_POLICY_NOT_IN_SINGLETON','LOGS_METRIC_POLICY_SELECTION_VALUES')}


def selection(raw):
    if raw is ABSENT:
        return ('prefix','IN',('',))
    if not isinstance(raw,str) or len(raw)>25600:
        return None
    match=re.fullmatch(r'\s*LogGroupName(Prefix)?\s+(IN|NOT\s+IN)\s+(\[.*\])\s*',raw,re.DOTALL)
    if not match:
        return None
    try:
        values=json.loads(match[3])
    except (ValueError,RecursionError):
        return None
    # Very long/invalid names and substitutions do not establish concrete sets.
    if not isinstance(values,list) or not all(isinstance(v,str) and 0<len(v)<512 and re.fullmatch(r'[A-Za-z0-9_./#-]+',v) for v in values):
        return None
    return ('prefix' if match[1] else 'name','NOT IN' if match[2].startswith('NOT') else 'IN',tuple(values))


def contains(outer_type,outer,inner_type,inner):
    return inner.startswith(outer) if outer_type=='prefix' else inner_type=='name' and inner==outer


def overlap(left,right):
    if left is None or right is None:
        return False  # Unknown sets are never proof of an overlap.
    lt,lo,lv=left;rt,ro,rv=right
    if lo==ro=='NOT IN':
        return False  # A separate singleton rule handles this case.
    if lo==ro=='IN':
        return any(contains(lt,l,rt,r) or contains(rt,r,lt,l) for l in lv for r in rv)
    if lo=='NOT IN':
        lt,lo,lv,rt,ro,rv=rt,ro,rv,lt,lo,lv
    return any(not any(contains(rt,excluded,lt,included) for excluded in rv) for included in lv)


def metric_policy_limits(design,resource):
    ctx=_Context(design,resource)
    if value(ctx,resource,'/properties/PolicyType')!='METRIC_EXTRACTION_POLICY':
        return []
    raw=value(ctx,resource,'/properties/SelectionCriteria')
    own=selection(raw)
    rows=[]
    if raw is not ABSENT:
        rows.append(ctx.finding('LOGS_METRIC_POLICY_SELECTION_VALUES','/properties/SelectionCriteria',
            ('FAIL' if len(own[2])>50 else 'PASS') if own else 'NEEDS_REVIEW',
            'a documented IN/NOT IN list allows at most fifty values; unknown grammar and substitutions remain under review'))
    name=value(ctx,resource,'/properties/PolicyName')
    known_scope=bool(re.fullmatch(r'\d{12}',resource.scope.account) and re.fullmatch(r'[a-z]{2}(?:-[a-z]+)+-\d+',resource.scope.region))
    names=set();negative=set();all_names=set();collides=False
    if known_scope and isinstance(name,str) and name and '{' not in name:
        names.add(name)
        if raw is ABSENT:
            all_names.add(name)
        if own and own[1]=='NOT IN':
            negative.add(name)
        for other in design.resources:
            if other.id==resource.id or other.type!=resource.type or other.scope!=resource.scope:
                continue
            if value(ctx,other,'/properties/PolicyType')!='METRIC_EXTRACTION_POLICY':
                continue
            other_name=value(ctx,other,'/properties/PolicyName')
            if not isinstance(other_name,str) or not other_name or '{' in other_name or other_name==name:
                continue
            names.add(other_name)
            other_raw=value(ctx,other,'/properties/SelectionCriteria')
            other_selection=selection(other_raw)
            if other_raw is ABSENT:
                all_names.add(other_name)
            if other_selection and other_selection[1]=='NOT IN':
                negative.add(other_name)
            collides |= overlap(own,other_selection)
    for rule,bad,reason in (
        ('LOGS_METRIC_POLICY_COUNT',len(names)>5 or bool(all_names) and len(names)>1,'at most five scoped policies or one all-log-group policy may coexist'),
        ('LOGS_METRIC_POLICY_NOT_IN_SINGLETON',len(negative)>1,'at most one distinct policy may use NOT IN'),
        ('LOGS_METRIC_POLICY_OVERLAP',collides,'declared IN/NOT IN selections of distinct policies must not overlap'),
    ):
        rows.append(ctx.finding(rule,'/properties/SelectionCriteria','FAIL' if bad else 'NEEDS_REVIEW',
            reason+'; external policies, aliases and unresolved selections remain unverified'))
    return rows
