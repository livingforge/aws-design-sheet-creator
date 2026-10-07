"""Checks for AWS::Budgets::Budget."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'BUDGETS_RECURSIVE_MATCH_OPTIONS': [CF+'aws-properties-budgets-budget-expressiondimensionvalues.html'],
}


@resource_check('AWS::Budgets::Budget')
def evaluate_budgets_recursive_match_options(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(p):return value(ctx,resource,p)
    def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
    if resource.type=='AWS::Budgets::Budget':
        root='/properties/Budget/FilterExpression';stack=[root] if get(root) is not ABSENT else [];visited=0
        while stack:
            p=stack.pop();visited+=1
            if visited>10000:
                emit('BUDGETS_RECURSIVE_MATCH_OPTIONS',p,'NEEDS_REVIEW','expression traversal limit reached; remaining nodes unverified');break
            if not isinstance(get(p),dict):
                emit('BUDGETS_RECURSIVE_MATCH_OPTIONS',p,'NEEDS_REVIEW','unknown expression subtree held');continue
            opt=p+'/Dimensions/MatchOptions';raw=get(opt)
            if raw is not ABSENT:emit('BUDGETS_RECURSIVE_MATCH_OPTIONS',opt,'NEEDS_REVIEW' if not isinstance(raw,list) else 'PASS' if len(raw)<=1 else 'FAIL','dimension MatchOptions has at most one entry at any And/Or/Not depth; other expression semantics separate')
            if get(p+'/Not') is not ABSENT:stack.append(p+'/Not')
            for key in ('And','Or'):
                raw=get(p+'/'+key)
                if isinstance(raw,list):stack.extend(p+'/'+key+'/'+str(i) for i in range(len(raw)))
                elif raw is not ABSENT:emit('BUDGETS_RECURSIVE_MATCH_OPTIONS',p+'/'+key,'NEEDS_REVIEW','unknown recursive expression array held')
    return results
