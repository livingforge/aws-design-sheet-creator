"""Application Auto Scaling query flags and bounded arithmetic dependencies."""
import ast
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
PAGES=[CF+'aws-properties-applicationautoscaling-scalingpolicy-'+p+'.html' for p in ('targettrackingmetricdataquery','predictivescalingmetricdataquery')]
SOURCES={
 'APPLICATION_SCALING_QUERY_IDS':PAGES,
 'APPLICATION_SCALING_QUERY_RETURN_DATA':PAGES,
 'APPLICATION_SCALING_ARITHMETIC_GRAPH':PAGES+['https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/using-metric-math.html'],
}
IDENT=re.compile(r'[a-z][A-Za-z0-9_]*')


def arithmetic_refs(raw):
    # Parse only arithmetic, without evaluating or loading anything.
    if not literal(raw) or len(raw)>2048 or not re.fullmatch(r'[A-Za-z0-9_+*/^().\s-]+',raw) or '**' in raw or '//' in raw:return None
    try:tree=ast.parse(raw.replace('^','**').strip(),mode='eval')
    except (SyntaxError,ValueError,RecursionError):return None
    refs=set();nodes=list(ast.walk(tree))
    if len(nodes)>500:return None
    allowed=(ast.Expression,ast.BinOp,ast.UnaryOp,ast.Name,ast.Constant,ast.Load,ast.Add,ast.Sub,ast.Mult,ast.Div,ast.Pow,ast.USub,ast.UAdd)
    for node in nodes:
        if not isinstance(node,allowed):return None
        if isinstance(node,ast.Name):
            if not IDENT.fullmatch(node.id):return None
            refs.add(node.id)
        if isinstance(node,ast.Constant) and type(node.value) not in (int,float):return None
    return refs


def graph_verdict(ids,expressions,metrics):
    if len(ids)!=len(set(ids)) or any(not literal(i) or not IDENT.fullmatch(i) for i in ids):return 'NEEDS_REVIEW'
    graph={}
    for name,expr,metric in zip(ids,expressions,metrics):
        if expr is ABSENT:
            if not isinstance(metric,dict) or '$state' in metric:return 'NEEDS_REVIEW'
            graph[name]=set()
        else:
            if metric is not ABSENT:return 'NEEDS_REVIEW'
            refs=arithmetic_refs(expr)
            if refs is None:return 'NEEDS_REVIEW'
            graph[name]=refs
    if any(ref not in graph for refs in graph.values() for ref in refs):return 'FAIL'
    # Kahn elimination avoids recursion on user-supplied dependency depth.
    remaining={name:set(refs) for name,refs in graph.items()}
    while remaining:
        ready={name for name,refs in remaining.items() if not refs}
        if not ready:return 'FAIL'
        remaining={name:refs-ready for name,refs in remaining.items() if name not in ready}
    return 'PASS'


@resource_check('AWS::ApplicationAutoScaling::ScalingPolicy')
def evaluate_applicationautoscaling_metric_queries(design,resource):
    if resource.type!='AWS::ApplicationAutoScaling::ScalingPolicy':return []
    ctx=_Context(design,resource);results=[]
    paths=list(expand(ctx,resource,'/properties/TargetTrackingScalingPolicyConfiguration/CustomizedMetricSpecification/Metrics'))
    for kind in ('CustomizedScalingMetricSpecification','CustomizedLoadMetricSpecification','CustomizedCapacityMetricSpecification'):
        paths.extend(expand(ctx,resource,'/properties/PredictiveScalingPolicyConfiguration/MetricSpecifications/*/'+kind+'/MetricDataQueries'))
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    for path in dict.fromkeys(paths):
        raw=value(ctx,resource,path)
        if not isinstance(raw,list) or not 1<=len(raw)<=500:
            for rule in SOURCES:emit(rule,path,'NEEDS_REVIEW','requires explicit nonempty query list of at most 500 for bounded analysis')
            continue
        ids=[value(ctx,resource,path+'/'+str(i)+'/Id') for i in range(len(raw))]
        known=[i for i in ids if literal(i)]
        identity='FAIL' if len(known)!=len(set(known)) or any(not IDENT.fullmatch(i) for i in known) else 'PASS' if len(known)==len(ids) else 'NEEDS_REVIEW'
        emit('APPLICATION_SCALING_QUERY_IDS',path,identity,'query IDs must be unique and start with a lowercase letter; missing or unresolved IDs held')
        expressions=[value(ctx,resource,path+'/'+str(i)+'/Expression') for i in range(len(raw))]
        metrics=[value(ctx,resource,path+'/'+str(i)+'/MetricStat') for i in range(len(raw))]
        returns=[value(ctx,resource,path+'/'+str(i)+'/ReturnData') for i in range(len(raw))]
        math=any(literal(e) for e in expressions)
        if not math:flags='NOT_APPLICABLE' if all(e is ABSENT for e in expressions) else 'NEEDS_REVIEW'
        elif sum(v is True for v in returns)>1 or any(v is True and e is ABSENT for v,e in zip(returns,expressions)):flags='FAIL'
        elif any(type(v) is not bool for v in returns) or any(e is not ABSENT and not literal(e) for e in expressions):flags='NEEDS_REVIEW'
        else:flags='PASS' if sum(v is True for v in returns)==1 else 'FAIL'
        emit('APPLICATION_SCALING_QUERY_RETURN_DATA',path,flags,'math requires exactly one expression ReturnData=true and false for other queries; final expression is selected by flags, not array position')
        graph=graph_verdict(ids,expressions,metrics) if identity=='PASS' else 'NEEDS_REVIEW'
        emit('APPLICATION_SCALING_ARITHMETIC_GRAPH',path,graph,'bounded arithmetic-only dependency references must exist and be acyclic; functions, strings, comparisons, dynamic expressions, output cardinality, metric dimensions and live values remain separate')
    return results
