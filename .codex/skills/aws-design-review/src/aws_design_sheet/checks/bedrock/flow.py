"""Bounded local flow definitions and parsed condition input references."""
import ast
import json
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT, UNKNOWN
from ..common.json_verdict import json_verdict
from ..common.literals import literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={
 'BEDROCK_FLOW_NESTED_NODE_CONSTRAINTS':[CF+'aws-resource-bedrock-flow.html',CF+'aws-properties-bedrock-flow-flownode.html',CF+'aws-properties-bedrock-flow-flownodeconfiguration.html',CF+'aws-properties-bedrock-flow-loopflownodeconfiguration.html'],
 'BEDROCK_FLOW_CONDITION_INPUT_REFERENCE':[CF+'aws-properties-bedrock-flow-flowcondition.html','https://docs.aws.amazon.com/bedrock/latest/userguide/flows-nodes.html'],
}
KINDS=set('Input Output KnowledgeBase Condition Lex Prompt LambdaFunction Agent Storage Retrieval Iterator Collector InlineCode Loop LoopInput LoopController'.split())


def condition_names(raw):
    if not literal(raw) or len(raw)>2048:return None
    try:tree=ast.parse(raw.strip(),mode='eval')
    except (SyntaxError,ValueError,RecursionError):return None
    nodes=list(ast.walk(tree));names=set()
    if len(nodes)>256:return None
    allowed=(ast.Expression,ast.Compare,ast.BoolOp,ast.UnaryOp,ast.Name,ast.Constant,ast.Load,ast.Eq,ast.NotEq,ast.Gt,ast.GtE,ast.Lt,ast.LtE,ast.And,ast.Or,ast.Not,ast.USub)
    for node in nodes:
        if not isinstance(node,allowed):return None
        if isinstance(node,ast.Name):
            if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*',node.id):return None
            if node.id not in ('true','false'):names.add(node.id)
        if isinstance(node,ast.Constant) and type(node.value) not in (str,int,float,bool):return None
    return names


def parse_definition(raw):
    if json_verdict(raw)!='PASS':return None
    def unique(pairs):
        result={}
        for k,v in pairs:
            if k in result:raise ValueError
            result[k]=v
        return result
    try:data=json.loads(raw,object_pairs_hook=unique)
    except (ValueError,RecursionError):return None
    return data if isinstance(data,dict) and '$state' not in data else None


@resource_check('AWS::Bedrock::Flow')
def evaluate_bedrock_flow(design,resource):
    if resource.type!='AWS::Bedrock::Flow':return []
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        f=ctx.finding(rule,path,verdict,reason);f['source_checked_at']='2026-10-04';results.append(f)
    sources=[(p,value(ctx,resource,'/properties/'+p)) for p in ('Definition','DefinitionString','DefinitionS3Location')]
    sources=[(p,v) for p,v in sources if v is not ABSENT]
    if not sources:return []
    if len(sources)!=1 or sources[0][0]=='DefinitionS3Location':
        emit('BEDROCK_FLOW_NESTED_NODE_CONSTRAINTS','/properties','NEEDS_REVIEW','requires one local explicit definition; ambiguous sources and S3 contents held');return results
    source,raw=sources[0];base='/properties/'+source;encoded=source=='DefinitionString'
    data=parse_definition(raw) if encoded and value(ctx,resource,'/properties/DefinitionSubstitutions') is ABSENT else raw if not encoded else None
    if not isinstance(data,dict) or '$state' in data:
        emit('BEDROCK_FLOW_NESTED_NODE_CONSTRAINTS',base,'NEEDS_REVIEW','local definition must be a bounded known object or unambiguous literal JSON; substitutions, duplicate keys and non-JSON bodies held');return results
    def key(name):return name[0].lower()+name[1:] if encoded else name
    def get(path):
        if not encoded:return value(ctx,resource,path)
        node=data
        for part in path[len(base):].strip('/').split('/') if path!=base else ():
            if isinstance(node,dict):
                if '$state' in node or any(k=='Ref' or k.startswith('Fn::') for k in node):return UNKNOWN
                node=node.get(part,ABSENT)
            elif isinstance(node,list) and part.isdigit() and int(part)<len(node):node=node[int(part)]
            else:return ABSENT
        return UNKNOWN if isinstance(node,dict) and '$state' in node else node
    pending=[(base,0)];count=0
    while pending:
        root,depth=pending.pop();nodes=get(root+'/'+key('Nodes'))
        if not isinstance(nodes,list) or depth>16 or count+len(nodes)>1000:
            emit('BEDROCK_FLOW_NESTED_NODE_CONSTRAINTS',root,'NEEDS_REVIEW','requires explicit node lists within 16 nested loops and 1000 nodes');continue
        count+=len(nodes)
        for i in range(len(nodes)):
            path=root+'/'+key('Nodes')+'/'+str(i);kind=get(path+'/'+key('Type'));configpath=path+'/'+key('Configuration');config=get(configpath)
            if encoded or depth>0:
                verdict='NEEDS_REVIEW'
                if literal(kind) and kind in KINDS:
                    if isinstance(config,dict) and '$state' not in config:
                        expected=key(kind)
                        content=get(configpath+'/'+expected)
                        verdict='FAIL' if content is ABSENT else 'PASS' if isinstance(content,dict) and '$state' not in content else 'NEEDS_REVIEW'
                    elif config is ABSENT:verdict='NOT_APPLICABLE'
                    forbidden='Inputs' if kind=='Input' else 'Outputs' if kind=='Output' else None
                    if forbidden:
                        rawports=get(path+'/'+key(forbidden))
                        if isinstance(rawports,list):verdict='FAIL'
                        elif rawports is not ABSENT:verdict='NEEDS_REVIEW'
                emit('BEDROCK_FLOW_NESTED_NODE_CONSTRAINTS',path,verdict,'known nested/literal-JSON nodes reuse type-to-configuration and Input/Output port restrictions; optional configuration omission does not establish full validity; graph connectivity, schemas, model access and loop eligibility remain open')
            if kind=='Condition':
                inputs=get(path+'/'+key('Inputs'));conditionspath=configpath+'/'+key('Condition')+'/'+key('Conditions');conditions=get(conditionspath)
                names=[get(path+'/'+key('Inputs')+'/'+str(j)+'/'+key('Name')) for j in range(len(inputs))] if isinstance(inputs,list) else None
                if not isinstance(conditions,list):
                    emit('BEDROCK_FLOW_CONDITION_INPUT_REFERENCE',conditionspath,'NEEDS_REVIEW','condition list is not explicit');continue
                for j in range(len(conditions)):
                    exprpath=conditionspath+'/'+str(j)+'/'+key('Expression');expr=get(exprpath)
                    if expr is ABSENT:continue  # default branches can omit an expression
                    refs=condition_names(expr)
                    if refs is None or names is None or any(not literal(n) for n in names) or len(names)!=len(set(names)):verdict='NEEDS_REVIEW'
                    else:verdict='PASS' if refs.intersection(names) else 'FAIL'
                    emit('BEDROCK_FLOW_CONDITION_INPUT_REFERENCE',exprpath,verdict,'parsed comparison/logical expression must reference at least one named node input; quoted strings are not references; unsupported expressions, duplicate/unknown input names and dynamic values held')
            if kind=='Loop':
                nested=configpath+'/'+key('Loop')+'/'+key('Definition')
                if get(nested) is not ABSENT:pending.append((nested,depth+1))
    return results
