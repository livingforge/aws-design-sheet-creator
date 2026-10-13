"""Bounded CQL type syntax for explicit nested UDT/collection FROZEN checks."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.literals import expand, literal
from ..common.scoped_resolution import resolved

SOURCES={'CASSANDRA_UDT_FIELD_FROZEN':[
 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-cassandra-type-field.html',
 'https://docs.aws.amazon.com/keyspaces/latest/devguide/udts.html']}
PRIMITIVES=set('ascii bigint blob boolean counter date decimal double duration float inet int smallint text time timestamp timeuuid tinyint uuid varchar varint'.split())
ARITY={'frozen':1,'list':1,'set':1,'map':2}


def parse_type(raw):
    if not literal(raw) or len(raw)>8192:return None
    if not re.fullmatch(r'[A-Za-z0-9_<>,\s]+',raw):return None
    tokens=re.findall(r'[A-Za-z_][A-Za-z0-9_]*|[<>,]',raw)
    if len(tokens)>512 or ''.join(tokens)!=re.sub(r'\s+','',raw):return None
    pos=0
    def node(depth):
        nonlocal pos
        if depth>32 or pos>=len(tokens) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',tokens[pos]):raise ValueError
        name=tokens[pos].lower();pos+=1;children=[]
        if pos<len(tokens) and tokens[pos]=='<':
            pos+=1;children.append(node(depth+1))
            while pos<len(tokens) and tokens[pos]==',':pos+=1;children.append(node(depth+1))
            if pos>=len(tokens) or tokens[pos]!='>':raise ValueError
            pos+=1
        if name in ARITY and len(children)!=ARITY[name] or name not in ARITY and children:raise ValueError
        return name,children
    try:
        tree=node(0)
        return tree if pos==len(tokens) else None
    except ValueError:return None


def keyspace(ctx,r):
    if not resolved(r):return None
    k=linked(ctx,r,'/properties/KeyspaceName','AWS::Cassandra::Keyspace')
    if resolved(k):return ('resource',k.id)
    raw=value(ctx,r,'/properties/KeyspaceName')
    return ('name',raw) if literal(raw) and re.fullmatch(r'[a-z][a-z0-9_]*',raw) else None


def frozen_field(ctx,r,raw):
    tree=parse_type(raw)
    if tree is None:return 'NEEDS_REVIEW'
    scope=keyspace(ctx,r)
    def visit(node,frozen=False):
        name,children=node
        if name=='frozen':return visit(children[0],True)
        if name in PRIMITIVES:return 'PASS' if not frozen else 'NEEDS_REVIEW'
        if name in ('map','list','set'):
            if not frozen:return 'FAIL'
            # Outer serialization does not establish support for every nested grammar.
            for child in children:
                childname,_=child
                if childname in ('map','list','set'):return 'NEEDS_REVIEW'
                v=visit(child)
                if v!='PASS':return 'NEEDS_REVIEW'
            return 'PASS'
        if scope is None:return 'NEEDS_REVIEW'
        matches=[t for t in ctx.design.resources if t.type=='AWS::Cassandra::Type' and t.scope==r.scope and keyspace(ctx,t)==scope and value(ctx,t,'/properties/TypeName')==name]
        if len(matches)!=1 or matches[0].id==r.id:return 'NEEDS_REVIEW'
        return 'PASS' if frozen else 'FAIL'
    return visit(tree)


@resource_check('AWS::Cassandra::Type')
def evaluate_cassandra_cql_types(design,resource):
    if resource.type!='AWS::Cassandra::Type':return []
    ctx=_Context(design,resource);results=[]
    for path in expand(ctx,resource,'/properties/Fields/*/FieldType'):
        f=ctx.finding('CASSANDRA_UDT_FIELD_FROZEN',path,frozen_field(ctx,resource,value(ctx,resource,path)),
            'known nested UDT or collection field requires FROZEN; bounded unquoted grammar only; quoted/qualified names, unknown/ambiguous types, self-reference, deeper collection semantics, cycles and service availability remain held')
        f['source_checked_at']='2026-10-04';results.append(f)
    return results
