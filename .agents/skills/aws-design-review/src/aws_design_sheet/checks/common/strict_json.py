"""Strict JSON parsing that rejects duplicate keys and oversized documents."""
import json
from .literals import literal


def parse(raw):
    if not literal(raw) or len(raw)>30000:return None
    def pairs(items):
        result={}
        for k,v in items:
            if k in result:raise ValueError('duplicate key')
            result[k]=v
        return result
    try:node=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite')))
    except (ValueError,RecursionError):return None
    if not isinstance(node,dict):return None
    stack=[(node,0)];count=0
    while stack:
        obj,depth=stack.pop();count+=1
        if count>10000 or depth>64:return None
        if isinstance(obj,dict):
            if any(k.startswith(('$','Fn::')) or k=='Ref' for k in obj):return None
            stack.extend((v,depth+1) for v in obj.values())
        elif isinstance(obj,list):stack.extend((v,depth+1) for v in obj)
        elif isinstance(obj,str) and ('${' in obj or '{{resolve:' in obj):return None
    return node
