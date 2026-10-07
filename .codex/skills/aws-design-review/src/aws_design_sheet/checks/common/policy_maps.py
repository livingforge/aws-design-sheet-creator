"""Tag and policy map helpers shared by Athena and Clean Rooms checks."""
import re
from .context_values import value
from .literals import literal


def plain_domain(raw,wildcard=False):
    if not isinstance(raw,str) or len(raw)>253:return False
    if wildcard and raw.startswith('*.'):raw=raw[2:]
    parts=raw.split('.')
    return len(parts)>1 and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',p) and not p.startswith('xn--') for p in parts)


def unique_items(ctx,resource,path,key):
    raw=value(ctx,resource,path); pending=not isinstance(raw,list); seen=set(); duplicate=False
    for i in range(len(raw)) if isinstance(raw,list) else ():
        item=value(ctx,resource,path+'/'+str(i)+'/'+key)
        if not literal(item):pending=True
        elif item in seen:duplicate=True
        else:seen.add(item)
    return 'FAIL' if duplicate else 'NEEDS_REVIEW' if pending else 'PASS'
