"""Ordering of explicitly reachable Organizations accounts."""
from ...template_dependencies import explicit_dependencies, members
from .context_values import _Context
from .scoped_resolution import resolved


def explicit_reach(pool,start):
    graph={r.id:[] for r in pool}
    for r in pool:
        for name in r.template.depends_on or []:
            matches=[other for other in pool if other.name==name]
            if len(matches)==1:graph[r.id].append(matches[0].id)
    reached=set();todo=list(graph[start.id])
    while todo:
        item=todo.pop()
        if item in reached:continue
        reached.add(item);todo.extend(graph[item])
    return reached


def sequential(ctx,r):
    if not resolved(r) or r.template is None:return 'NEEDS_REVIEW'
    pool=members(ctx.design,r)
    if not pool or len(pool)>1000:return 'NEEDS_REVIEW'
    accounts=[other for other in pool if other.type==r.type]
    if len(accounts)==1:return 'NOT_APPLICABLE'
    if len(accounts)>100 or any(not resolved(other) for other in accounts):return 'NEEDS_REVIEW'
    explicit={};actual={}
    for other in accounts:
        explicit[other.id]=explicit_reach(pool,other)
        try:
            sub=_Context(ctx.design,other);actual[other.id]=explicit_dependencies(sub,other)
            ctx.evidence.extend(sub.evidence);ctx.dependencies.extend(sub.dependencies)
        except RecursionError:return 'NEEDS_REVIEW'
        if actual[other.id][2]:return 'FAIL'
    pending=False
    # A shared predecessor is not enough: every pair must be ordered.
    for i,a in enumerate(accounts):
        for b in accounts[i+1:]:
            if a.id in explicit[b.id] or b.id in explicit[a.id]:continue
            ar,au,_=actual[a.id];br,bu,_=actual[b.id]
            if a.id not in br and b.id not in ar and not au and not bu:return 'FAIL'
            pending=True
    return 'NEEDS_REVIEW' if pending else 'PASS'
