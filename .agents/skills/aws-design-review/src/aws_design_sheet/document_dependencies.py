"""Check explicit logical dependency declarations without inventing CFN stacks."""
from graphlib import CycleError, TopologicalSorter


def inspect_dependencies(document):
    declarations=[(i,c) for i,c in enumerate(document.design.connections) if c.kind=='DEPENDENCY']
    if not declarations:
        return [],[{'kind':'DEPENDENCY_NOT_DECLARED','resource_id':None,'path':None,
                    'reason':'No explicit logical dependency graph; stack order is not inferred.'}]
    graph={r.id:set() for r in document.design.resources}
    unknown=[];sources=[];pointers=[]
    for i,connection in declarations:
        pointers.append('/connections/'+str(i));sources.extend(connection.sources)
        if connection.status=='UNDECIDED':unknown.append(connection.id)
        elif connection.status=='DECIDED':graph[connection.source].add(connection.target)
    cycle=[]
    try:list(TopologicalSorter(graph).static_order())
    except CycleError as exc:cycle=exc.args[1]
    verdict='FAIL' if cycle else 'NEEDS_REVIEW' if unknown else 'PASS'
    return [{'rule_id':'DOCUMENT_DEPENDENCY_ACYCLIC','rule_version':'1.0','resource_id':None,'path':None,
             'verdict':verdict,'severity':'ERROR','authority':'DECLARED_DESIGN_GRAPH',
             'reason':'Explicit logical dependency cycle' if cycle else 'Dependency declarations unresolved' if unknown else 'Declared logical dependency graph is acyclic; deployment order not verified',
             'actual':cycle or None,'dependencies':unknown,'source_ids':sorted(set(sources)),
             'input_pointers':pointers,'evidence_ids':[]}],[]
