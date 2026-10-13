"""Multi-node constraints for explicitly disjoint legacy container ranges."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={
    'BATCH_NODE_RESOURCE_PRESENCE':[CF+'aws-properties-batch-jobdefinition-multinodecontainerproperties.html',CF+'aws-properties-batch-jobdefinition-noderangeproperty.html'],
    'BATCH_NODE_INSTANCE_UNIFORM':['https://docs.aws.amazon.com/batch/latest/userguide/mnp-node-groups.html',CF+'aws-properties-batch-jobdefinition-noderangeproperty.html'],
}


@resource_check('AWS::Batch::JobDefinition')
def evaluate_batch_nodes(design,resource):
    if resource.type!='AWS::Batch::JobDefinition':return []
    ctx=_Context(design,resource);root='/properties/NodeProperties'
    if value(ctx,resource,root) is ABSENT:return []
    count=value(ctx,resource,root+'/NumNodes');ranges=value(ctx,resource,root+'/NodeRangeProperties')
    rows=[];pending=False
    if type(count) is not int or count<=0 or not isinstance(ranges,list):pending=True
    else:
        for i in range(len(ranges)):
            base=root+'/NodeRangeProperties/'+str(i);span=value(ctx,resource,base+'/TargetNodes')
            if not isinstance(span,str) or not re.fullmatch(r'(?:[0-9]{1,20}|[0-9]{0,20}:[0-9]{0,20})',span):pending=True;continue
            if ':' in span:
                start,end=span.split(':');lo=int(start or 0);hi=int(end) if end else count-1
            else:lo=hi=int(span)
            if not 0<=lo<=hi<count:pending=True;continue
            rows.append((lo,hi,base))
        ordered=sorted(rows)
        # Do not guess property inheritance, equal-range precedence or partial overlaps.
        if any(b[0]<=a[1] for a,b in zip(ordered,ordered[1:])):pending=True
        if sum(hi-lo+1 for lo,hi,_ in rows)!=count:pending=True
    quantity_pending=pending;missing=False;types=[];type_pending=pending
    if not pending:
        for _,_,base in rows:
            container=base+'/Container';raw=value(ctx,resource,container)
            if not isinstance(raw,dict) or any(value(ctx,resource,base+'/'+k) is not ABSENT for k in ('EcsProperties','EksProperties')):
                quantity_pending=True
            else:
                requirements=value(ctx,resource,container+'/ResourceRequirements')
                for old,modern in [('Memory','MEMORY'),('Vcpus','VCPU')]:
                    known=value(ctx,resource,container+'/'+old)
                    present=type(known) is int;unknown=known is not ABSENT and not present
                    if isinstance(requirements,list):
                        for j in range(len(requirements)):
                            p=container+'/ResourceRequirements/'+str(j)
                            kind=value(ctx,resource,p+'/Type');number=value(ctx,resource,p+'/Value')
                            if kind==modern:
                                if literal(number):present=True
                                else:unknown=True
                            elif kind not in ('MEMORY','VCPU','GPU'):unknown=True
                    elif requirements is not ABSENT:unknown=True
                    if not present:
                        if unknown:quantity_pending=True
                        else:missing=True
            group=value(ctx,resource,base+'/InstanceTypes');legacy=value(ctx,resource,container+'/InstanceType')
            group_type=group[0] if isinstance(group,list) and len(group)==1 and literal(group[0]) else None
            if group is ABSENT and literal(legacy):types.append(legacy)
            elif group_type and legacy is ABSENT:types.append(group_type)
            elif group_type and group_type==legacy:types.append(group_type)
            else:type_pending=True
    return [ctx.finding('BATCH_NODE_RESOURCE_PRESENCE',root+'/NodeRangeProperties',
            'FAIL' if missing else 'NEEDS_REVIEW' if quantity_pending else 'PASS',
            'each node in disjoint fully covered legacy container ranges needs explicit MEMORY and VCPU, via legacy fields or ResourceRequirements; values, job-submission overrides and overlapping inheritance remain separate'),
            ctx.finding('BATCH_NODE_INSTANCE_UNIFORM',root+'/NodeRangeProperties',
            'FAIL' if len(set(types))>1 else 'NEEDS_REVIEW' if type_pending else 'PASS',
            'disjoint node ranges must use one explicit instance type; omitted, conflicting selectors, unknown or overlapping ranges require review and EC2 validity is external')]
