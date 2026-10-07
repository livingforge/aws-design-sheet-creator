"""Checks for AWS::Batch::ComputeEnvironment, AWS::Batch::SchedulingPolicy."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT, UNKNOWN

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'BATCH_SHARE_NONOVERLAP': [CF+'aws-properties-batch-schedulingpolicy-shareattributes.html'],
    'BATCH_OVERRIDE_TARGETS': [CF+'aws-properties-batch-computeenvironment-launchtemplatespecificationoverride.html'],
}


@resource_check('AWS::Batch::SchedulingPolicy', 'AWS::Batch::ComputeEnvironment')
def evaluate_batch_shares_and_overrides(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::Batch::SchedulingPolicy':
        path='/properties/FairsharePolicy/ShareDistribution';raw=value(ctx,resource,path)
        if raw is not ABSENT:
            verdict='NEEDS_REVIEW'
            if isinstance(raw,list):
                identifiers=[value(ctx,resource,path+'/'+str(i)+'/ShareIdentifier') for i in range(len(raw))]
                known=[s for s in identifiers if isinstance(s,str) and re.fullmatch(r'[A-Za-z0-9]{1,255}\*?',s)]
                overlap=any(a==b or a.endswith('*') and b.rstrip('*').startswith(a[:-1])
                            or b.endswith('*') and a.rstrip('*').startswith(b[:-1])
                            for i,a in enumerate(known) for b in known[i+1:])
                verdict='FAIL' if overlap else 'PASS' if len(known)==len(identifiers) else 'NEEDS_REVIEW'
            emit('BATCH_SHARE_NONOVERLAP',path,verdict,'literal share identifiers and documented trailing-asterisk prefixes must not overlap; unsupported spellings and unknown identifiers remain under review, active runtime share count is external')
    if resource.type=='AWS::Batch::ComputeEnvironment':
        root='/properties/ComputeResources';path=root+'/LaunchTemplate/Overrides';raw=value(ctx,resource,path)
        if raw is not ABSENT:
            def literal_type(v):
                return isinstance(v,str) and re.fullmatch(r'[a-z][a-z0-9-]*[0-9][a-z0-9-]*(?:\.[a-z0-9]+)?',v)
            def covers(a,b):
                return a==b or '.' not in a and b.startswith(a+'.')
            parent=value(ctx,resource,root+'/InstanceTypes')
            parent_parts=[value(ctx,resource,root+'/InstanceTypes/'+str(i)) for i in range(len(parent))] if isinstance(parent,list) else [UNKNOWN]
            parents=[p for p in parent_parts if literal_type(p)]
            parent_known=len(parents)==len(parent_parts)
            pending=False;invalid=False;targets=[]
            if isinstance(raw,list):
                for i in range(len(raw)):
                    base=path+'/'+str(i)+'/TargetInstanceTypes';parts=value(ctx,resource,base)
                    if not isinstance(parts,list) or not parts:pending=True;continue
                    for j in range(len(parts)):
                        t=value(ctx,resource,base+'/'+str(j))
                        if t in ('optimal','default_x86_64','default_arm64'):invalid=True
                        elif literal_type(t):
                            targets.append(t)
                            if not any(covers(p,t) for p in parents):
                                if parent_known:invalid=True
                                else:pending=True
                        else:pending=True
            else:pending=True
            overlap=any(covers(a,b) or covers(b,a) for i,a in enumerate(targets) for b in targets[i+1:])
            verdict='FAIL' if invalid or overlap else 'NEEDS_REVIEW' if pending else 'PASS'
            emit('BATCH_OVERRIDE_TARGETS',path,verdict,'checks forbidden aliases, family/type inclusion in InstanceTypes, and overlap within/across overrides; unknown inputs and actual EC2 catalog validity remain separate review items')
    return results
