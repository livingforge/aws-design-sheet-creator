"""Per-worker memory and standard disk sizes; cumulative caps are separate."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES={'EMRSERVERLESS_INITIAL_WORKER_SIZES':[CF+'aws-properties-emrserverless-application-workerconfiguration.html',CF+'aws-properties-emrserverless-application-maximumallowedresources.html','https://docs.aws.amazon.com/emr/latest/EMR-Serverless-UserGuide/app-behavior.html']}
MEMORY={1:(2,8,1),2:(4,16,1),4:(8,30,1),8:(16,60,4),16:(32,120,8)}


def size(raw,unit,optional=True):
    if not isinstance(raw,str) or len(raw)>15:return None
    suffix='(?:vCPU|vcpu|VCPU)' if unit=='cpu' else '(?:GB|gb|gB|Gb)'
    match=re.fullmatch(r'([1-9][0-9]*)(?:\s)?'+suffix+('?' if optional else ''),raw)
    return int(match[1]) if match else None


def memory(cpu,amount):
    if cpu is None or amount is None:return 'NEEDS_REVIEW'
    if cpu==32:return 'PASS' if amount in (60,120,244) else 'FAIL'
    if cpu not in MEMORY:return 'NEEDS_REVIEW'
    low,high,step=MEMORY[cpu]
    return 'PASS' if low<=amount<=high and (amount-low)%step==0 else 'FAIL'


@resource_check('AWS::EMRServerless::Application')
def evaluate_emrserverless_worker_sizes(design,resource):
    if resource.type!='AWS::EMRServerless::Application':return []
    ctx=_Context(design,resource);results=[];pattern='/properties/InitialCapacity/*/Value/WorkerConfiguration'
    for root in expand(ctx,resource,pattern):
        if root.count('/')!=pattern.count('/'):
            results.append(ctx.finding('EMRSERVERLESS_INITIAL_WORKER_SIZES',root,'NEEDS_REVIEW','Unknown or malformed initial-capacity collection cannot be interpreted as a worker.'));continue
        cpu=size(value(ctx,resource,root+'/Cpu'),'cpu')
        raw=value(ctx,resource,root+'/Memory')
        results.append(ctx.finding('EMRSERVERLESS_INITIAL_WORKER_SIZES',root+'/Memory',memory(cpu,size(raw,'gb')),
            'Per-worker memory follows the documented vCPU range and increment, including discrete 32-vCPU sizes. Application MaximumCapacity is cumulative, and proportional sizing is a best practice rather than a rejection constraint.'))
        disk=value(ctx,resource,root+'/Disk')
        if disk is ABSENT:continue
        kind=value(ctx,resource,root+'/DiskType');amount=size(disk,'gb',optional=False)
        verdict='NEEDS_REVIEW'
        if amount is not None and (kind is ABSENT or kind in ('STANDARD','Standard','standard')):verdict='PASS' if 20<=amount<=200 else 'FAIL'
        results.append(ctx.finding('EMRSERVERLESS_INITIAL_WORKER_SIZES',root+'/Disk',verdict,
            'Standard per-worker temporary disk is 20..200 GB, with STANDARD as the documented default. Shuffle-optimized and unknown disk types remain reviewable; application cumulative disk caps are not subjected to worker-size limits.'))
    return results
