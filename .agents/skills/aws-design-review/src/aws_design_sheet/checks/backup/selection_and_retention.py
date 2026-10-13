"""Checks for these resource types:

- AWS::Backup::BackupPlan
- AWS::Backup::BackupSelection
- AWS::Backup::RestoreTestingSelection
- AWS::Backup::TieringConfiguration
"""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'BACKUP_RESTORE_SELECTION_EXCLUSIVE': [CF+'aws-resource-backup-restoretestingselection.html'],
    'BACKUP_COLD_RETENTION': [CF+'aws-properties-backup-backupplan-lifecycleresourcetype.html', 'https://docs.aws.amazon.com/aws-backup/latest/APIReference/API_Lifecycle.html'],
    'BACKUP_EXCLUSION_WILDCARD_LIMIT': [CF+'aws-properties-backup-backupselection-backupselectionresourcetype.html'],
    'BACKUP_TIERING_SELECTION': [CF+'aws-properties-backup-tieringconfiguration-resourceselection.html'],
}


@resource_check(
    'AWS::Backup::RestoreTestingSelection',
    'AWS::Backup::BackupPlan',
    'AWS::Backup::BackupSelection',
    'AWS::Backup::TieringConfiguration',
)
def evaluate_backup_selection_and_retention(design,resource):
    ctx=_Context(design,resource);results=[]
    def emit(rule,path,verdict,reason):
        results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::Backup::RestoreTestingSelection':
        path='/properties/ProtectedResourceArns';raw=value(ctx,resource,path)
        if raw is not ABSENT:
            verdict='NEEDS_REVIEW'
            if isinstance(raw,list):
                parts=[value(ctx,resource,path+'/'+str(i)) for i in range(len(raw))]
                literal=[p for p in parts if isinstance(p,str) and '${' not in p and '{{' not in p]
                arns=[p for p in literal if re.fullmatch(r'arn:[a-z0-9-]+:[a-z0-9-]+:[a-z0-9-]*:[0-9]*:[^\s*?{}]+',p)]
                if '*' in literal and arns:verdict='FAIL'
                elif len(literal)==len(parts) and (literal==['*'] or len(arns)==len(parts)):verdict='PASS'
            emit('BACKUP_RESTORE_SELECTION_EXCLUSIVE',path,verdict,'specific literal resource ARNs and the standalone wildcard cannot be mixed; external existence and unsupported ARN spellings remain unverified')
    if resource.type=='AWS::Backup::BackupPlan':
        root='/properties/BackupPlan/BackupPlanRule';rules=value(ctx,resource,root)
        paths=[]
        if isinstance(rules,list):
            for i in range(len(rules)):
                base=root+'/'+str(i);paths.append(base+'/Lifecycle')
                copies=value(ctx,resource,base+'/CopyActions')
                if isinstance(copies,list):paths.extend(base+'/CopyActions/'+str(j)+'/Lifecycle' for j in range(len(copies)))
                elif copies is not ABSENT:emit('BACKUP_COLD_RETENTION',base+'/CopyActions','NEEDS_REVIEW','copy actions are unresolved')
        elif rules is not ABSENT:emit('BACKUP_COLD_RETENTION',root,'NEEDS_REVIEW','backup rules are unresolved')
        for path in paths:
            if value(ctx,resource,path) is ABSENT:continue
            cold=value(ctx,resource,path+'/MoveToColdStorageAfterDays');delete=value(ctx,resource,path+'/DeleteAfterDays')
            verdict='NEEDS_REVIEW'
            if type(cold) is int and type(delete) is int and cold>=0 and delete>=0:
                verdict='PASS' if delete>=cold+90 else 'FAIL'
            emit('BACKUP_COLD_RETENTION',path,verdict,'explicit nonnegative integer retention must be at least 90 days beyond cold transition; missing values and negative lifecycle-removal sentinels require separate review, as does resource support')
    if resource.type=='AWS::Backup::BackupSelection':
        path='/properties/BackupSelection/NotResources';raw=value(ctx,resource,path)
        if raw is not ABSENT:
            verdict='NEEDS_REVIEW'
            if isinstance(raw,list):
                parts=[value(ctx,resource,path+'/'+str(i)) for i in range(len(raw))]
                known=[p for p in parts if isinstance(p,str) and '${' not in p and '{{' not in p]
                wildcard=any('*' in p for p in known)
                if len(parts)>500 or wildcard and len(parts)>30:verdict='FAIL'
                elif len(known)==len(parts) and all('?' not in p for p in known):verdict='PASS'
            emit('BACKUP_EXCLUSION_WILDCARD_LIMIT',path,verdict,'exclusion list permits at most 500 entries, reduced to 30 with an explicit asterisk wildcard; unresolved entries and other wildcard spellings remain under review, ARN validity is separate')
    if resource.type=='AWS::Backup::TieringConfiguration':
        path='/properties/ResourceSelection';raw=value(ctx,resource,path)
        if raw is not ABSENT:
            known_arns=set();pending=False;conflict=False;arn_count=0
            if isinstance(raw,list):
                for i in range(len(raw)):
                    base=path+'/'+str(i)+'/Resources';selection=value(ctx,resource,base)
                    if not isinstance(selection,list):pending=True;continue
                    parts=[value(ctx,resource,base+'/'+str(j)) for j in range(len(selection))]
                    arns=[s for s in parts if isinstance(s,str) and re.fullmatch(r'arn:[a-z0-9-]+:[a-z0-9-]+:[a-z0-9-]*:[0-9]*:[^\s*?{}]+',s)]
                    known_arns.update(arns)
                    arn_count+=len(arns)
                    if '*' in parts and arns:conflict=True
                    if parts!=['*'] and len(arns)!=len(parts):pending=True
            else:pending=True
            verdict='FAIL' if conflict or len(known_arns)>100 else 'NEEDS_REVIEW' if pending or arn_count>100 else 'PASS'
            emit('BACKUP_TIERING_SELECTION',path,verdict,'each selection uses specific ARNs or standalone wildcard, and at most 100 distinct explicit resources across the configuration; duplicate counting and external resource validity are not certified')
    return results
