"""Checks for AWS::DataSync::Task."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT, UNKNOWN
from ..common.literals import literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'DATASYNC_EFS_PRESERVE_DEVICES': [CF+'aws-properties-datasync-task-options.html'],
    'DATASYNC_ARCHIVE_VERIFY_MODE': [CF+'aws-properties-datasync-task-options.html'],
}


@resource_check('AWS::DataSync::Task')
def evaluate_datasync_task(design, resource):
    ctx = _Context(design, resource)
    results = []
    def get(p):
        return value(ctx, resource, p)
    def emit(rule, p, verdict, reason):
        f = ctx.finding(rule, p, verdict, reason)
        f['source_checked_at'] = '2026-10-04'
        results.append(f)
    if resource.type == 'AWS::DataSync::Task':
        p = '/properties/Options/PreserveDevices'
        preserve = get(p)
        if preserve == 'PRESERVE':
            types = []
            for side in ('SourceLocationArn','DestinationLocationArn'):
                kind = None
                for name in ('LocationEFS','LocationNFS','LocationS3','LocationSMB','LocationFSxWindows','LocationFSxLustre','LocationFSxONTAP','LocationFSxOpenZFS','LocationHDFS','LocationObjectStorage','LocationAzureBlob'):
                    if linked(ctx,resource,'/properties/'+side,'AWS::DataSync::'+name):
                        kind = name
                        break
                types.append(kind)
            verdict = 'FAIL' if 'LocationEFS' in types else 'PASS' if all(types) else 'NEEDS_REVIEW'
            emit('DATASYNC_EFS_PRESERVE_DEVICES', p, verdict, 'explicit PRESERVE cannot involve a linked EFS location; unknown locations, runtime overrides and other metadata restrictions remain separate')
        elif preserve is not ABSENT and not literal(preserve):
            emit('DATASYNC_EFS_PRESERVE_DEVICES', p, 'NEEDS_REVIEW', 'preservation option unresolved')
        p = '/properties/Options/VerifyMode'
        verify = get(p)
        if verify == 'POINT_IN_TIME_CONSISTENT':
            destination = linked(ctx,resource,'/properties/DestinationLocationArn','AWS::DataSync::LocationS3')
            storage = value(ctx,destination,'/properties/S3StorageClass') if destination else UNKNOWN
            verdict = 'FAIL' if storage in ('GLACIER','DEEP_ARCHIVE') else 'PASS' if storage in ('STANDARD','STANDARD_IA','ONEZONE_IA','INTELLIGENT_TIERING','GLACIER_INSTANT_RETRIEVAL') else 'NEEDS_REVIEW'
            emit('DATASYNC_ARCHIVE_VERIFY_MODE', p, verdict, 'explicit verification mode checked against linked S3 destination class; omitted modes/classes, other destinations and runtime overrides remain held')
        elif verify is not ABSENT and not literal(verify):
            emit('DATASYNC_ARCHIVE_VERIFY_MODE', p, 'NEEDS_REVIEW', 'verification option unresolved')
    return results
