"""Checks for AWS::WorkSpacesWeb::UserAccessLoggingSettings, AWS::WorkSpacesWeb::UserSettings."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import known_scope, literal

SOURCES = {
    'WORKSPACESWEB_CONTACT_LINK': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-workspacesweb-usersettings-localizedbrandingstrings.html',
    ],
    'WORKSPACESWEB_LOG_ENCRYPTION': [
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-workspacesweb-useraccessloggingsettings.html',
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-kinesis-stream.html',
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-kinesis-stream-streamencryption.html',
        'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-kms-key.html',
        'https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html',
    ],
}


@resource_check('AWS::WorkSpacesWeb::UserSettings', 'AWS::WorkSpacesWeb::UserAccessLoggingSettings')
def evaluate_workspacesweb_waf_portal(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    kind=resource.type.split('::')[-1]
    if resource.type=='AWS::WorkSpacesWeb::UserSettings':
        path='/properties/BrandingConfiguration/LocalizedStrings';raw=get(path)
        if raw is not ABSENT:
            if not isinstance(raw,dict):emit('WORKSPACESWEB_CONTACT_LINK',path,'NEEDS_REVIEW','localized strings map is unresolved')
            else:
                for locale in raw:
                    if not literal(locale) or '/' in locale or '~' in locale:
                        emit('WORKSPACESWEB_CONTACT_LINK',path,'NEEDS_REVIEW','unknown or escaped locale key remains under review');continue
                    p=path+'/'+locale+'/ContactLink';url=get(p)
                    if url is ABSENT:continue
                    verdict='NEEDS_REVIEW'
                    if literal(url):
                        if url.startswith(('https://','mailto:')):verdict='PASS'
                        elif not url.lower().startswith(('http://','https://','mailto:')):verdict='FAIL'
                    emit('WORKSPACESWEB_CONTACT_LINK',p,verdict,'literal ContactLink uses https:// or mailto: per prose; http:// conflicts with schema and is held, as are case variants/unknown values; URL existence and full grammar are separate')
    if resource.type=='AWS::WorkSpacesWeb::UserAccessLoggingSettings':
        path='/properties/KinesisStreamArn';stream=linked(ctx,resource,path,'AWS::Kinesis::Stream') if known_scope(resource) else None
        verdict='NEEDS_REVIEW'
        if stream:
            base='/properties/StreamEncryption';encryption=value(ctx,stream,base)
            if encryption is ABSENT:verdict='PASS'
            elif value(ctx,stream,base+'/EncryptionType')=='KMS':
                key=linked(ctx,stream,base+'/KeyId','AWS::KMS::Key')
                key_id=value(ctx,stream,base+'/KeyId')
                if key:verdict='FAIL'
                elif key_id=='alias/aws/kinesis':verdict='PASS'
        emit('WORKSPACESWEB_LOG_ENCRYPTION',path,verdict,'explicit linked Kinesis stream must use no designed encryption or AWS-managed alias/aws/kinesis; linked AWS::KMS::Key is customer managed and invalid; other IDs/aliases, conditional/external links and live encryption remain under review')
    return results
