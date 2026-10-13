"""Checks for AWS::MediaLive::Channel, AWS::MediaLive::Input."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, known_scope, literal
from ..common.unique_strings import unique_strings

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'MEDIALIVE_CHANNEL_CAPTION_NAMES': [CF+'aws-properties-medialive-channel-captionselector.html'],
    'MEDIALIVE_SMOOTH_BITRATE_DUPLICATES': [CF+'aws-properties-medialive-channel-h264settings.html',CF+'aws-properties-medialive-channel-h265settings.html'],
    'MEDIALIVE_CHANNEL_SUBNET_AZS': [CF+'aws-properties-medialive-channel-vpcoutputsettings.html'],
    'MEDIALIVE_INPUT_SUBNET_AZS': [CF+'aws-properties-medialive-input-inputvpcrequest.html'],
}


@resource_check('AWS::MediaLive::Channel', 'AWS::MediaLive::Input')
def evaluate_medialive_channel_and_input(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(p):return value(ctx,resource,p)
    def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
    if resource.type=='AWS::MediaLive::Channel':
        p='/properties/InputAttachments'
        if get(p) is not ABSENT:emit('MEDIALIVE_CHANNEL_CAPTION_NAMES',p,unique_strings(ctx,resource,p+'/*/InputSettings/CaptionSelectors/*/Name'),'caption selector names must be unique across all channel input attachments; unknown collections/names held')
        video='/properties/EncoderSettings/VideoDescriptions';descriptions={};ambiguous=False
        for p in expand(ctx,resource,video+'/*'):
            name=get(p+'/Name')
            if not literal(name):ambiguous=True;continue
            descriptions.setdefault(name,[]).append(p)
        for group in expand(ctx,resource,'/properties/EncoderSettings/OutputGroups/*'):
            if not isinstance(get(group+'/OutputGroupSettings/MsSmoothGroupSettings'),dict):continue
            buckets=[];pending=ambiguous
            for p in expand(ctx,resource,group+'/Outputs/*'):
                name=get(p+'/VideoDescriptionName')
                if name is ABSENT:continue
                found=descriptions.get(name,[]) if literal(name) else []
                if len(found)!=1:pending=True;continue
                codecs=[found[0]+'/CodecSettings/'+c for c in ('H264Settings','H265Settings') if get(found[0]+'/CodecSettings/'+c) is not ABSENT]
                if len(codecs)!=1:pending=True;continue
                if get(codecs[0]+'/RateControlMode') not in ('CBR','VBR'):pending=True;continue
                bitrate=get(codecs[0]+'/Bitrate')
                if type(bitrate) is not int or bitrate<0:pending=True;continue
                buckets.append(bitrate//1000)
            verdict='NEEDS_REVIEW' if ambiguous else 'FAIL' if len(buckets)!=len(set(buckets)) else 'NEEDS_REVIEW' if pending else 'PASS'
            emit('MEDIALIVE_SMOOTH_BITRATE_DUPLICATES',group,verdict,'checks H264/H265 CBR/VBR bitrate uniqueness rounded down to multiples of 1000 among explicitly resolved Smooth group video outputs; QVBR, omitted modes, ambiguous video names and unknown codecs held; MediaPackageV2 group flags separate')
    if resource.type in ('AWS::MediaLive::Channel','AWS::MediaLive::Input'):
        channel=resource.type.endswith('::Channel');p='/properties/Vpc/SubnetIds';raw=get(p)
        if raw is not ABSENT:
            verdict='NEEDS_REVIEW';zones=[]
            applicable=not channel or get('/properties/ChannelClass')=='STANDARD'
            if applicable and isinstance(raw,list) and len(raw)==2 and known_scope(resource):
                for i in range(2):
                    subnet=linked(ctx,resource,p+'/'+str(i),'AWS::EC2::Subnet')
                    zone=value(ctx,subnet,'/properties/AvailabilityZone') if subnet else None
                    if literal(zone):zones.append(zone)
                if len(zones)==2:verdict='PASS' if zones[0]!=zones[1] else 'FAIL'
            emit('MEDIALIVE_CHANNEL_SUBNET_AZS' if channel else 'MEDIALIVE_INPUT_SUBNET_AZS',p,verdict,'two explicit same-scope unconditionally linked subnets require distinct known AvailabilityZone names; Channel applies only to explicit STANDARD; omitted class, IDs, AZ IDs and external subnets held')
    return results
