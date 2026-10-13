"""Checks for AWS::Transfer::Server, AWS::Transfer::User."""
from ..registry import resource_check
from ..common.context_values import _Context, linked, value
from ..common.field_reads import ABSENT
from ..common.literals import known_scope
from ..common.string_lists import strings

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'TRANSFER_ENDPOINT_ARRAY_LENGTH': [CF+'aws-properties-transfer-server-endpointdetails.html'],
    'TRANSFER_USER_SERVER_IDENTITY': [CF+'aws-resource-transfer-user.html'],
}


@resource_check('AWS::Transfer::Server', 'AWS::Transfer::User')
def evaluate_transfer_server_endpoints_and_users(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::Transfer::Server':
        path='/properties/EndpointDetails/AddressAllocationIds'
        if get(path) is not ABSENT:
            addresses,a_pending=strings(ctx,resource,path);subnets,s_pending=strings(ctx,resource,'/properties/EndpointDetails/SubnetIds')
            verdict='NEEDS_REVIEW' if a_pending or s_pending or not addresses or not subnets else 'PASS' if len(addresses)==len(subnets) else 'FAIL'
            emit('TRANSFER_ENDPOINT_ARRAY_LENGTH',path,verdict,'nonempty explicit AddressAllocationIds and SubnetIds must have equal length; unresolved/empty arrays, update sequencing, offline state and address availability remain under review')
    if resource.type=='AWS::Transfer::User':
        path='/properties/ServerId';server=linked(ctx,resource,path,'AWS::Transfer::Server') if known_scope(resource) else None
        kind=value(ctx,server,'/properties/IdentityProviderType') if server else None
        verdict='PASS' if kind=='SERVICE_MANAGED' else 'FAIL' if kind in ('API_GATEWAY','AWS_DIRECTORY_SERVICE','AWS_LAMBDA') else 'NEEDS_REVIEW'
        emit('TRANSFER_USER_SERVER_IDENTITY',path,verdict,'explicit same-scope linked server must use SERVICE_MANAGED; omitted/unknown provider types and conditional/external server references remain under review')
    return results
