"""Checks for AWS::Cognito::UserPoolClient."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'COGNITO_DEFAULT_CALLBACK': [CF+'aws-resource-cognito-userpoolclient.html'],
}


@resource_check('AWS::Cognito::UserPoolClient')
def evaluate_cognito_default_callback(design,resource):
    ctx=_Context(design,resource);results=[]
    def get(path):return value(ctx,resource,path)
    def emit(rule,path,verdict,reason):results.append(ctx.finding(rule,path,verdict,reason))
    if resource.type=='AWS::Cognito::UserPoolClient':
        path='/properties/DefaultRedirectURI';default=get(path)
        if default is not ABSENT:
            raw=get('/properties/CallbackURLs');pending=raw is not ABSENT and not isinstance(raw,list);found=False
            for i in range(len(raw)) if isinstance(raw,list) else ():
                url=get('/properties/CallbackURLs/'+str(i))
                if not literal(url):pending=True
                elif url==default:found=True
            verdict='NEEDS_REVIEW' if not literal(default) else 'PASS' if found else 'NEEDS_REVIEW' if pending else 'FAIL'
            emit('COGNITO_DEFAULT_CALLBACK',path,verdict,'literal DefaultRedirectURI must exactly match a CallbackURLs entry; URL normalization, OAuth configuration and external registration are separate')
    return results
