import pytest
from aws_design_sheet.checks.registry import run_resource_checks
from aws_design_sheet.checks.apigatewayv2.cross_resource import evaluate_protocol_constraints
from test_autoscaling_group_and_scaling_policy import target, linked_design, UNKNOWN

FUNCTION='arn:aws:lambda:ap-northeast-1:123456789012:function:app'
WRAPPED='arn:aws:apigateway:ap-northeast-1:lambda:path/2015-03-31/functions/'+FUNCTION+'/invocations'


@pytest.mark.parametrize('destination,expected',[
    ('overwrite:path','PASS'),('append:querystring.page','PASS'),
    ('remove:header.X-Custom','PASS'),('append:header.Authorization','FAIL'),
    ('overwrite:header.X-AmZn-Trace-Id','FAIL'),('append:header.access-control-allow-origin','FAIL'),
    ('overwrite:statuscode','FAIL'),('append:path','FAIL'),('append:header.','FAIL'),
    ('${Mapping}','NEEDS_REVIEW'),
])
def test_http_request_destinations(destination,expected):
    assert check({'RequestParameters':{destination:'value'}})['APIGATEWAYV2_HTTP_REQUEST_DESTINATIONS']==expected


@pytest.mark.parametrize('destination,expected',[
    ('overwrite:statuscode','PASS'),('append:header.X-Error','PASS'),
    ('overwrite.statuscode','NEEDS_REVIEW'),
    ('remove:header.content-LENGTH','FAIL'),('append:header.apigw-test','FAIL'),
    ('append:querystring.page','FAIL'),('overwrite:path','FAIL'),
    (UNKNOWN,'NEEDS_REVIEW'),
])
def test_http_response_destinations(destination,expected):
    props={'ResponseParameters':{'500':{'ResponseParameters':[{'Destination':destination,'Source':'403'}]}}}
    assert check(props)['APIGATEWAYV2_HTTP_RESPONSE_DESTINATIONS']==expected


def test_service_subtype_and_websocket_mapping_are_not_http_request_keys():
    props={'RequestParameters':{'QueueUrl':'queue'},'IntegrationSubtype':'SQS-SendMessage'}
    assert 'APIGATEWAYV2_HTTP_REQUEST_DESTINATIONS' not in check(props)
    assert 'APIGATEWAYV2_HTTP_REQUEST_DESTINATIONS' not in check({'RequestParameters':{'integration.request.header.x':'value'}},'WEBSOCKET')


@pytest.mark.parametrize('props',[
    {'RequestParameters':UNKNOWN},
    {'RequestParameters':{'append:header.x':'value'},'IntegrationSubtype':UNKNOWN},
])
def test_unknown_mapping_inputs(props):
    assert check(props)['APIGATEWAYV2_HTTP_REQUEST_DESTINATIONS']=='NEEDS_REVIEW'


def test_conditional_api_cannot_prove_http_mapping_rules():
    assert check({'RequestParameters':{'append:header.Authorization':'value'}},conditional=True)['APIGATEWAYV2_HTTP_REQUEST_DESTINATIONS']=='NEEDS_REVIEW'


def check(props,protocol='HTTP',conditional=False):
    main=target('integration','AWS::ApiGatewayV2::Integration',ApiId={'Ref':'api'},**props)
    main.scope.account='123456789012'
    api=target('api','AWS::ApiGatewayV2::Api',ProtocolType=protocol)
    api.scope.account='123456789012'
    data=linked_design(main,[api],[('ApiId','api')])
    if conditional:
        data.relations[0].condition='condition'
    rows=evaluate_protocol_constraints(data,main)+run_resource_checks(data,main)
    return {r['rule_id']:r['verdict'] for r in rows}


@pytest.mark.parametrize('uri,expected',[
    (FUNCTION,'PASS'),(WRAPPED,'PASS'),(FUNCTION+':alias','PASS'),
    ('https://example.com','FAIL'),('arn:aws:sqs:ap-northeast-1:123456789012:queue','FAIL'),
    (UNKNOWN,'NEEDS_REVIEW'),('not-an-arn:lambda:path/anything:lambda:','NEEDS_REVIEW'),
    ('arn:aws:lambda:ap-northeast-1:123456789012:function:${Function}','NEEDS_REVIEW'),
])
def test_payload_v2_target(uri,expected):
    assert check({'IntegrationType':'AWS_PROXY','PayloadFormatVersion':'2.0','IntegrationUri':uri})['APIGATEWAYV2_INTEGRATION_PAYLOAD_PROTOCOL']==expected


@pytest.mark.parametrize('field',['IntegrationType','IntegrationSubtype','PayloadFormatVersion'])
def test_dynamic_payload_inputs_are_not_definite_failures(field):
    props={'IntegrationType':'AWS_PROXY','PayloadFormatVersion':'2.0','IntegrationUri':FUNCTION,field:UNKNOWN}
    assert check(props)['APIGATEWAYV2_INTEGRATION_PAYLOAD_PROTOCOL']=='NEEDS_REVIEW'


def test_conditional_api_link_does_not_establish_protocol():
    props={'IntegrationType':'AWS_PROXY','PayloadFormatVersion':'2.0','IntegrationUri':FUNCTION}
    assert check(props,conditional=True)['APIGATEWAYV2_INTEGRATION_PAYLOAD_PROTOCOL']=='NEEDS_REVIEW'


@pytest.mark.parametrize('method,expected',[('POST','PASS'),('GET','FAIL'),(None,'FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_websocket_lambda_method(method,expected):
    props={'IntegrationType':'AWS_PROXY','IntegrationUri':WRAPPED,**({'IntegrationMethod':method} if method is not None else {})}
    assert check(props,'WEBSOCKET')['APIGATEWAYV2_WEBSOCKET_LAMBDA_POST']==expected


@pytest.mark.parametrize('uri,expected',[
    ('arn:aws:elasticloadbalancing:ap-northeast-1:123456789012:listener/app/lb/0123456789abcdef/fedcba9876543210','PASS'),
    ('arn:aws:elasticloadbalancing:ap-northeast-1:999999999999:listener/net/lb/0123456789abcdef/fedcba9876543210','FAIL'),
    ('arn:aws:servicediscovery:ap-northeast-1:123456789012:service/srv-123?stage=prod','PASS'),
    ('arn:aws:elasticloadbalancing:ap-northeast-1:123456789012:loadbalancer/app/lb/0123456789abcdef','FAIL'),
    (FUNCTION,'FAIL'),('https://example.com','FAIL'),(UNKNOWN,'NEEDS_REVIEW'),
])
def test_private_target_type_and_account(uri,expected):
    assert check({'ConnectionType':'VPC_LINK','IntegrationType':'HTTP_PROXY','IntegrationUri':uri})['APIGATEWAYV2_PRIVATE_TARGET_SCOPE']==expected


def test_explicit_lambda_link_and_conditional_target():
    main=target('integration','AWS::ApiGatewayV2::Integration',ApiId={'Ref':'api'},IntegrationType='AWS_PROXY',PayloadFormatVersion='2.0',IntegrationUri={'Ref':'fn'})
    api=target('api','AWS::ApiGatewayV2::Api',ProtocolType='HTTP')
    fn=target('fn','AWS::Lambda::Function')
    data=linked_design(main,[api,fn],[('ApiId','api'),('IntegrationUri','fn')])
    rows={r['rule_id']:r['verdict'] for r in evaluate_protocol_constraints(data,main)}
    assert rows['APIGATEWAYV2_INTEGRATION_PAYLOAD_PROTOCOL']=='PASS'
    data.relations[-1].condition='condition'
    rows={r['rule_id']:r['verdict'] for r in evaluate_protocol_constraints(data,main)}
    assert rows['APIGATEWAYV2_INTEGRATION_PAYLOAD_PROTOCOL']=='NEEDS_REVIEW'


@pytest.mark.parametrize('version,uri,protocol,expected',[
    ('2.0',FUNCTION,'HTTP','PASS'),('2.0',WRAPPED,'HTTP','PASS'),
    ('2.0','https://example.com','HTTP','FAIL'),('1.0','https://example.com','HTTP','PASS'),
    ('2.0',UNKNOWN,'HTTP','NEEDS_REVIEW'),('2.0',FUNCTION,UNKNOWN,'NEEDS_REVIEW'),
    (UNKNOWN,FUNCTION,'HTTP','NEEDS_REVIEW'),('2.0',FUNCTION,'WEBSOCKET','NEEDS_REVIEW'),
])
def test_managed_payload_target(version,uri,protocol,expected):
    main=target('override','AWS::ApiGatewayV2::ApiGatewayManagedOverrides',ApiId={'Ref':'api'},Integration={'PayloadFormatVersion':version})
    api=target('api','AWS::ApiGatewayV2::Api',ProtocolType=protocol,Target=uri)
    data=linked_design(main,[api],[('ApiId','api')])
    findings={r['rule_id']:r['verdict'] for r in run_resource_checks(data,main)}
    assert findings['APIGATEWAYV2_MANAGED_PAYLOAD_TARGET']==expected


@pytest.mark.parametrize('lb_kind,expected',[('application','PASS'),('network','PASS'),('gateway','FAIL'),(UNKNOWN,'NEEDS_REVIEW')])
def test_private_listener_link_type(lb_kind,expected):
    from aws_design_sheet.models import Relation
    main=target('integration','AWS::ApiGatewayV2::Integration',ApiId={'Ref':'api'},ConnectionType='VPC_LINK',IntegrationUri={'Ref':'listener'})
    api=target('api','AWS::ApiGatewayV2::Api',ProtocolType='HTTP')
    listener=target('listener','AWS::ElasticLoadBalancingV2::Listener',LoadBalancerArn={'Ref':'lb'})
    lb=target('lb','AWS::ElasticLoadBalancingV2::LoadBalancer',Type=lb_kind)
    data=linked_design(main,[api,listener,lb],[('ApiId','api'),('IntegrationUri','listener')])
    data.relations.append(Relation(id='lb',source_resource_id='listener',source_path='/properties/LoadBalancerArn',target_resource_id='lb',evidence_ids=['e1']))
    findings={r['rule_id']:r['verdict'] for r in run_resource_checks(data,main)}
    assert findings['APIGATEWAYV2_PRIVATE_TARGET_SCOPE']==expected
