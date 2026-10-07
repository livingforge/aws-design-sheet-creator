"""Checks for AWS::NetworkManager::ConnectPeer."""
import ipaddress
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.literals import literal

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'NETWORKMANAGER_PEER_FAMILY': [CF+'aws-resource-networkmanager-connectpeer.html'],
}


@resource_check('AWS::NetworkManager::ConnectPeer')
def evaluate_networkmanager_peer_family(design,resource):
 ctx=_Context(design,resource);results=[]
 def get(p):return value(ctx,resource,p)
 def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
 if resource.type=='AWS::NetworkManager::ConnectPeer':
  p='/properties/PeerAddress';a=get(p);b=get('/properties/CoreNetworkAddress');v='NEEDS_REVIEW'
  if literal(a) and literal(b) and '%' not in a+b:
   try:v='PASS' if ipaddress.ip_address(a).version==ipaddress.ip_address(b).version else 'FAIL'
   except ValueError:pass
  emit('NETWORKMANAGER_PEER_FAMILY',p,v,'explicit valid IP addresses must share address family; missing service-assigned address, malformed text and unresolved input remain held')
 return results
