"""Checks for AWS::Budgets::Budget."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.literals import expand

CF='https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'BUDGET_SUBSCRIBER_COUNTS': [CF+'aws-properties-budgets-budget-notificationwithsubscribers.html'],
}


@resource_check('AWS::Budgets::Budget')
def evaluate_budgets_subscriber_counts(design,resource):
 ctx=_Context(design,resource);results=[]
 def get(p):return value(ctx,resource,p)
 def emit(rule,p,v,reason):results.append(ctx.finding(rule,p,v,reason))
 if resource.type=='AWS::Budgets::Budget':
  for p in expand(ctx,resource,'/properties/NotificationsWithSubscribers/*/Subscribers'):
   raw=get(p);counts={'SNS':0,'EMAIL':0};pending=not isinstance(raw,list)
   for i in range(len(raw)) if isinstance(raw,list) else ():
    kind=get(p+'/'+str(i)+'/SubscriptionType')
    if isinstance(kind,str) and kind in counts:counts[kind]+=1
    else:pending=True
   invalid=counts['SNS']>1 or counts['EMAIL']>10
   emit('BUDGET_SUBSCRIBER_COUNTS',p,'FAIL' if invalid else 'NEEDS_REVIEW' if pending else 'PASS','per notification at most one SNS and ten EMAIL subscribers; unknown kinds held unless known counts exceed bounds; total cardinality and delivery remain separate')
 return results
