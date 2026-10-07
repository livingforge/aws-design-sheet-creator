"""Checks for AWS::Budgets::Budget, AWS::Budgets::BudgetsAction."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'BUDGET_PUBLIC_METADATA': [CF+'aws-resource-budgets-budget.html', CF+'aws-properties-budgets-budget-budgetdata.html', CF+'aws-properties-budgets-budget-notification.html', CF+'aws-properties-budgets-budget-subscriber.html', CF+'aws-properties-budgets-budget-autoadjustdata.html', CF+'aws-properties-budgets-budget-historicaloptions.html'],
    'BUDGET_ACTION_ROLE_ACCOUNT': [CF+'aws-resource-budgets-budgetsaction.html'],
}
BUDGET_ENUMS = {
    '/properties/Budget/BudgetType': ('USAGE','COST','RI_UTILIZATION','RI_COVERAGE','SAVINGS_PLANS_UTILIZATION','SAVINGS_PLANS_COVERAGE'),
    '/properties/Budget/TimeUnit': ('DAILY','MONTHLY','QUARTERLY','ANNUALLY','CUSTOM'),
    '/properties/Budget/AutoAdjustData/AutoAdjustType': ('HISTORICAL','FORECAST'),
    '/properties/NotificationsWithSubscribers/*/Notification/ComparisonOperator': ('GREATER_THAN','LESS_THAN','EQUAL_TO'),
    '/properties/NotificationsWithSubscribers/*/Notification/NotificationType': ('ACTUAL','FORECASTED'),
    '/properties/NotificationsWithSubscribers/*/Notification/ThresholdType': ('PERCENTAGE','ABSOLUTE_VALUE'),
    '/properties/NotificationsWithSubscribers/*/Subscribers/*/SubscriptionType': ('SNS','EMAIL'),
}


@resource_check('AWS::Budgets::Budget', 'AWS::Budgets::BudgetsAction')
def evaluate_budgets_budget_values(design, resource):
    ctx = _Context(design, resource)
    results = []
    def get(path): return value(ctx, resource, path)
    def emit(rule,path,verdict,reason):
        finding = ctx.finding(rule,path,verdict,reason)
        finding['source_checked_at'] = '2026-10-04'
        results.append(finding)
    if resource.type == 'AWS::Budgets::Budget':
        rule = 'BUDGET_PUBLIC_METADATA'
        for pattern, allowed in BUDGET_ENUMS.items():
            for path in expand(ctx,resource,pattern):
                raw = get(path)
                emit(rule,path,'NEEDS_REVIEW' if not literal(raw) else 'PASS' if raw in allowed else 'FAIL','explicit value compared with current CF allowed values; unknown inputs held')
        path = '/properties/ResourceTags'
        raw = get(path)
        if raw is not ABSENT:
            emit(rule,path,'NEEDS_REVIEW' if not isinstance(raw,list) else 'PASS' if len(raw) <= 200 else 'FAIL','documented ResourceTags maximum is 200; conflicting notification count is deliberately excluded')
        path = '/properties/Budget/AutoAdjustData/HistoricalOptions/BudgetAdjustmentPeriod'
        raw = get(path)
        if raw is not ABSENT:
            emit(rule,path,'NEEDS_REVIEW' if type(raw) is not int else 'PASS' if 1 <= raw <= 60 else 'FAIL','checks public absolute 1..60 bound only; existing TimeUnit-specific rules remain in force')
    if resource.type == 'AWS::Budgets::BudgetsAction':
        path = '/properties/ExecutionRoleArn'
        raw = get(path)
        match = re.fullmatch(r'arn:aws(?:-eusc|-cn|-us-gov|-iso|-iso-[a-z])?:iam::([0-9]{12}):role/[^\s]+',raw) if literal(raw) else None
        account = resource.scope.account
        verdict = 'NEEDS_REVIEW'
        if match and re.fullmatch(r'[0-9]{12}',account): verdict = 'PASS' if match[1] == account else 'FAIL'
        emit('BUDGET_ACTION_ROLE_ACCOUNT',path,verdict,'execution role ARN account must equal explicit action deployment account; role existence and permissions remain external')
    return results
