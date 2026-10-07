"""Checks for AWS::APS::RuleGroupsNamespace, AWS::APS::Scraper, AWS::APS::Workspace."""
import base64
from ..registry import resource_check
from ..common.bounded_yaml import bounded_yaml
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.key_types_and_base64 import base64_syntax
from ..common.literals import literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
PROM = 'https://prometheus.io/docs/'
SOURCES = {
    'APS_RULE_FILE_STRUCTURE': [CF+'aws-resource-aps-rulegroupsnamespace.html', PROM+'prometheus/latest/configuration/recording_rules/'],
    'APS_SCRAPE_FILE_STRUCTURE': [CF+'aws-properties-aps-scraper-scrapeconfiguration.html', PROM+'prometheus/latest/configuration/configuration/'],
    'APS_ALERT_RECEIVER_REFERENCES': [CF+'aws-resource-aps-workspace.html', 'https://docs.aws.amazon.com/prometheus/latest/userguide/AMP-alertmanager-config.html', PROM+'alerting/latest/configuration/'],
}


def rules_file(raw):
    verdict, data = bounded_yaml(raw)
    if data is None:
        return verdict
    if not isinstance(data, dict) or not isinstance(data.get('groups'), list):
        return 'NEEDS_REVIEW'
    names = set()
    for group in data['groups']:
        if not isinstance(group, dict) or not literal(group.get('name')):
            return 'NEEDS_REVIEW'
        if group['name'] in names:
            return 'FAIL'
        names.add(group['name'])
        if not isinstance(group.get('rules'), list):
            return 'NEEDS_REVIEW'
        for rule in group['rules']:
            if not isinstance(rule, dict):
                return 'NEEDS_REVIEW'
            if ('record' in rule) == ('alert' in rule) or 'expr' not in rule:
                return 'FAIL'
            if not literal(rule.get('expr')) or not literal(rule.get('record', rule.get('alert'))):
                return 'NEEDS_REVIEW'
    return 'PASS'


def scrape_file(raw):
    verdict = base64_syntax(raw)
    if verdict != 'PASS':
        return verdict
    try:
        text = base64.b64decode(raw, validate=True).decode('utf8')
    except UnicodeError:
        return 'NEEDS_REVIEW'
    verdict, data = bounded_yaml(text)
    if data is None:
        return verdict
    if not isinstance(data, dict) or not isinstance(data.get('scrape_configs'), list):
        return 'NEEDS_REVIEW'
    names = []
    for job in data['scrape_configs']:
        if not isinstance(job, dict) or not literal(job.get('job_name')):
            return 'NEEDS_REVIEW'
        names.append(job['job_name'])
    return 'PASS' if len(names) == len(set(names)) else 'FAIL'


def alert_receivers(raw):
    verdict, outer = bounded_yaml(raw)
    if outer is None:
        return verdict
    if not isinstance(outer, dict) or not isinstance(outer.get('alertmanager_config'), str):
        return 'NEEDS_REVIEW'
    verdict, data = bounded_yaml(outer['alertmanager_config'])
    if data is None:
        return verdict
    if not isinstance(data, dict) or not isinstance(data.get('receivers'), list):
        return 'NEEDS_REVIEW'
    names = []
    for receiver in data['receivers']:
        if not isinstance(receiver, dict) or not literal(receiver.get('name')):
            return 'NEEDS_REVIEW'
        names.append(receiver['name'])
    if len(names) != len(set(names)):
        return 'FAIL'
    pending = [data.get('route')]
    while pending:
        route = pending.pop()
        if not isinstance(route, dict):
            return 'NEEDS_REVIEW'
        if 'receiver' in route:
            if not literal(route['receiver']):
                return 'NEEDS_REVIEW'
            if route['receiver'] not in names:
                return 'FAIL'
        if 'routes' in route:
            if not isinstance(route['routes'], list):
                return 'NEEDS_REVIEW'
            pending.extend(route['routes'])
    return 'PASS'


@resource_check('AWS::APS::RuleGroupsNamespace', 'AWS::APS::Scraper', 'AWS::APS::Workspace')
def evaluate_aps_yaml_structure(design, resource):
    specs = {
        'AWS::APS::RuleGroupsNamespace': ('APS_RULE_FILE_STRUCTURE', '/properties/Data', rules_file),
        'AWS::APS::Scraper': ('APS_SCRAPE_FILE_STRUCTURE', '/properties/ScrapeConfiguration/ConfigurationBlob', scrape_file),
        'AWS::APS::Workspace': ('APS_ALERT_RECEIVER_REFERENCES', '/properties/AlertManagerDefinition', alert_receivers),
    }
    if resource.type not in specs:
        return []
    ctx = _Context(design, resource)
    rule, path, check = specs[resource.type]
    raw = value(ctx, resource, path)
    if raw is ABSENT:
        return []
    f = ctx.finding(rule, path, check(raw), 'bounded YAML structure and explicit name/reference checks only; PromQL, relabeling, templates, receiver/service-specific options, endpoints and permissions remain open; aliases, tags and duplicate keys held')
    f['source_checked_at'] = '2026-10-04'
    return [f]
