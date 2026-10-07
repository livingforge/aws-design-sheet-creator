"""Checks for AWS::ApiGateway::Model."""
from __future__ import annotations

import json
from ..registry import resource_check
from ..common.design_uniqueness import _Context
from ..common.field_reads import ABSENT, UNKNOWN, read


SOURCES = {
    "APIGATEWAY_MODEL_SDK_DESCRIPTION": [
        "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigateway-model.html"],
}


@resource_check('AWS::ApiGateway::Model')
def model_sdk_descriptions(design, resource):
    """Inspect schema keywords, never user data in defaults/examples/enums."""
    ctx = _Context(design, resource)
    path = '/properties/Schema'
    schema = read(ctx, resource, path)
    if schema is ABSENT:
        return []
    if isinstance(schema, str):
        try:
            schema = json.loads(schema)
        except (ValueError, RecursionError):
            schema = UNKNOWN
    pending, bad = False, False
    stack = [schema]
    count = 0
    while stack:
        node = stack.pop()
        count += 1
        if count > 10000:
            pending = True
            break
        if not isinstance(node, dict) or any(k in node for k in ('$state', 'Ref')) or any(
                isinstance(k, str) and k.startswith('Fn::') for k in node):
            pending = True
            continue
        # JSON Schema $ref is an unresolved schema reference, not a description.
        pending |= '$ref' in node
        if 'description' in node:
            description = node['description']
            if not isinstance(description, str) or '{{resolve:' in description:
                pending = True
            elif '*/' in description:
                bad = True
        for key in ('properties', 'patternProperties', 'definitions'):
            if key in node:
                if isinstance(node[key], dict):
                    stack.extend(node[key].values())
                else:
                    pending = True
        for key in ('items', 'additionalItems', 'additionalProperties', 'not'):
            if key in node and not isinstance(node[key], bool):
                stack.extend(node[key] if isinstance(node[key], list) else [node[key]])
        for key in ('allOf', 'anyOf', 'oneOf'):
            if key in node:
                if isinstance(node[key], list):
                    stack.extend(node[key])
                else:
                    pending = True
        if 'dependencies' in node:
            if isinstance(node['dependencies'], dict):
                stack.extend(v for v in node['dependencies'].values() if not isinstance(v, list))
            else:
                pending = True
    verdict = 'FAIL' if bad else 'NEEDS_REVIEW' if pending else 'PASS'
    return [{**ctx.finding('APIGATEWAY_MODEL_SDK_DESCRIPTION', path, verdict,
        'schema descriptions containing */ can break generated SDK installation; schema references and unresolved values need review'),
        'severity': 'WARNING', 'source_checked_at': '2026-10-03'}]
