"""Checks for AWS::Events::EventBus."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from .rule import encrypted_bus_discovery

SOURCES = {
    'EVENTS_PARTNER_BUS_NAME': ['https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_CreateEventBus.html'],
}


@resource_check('AWS::Events::EventBus')
def event_bus(design, resource):
    ctx = _Context(design, resource)
    results = encrypted_bus_discovery(design, resource)
    source = value(ctx, resource, '/properties/EventSourceName')
    if source is ABSENT:
        return results
    name = value(ctx, resource, '/properties/Name')
    verdict = ('PASS' if name == source else 'FAIL') if isinstance(name, str) and isinstance(source, str) else 'NEEDS_REVIEW'
    return results + [ctx.finding('EVENTS_PARTNER_BUS_NAME', '/properties/Name', verdict,
        'a partner event bus name must exactly match its partner event source name')]
