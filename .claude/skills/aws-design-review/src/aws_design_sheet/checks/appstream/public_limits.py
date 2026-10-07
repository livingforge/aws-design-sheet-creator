"""Checks for AWS::AppStream::AppBlockBuilder, AWS::AppStream::Application, AWS::AppStream::Fleet."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.field_reads import ABSENT
from ..common.literals import expand, literal

CF = 'https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/'
SOURCES = {
    'APPSTREAM_BUILDER_PUBLIC_LIMITS': [CF+'aws-resource-appstream-appblockbuilder.html'],
    'APPSTREAM_APPLICATION_PUBLIC_LIMITS': [CF+'aws-resource-appstream-application.html'],
    'APPSTREAM_FLEET_PUBLIC_VALUES': [CF+'aws-resource-appstream-fleet.html'],
}
FLEET_PLATFORMS = ('WINDOWS','WINDOWS_SERVER_2016','WINDOWS_SERVER_2019','WINDOWS_SERVER_2022',
                   'WINDOWS_SERVER_2025','WINDOWS_11','AMAZON_LINUX2','RHEL8','ROCKY_LINUX8','UBUNTU_PRO_2404')


@resource_check('AWS::AppStream::AppBlockBuilder', 'AWS::AppStream::Application', 'AWS::AppStream::Fleet')
def evaluate_appstream_public_limits(design, resource):
    ctx = _Context(design, resource)
    results = []
    def get(path): return value(ctx, resource, path)
    def emit(rule, path, verdict, reason):
        results.append(ctx.finding(rule, path, verdict, reason))
    def enum(rule, path, choices):
        raw = get(path)
        if raw is not ABSENT:
            emit(rule, path, 'NEEDS_REVIEW' if not literal(raw) else 'PASS' if raw in choices else 'FAIL',
                 'explicit value compared with current documented allowed values; omitted and unresolved values are not inferred')
    def maximum(rule, path, limit):
        raw = get(path)
        if raw is not ABSENT:
            emit(rule, path, 'NEEDS_REVIEW' if not isinstance(raw, list) else 'PASS' if len(raw) <= limit else 'FAIL',
                 'explicit array length compared with documented maximum; member validity is separate')
    def required(rule, path, active):
        raw = get(path)
        verdict = 'NEEDS_REVIEW'
        if active:
            verdict = 'FAIL' if raw is ABSENT else 'PASS' if literal(raw) else 'NEEDS_REVIEW'
        emit(rule, path, verdict, 'checks presence only for an explicitly established triggering condition; credentials and resource existence remain external')

    if resource.type == 'AWS::AppStream::AppBlockBuilder':
        rule = 'APPSTREAM_BUILDER_PUBLIC_LIMITS'
        enum(rule,'/properties/Platform',('WINDOWS_SERVER_2019',))
        maximum(rule,'/properties/AppBlockArns',1)
    if resource.type == 'AWS::AppStream::Application':
        rule = 'APPSTREAM_APPLICATION_PUBLIC_LIMITS'
        for key, choices in [('InstanceFamilies',('GENERAL_PURPOSE','GRAPHICS_G4')),('Platforms',('WINDOWS_SERVER_2019','AMAZON_LINUX2'))]:
            for path in expand(ctx,resource,'/properties/'+key+'/*'): enum(rule,path,choices)
        maximum(rule,'/properties/Platforms',4)
    if resource.type == 'AWS::AppStream::Fleet':
        rule = 'APPSTREAM_FLEET_PUBLIC_VALUES'
        # Platform is documented as ignored for non-Elastic fleets.
        if get('/properties/FleetType') == 'ELASTIC': enum(rule,'/properties/Platform',FLEET_PLATFORMS)
        enum(rule,'/properties/StreamView',('APP','DESKTOP'))
    return results
