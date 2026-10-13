"""Documented legacy map styles and Grab's regional restriction."""
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.literals import literal
from ..common.scoped_resolution import resolved

URLS=['https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-location-map-mapconfiguration.html','https://docs.aws.amazon.com/location/previous/APIReference/API_MapConfiguration.html']
SOURCES={rule:URLS for rule in ('LOCATION_MAP_STYLE_CATALOG','LOCATION_GRAB_MAP_REGION')}
STYLES=set('VectorEsriDarkGrayCanvas RasterEsriImagery VectorEsriLightGrayCanvas VectorEsriTopographic VectorEsriStreets VectorEsriNavigation VectorHereContrast VectorHereBerlin VectorHereExplore VectorHereExploreTruck RasterHereExploreSatellite HybridHereExploreSatellite VectorGrabStandardLight VectorGrabStandardDark VectorOpenDataStandardLight VectorOpenDataStandardDark VectorOpenDataVisualizationLight VectorOpenDataVisualizationDark'.split())
GRAB={'VectorGrabStandardLight','VectorGrabStandardDark'}


@resource_check('AWS::Location::Map')
def evaluate_location_map_styles(design,resource):
    if resource.type!='AWS::Location::Map':return []
    ctx=_Context(design,resource);style=value(ctx,resource,'/properties/Configuration/Style')
    known=resolved(resource) and literal(style)
    catalog=('PASS' if style in STYLES else 'FAIL') if known else 'NEEDS_REVIEW'
    region=('PASS' if resource.scope.region=='ap-southeast-1' else 'FAIL') if known and style in GRAB else 'NOT_APPLICABLE' if known and style in STYLES else 'NEEDS_REVIEW'
    result=[]
    for rule,verdict,message in [
        ('LOCATION_MAP_STYLE_CATALOG',catalog,'Compare the declared style against the documented legacy MapConfiguration catalog. The deprecated VectorHereBerlin alias remains supported. PASS confirms the style name only; it does not certify provider availability or coverage.'),
        ('LOCATION_GRAB_MAP_REGION',region,'Grab map styles require ap-southeast-1. Other documented providers are outside this Grab-specific check; unresolved scope or style remains reviewable.')]:
        finding=ctx.finding(rule,'/properties/Configuration/Style',verdict,message)
        finding['source_checked_at']='2026-10-04';result.append(finding)
    return result
