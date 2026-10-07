"""Location API key action-family coverage for literal resource ARNs."""
import re
from ..registry import resource_check
from ..common.context_values import _Context, value
from ..common.literals import literal

SOURCES={'LOCATION_RESOURCE_ACTION_COVERAGE':['https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-location-apikey-apikeyrestrictions.html']}
FAMILIES={
 'map':{'geo:GetMap*'},
 'place-index':{'geo:SearchPlaceIndexForText','geo:SearchPlaceIndexForPosition','geo:SearchPlaceIndexForSuggestions','geo:GetPlace'},
 'route-calculator':{'geo:CalculateRoute','geo:CalculateRouteMatrix'},
 'geo-maps':{'geo-maps:GetTile','geo-maps:GetStaticMap','geo-maps:*'},
 'geo-places':{'geo-places:Autocomplete','geo-places:Geocode','geo-places:GetPlace','geo-places:ReverseGeocode','geo-places:SearchNearby','geo-places:SearchText','geo-places:Suggest','geo-places:*'},
 'geo-routes':{'geo-routes:CalculateIsolines','geo-routes:CalculateRoutes','geo-routes:CalculateRouteMatrix','geo-routes:OptimizeWaypoints','geo-routes:SnapToRoads','geo-routes:*'},
}


def family(raw):
    if not literal(raw):return None
    m=re.fullmatch(r'arn:aws(?:-[a-z0-9-]+)?:geo:[a-z0-9-]+:[0-9]{12}:(map|place-index|route-calculator)/[a-zA-Z0-9_.?*-]+',raw)
    if m:return m[1]
    m=re.fullmatch(r'arn:aws(?:-[a-z0-9-]+)?:(geo-maps|geo-places|geo-routes):[a-z0-9-]+::provider/default',raw)
    return m[1] if m else None


@resource_check('AWS::Location::APIKey')
def evaluate_location_action_resources(design,resource):
    if resource.type!='AWS::Location::APIKey':return []
    ctx=_Context(design,resource);base='/properties/Restrictions'
    actions=value(ctx,resource,base+'/AllowActions');arns=value(ctx,resource,base+'/AllowResources');verdict='NEEDS_REVIEW'
    if isinstance(actions,list) and len(actions)<=200 and isinstance(arns,list) and 0<len(arns)<=100 and (resource.template is None or resource.template.state.value=='KNOWN'):
        all_actions=set().union(*FAMILIES.values());known=set(a for a in actions if isinstance(a,str) and a in all_actions)
        unknown_action=any(not isinstance(a,str) or a not in all_actions for a in actions)
        families=[family(a) for a in arns]
        missing=any(f is not None and not (known & FAMILIES[f]) for f in families)
        if missing and not unknown_action:verdict='FAIL'
        elif not missing and not unknown_action and all(f is not None for f in families):verdict='PASS'
    f=ctx.finding('LOCATION_RESOURCE_ACTION_COVERAGE',base+'/AllowActions',verdict,'Each allowed resource type needs at least one corresponding action. Treat legacy geo map/place-index/route-calculator separately from enhanced geo-maps/geo-places/geo-routes provider/default resources; include the documented enhanced wildcard examples. Resource-name wildcards do not change the family. Unknown actions or ARN forms remain reviewable rather than treated as proof of missing permission. ARN scope, existence and general key validity are separate.')
    f['source_checked_at']='2026-10-04';return [f]
