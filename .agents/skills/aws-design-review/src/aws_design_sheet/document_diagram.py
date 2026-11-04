"""Architecture diagram: one environment's resources and declared connections as a draw.io file.

Icons are draw.io's built-in AWS shapes, referenced by name; no icon is bundled or fetched.
A resource sits inside a VPC or subnet only when its own effective settings reference that
VPC or subnet, or a security group or subnet group that does, or when a VPC gateway
attachment attaches it; a database instance naming nothing of its own network sits with the
cluster it names. Lines are the declared connections and, dashed, the resources a setting
names, leaving out what the frames show and the keys, log groups and roles many resources share.
A resource left off the picture (a listener, a user pool domain, a route table and its routes)
that names two resources on it joins them with a dashed line carrying its name, and a subnet
whose associated route table routes to an internet gateway is drawn public, one with a route
table and no such route private. Actors, the people, outside systems and AWS services the input
names without modelling them, stand outside the AWS Cloud frame, the AWS services inside their
region. Nothing is inferred from names, CIDRs or defaults, and the picture is not a reachability
or correctness result.

The layout is computed, with no judgement involved: inside each frame, items joined by lines
stand in columns that follow the lines from left to right, lines turn at right angles in the
gaps between columns and pass other columns through reserved bends, and items without lines
sit in rows below, grouped by icon colour and type. Groups with lines crossing a frame's sides are
placed together, so that small ones fill the columns of large ones. Lopsided groups fold their tall columns or
wrap into bands. Subnets with a decided zone sit in a zone frame, and a resource spanning
several subnets leaves a tag in each. The same input always gives the same file.
"""
import html
import unicodedata
from collections import Counter
import xml.etree.ElementTree as ET

from .document_v11 import SchemaSetting

CMP, DB, STO, NET, ANA, INT, MGT, SEC, ENG = ('#ED7100', '#C925D1', '#7AA116', '#8C4FFF', '#8C4FFF',
                                             '#E7157B', '#E7157B', '#DD344C', '#3334B9')
# Main resource types and their draw.io AWS4 shapes. A 'shape:' name is a plain shape,
# the rest are service icons. Other types appear only as the end of a declared connection.
ICONS = {
    'AWS::ACMPCA::CertificateAuthority': ('private_certificate_authority', SEC),
    'AWS::AccessAnalyzer::Analyzer': ('identity_and_access_management', SEC),
    'AWS::ApiGateway::RestApi': ('api_gateway', INT), 'AWS::ApiGatewayV2::Api': ('api_gateway', INT),
    'AWS::Athena::WorkGroup': ('athena', ANA),
    'AWS::AutoScaling::AutoScalingGroup': ('auto_scaling2', CMP),
    'AWS::Backup::BackupPlan': ('backup', STO), 'AWS::Backup::BackupVault': ('backup', STO),
    'AWS::CertificateManager::Certificate': ('certificate_manager_3', SEC),
    'AWS::CloudFormation::Stack': ('cloudformation', MGT), 'AWS::CloudFormation::StackSet': ('cloudformation', MGT),
    'AWS::CloudFront::Distribution': ('cloudfront', NET),
    'AWS::CloudTrail::Trail': ('cloudtrail', MGT), 'AWS::CloudTrail::EventDataStore': ('cloudtrail', MGT),
    'AWS::CloudWatch::Alarm': ('cloudwatch_2', MGT), 'AWS::CloudWatch::CompositeAlarm': ('cloudwatch_2', MGT),
    'AWS::CloudWatch::Dashboard': ('cloudwatch_2', MGT),
    'AWS::Cognito::UserPool': ('cognito', SEC), 'AWS::Cognito::IdentityPool': ('cognito', SEC),
    'AWS::Config::ConfigurationRecorder': ('config', MGT), 'AWS::Config::ConfigRule': ('config', MGT),
    'AWS::Config::ConformancePack': ('config', MGT), 'AWS::Config::ConfigurationAggregator': ('config', MGT),
    'AWS::ControlTower::LandingZone': ('control_tower', MGT), 'AWS::ControlTower::EnabledControl': ('control_tower', MGT),
    'AWS::ControlTower::EnabledBaseline': ('control_tower', MGT),
    'AWS::DynamoDB::Table': ('dynamodb', DB), 'AWS::DynamoDB::GlobalTable': ('dynamodb', DB),
    'AWS::EC2::Instance': ('ec2', CMP), 'AWS::EC2::Volume': ('elastic_block_store', STO),
    'AWS::EC2::InternetGateway': ('shape:internet_gateway', NET), 'AWS::EC2::EgressOnlyInternetGateway': ('shape:internet_gateway', NET),
    'AWS::EC2::NatGateway': ('shape:nat_gateway', NET), 'AWS::EC2::VPCEndpoint': ('shape:endpoints', NET),
    'AWS::EC2::VPNGateway': ('shape:vpn_gateway', NET), 'AWS::EC2::CustomerGateway': ('shape:customer_gateway', NET),
    'AWS::EC2::VPNConnection': ('shape:vpn_connection', NET), 'AWS::EC2::VPCPeeringConnection': ('shape:peering', NET),
    'AWS::EC2::TransitGateway': ('transit_gateway', NET),
    'AWS::EC2::TransitGatewayAttachment': ('shape:transit_gateway_attachment', NET),
    'AWS::EC2::TransitGatewayVpcAttachment': ('shape:transit_gateway_attachment', NET),
    'AWS::EC2::ClientVpnEndpoint': ('client_vpn', NET),
    'AWS::ECR::Repository': ('ecr', CMP), 'AWS::ECR::PublicRepository': ('ecr', CMP),
    'AWS::ECS::Cluster': ('ecs', CMP), 'AWS::ECS::Service': ('ecs', CMP), 'AWS::ECS::TaskDefinition': ('ecs', CMP),
    'AWS::EKS::Cluster': ('eks', CMP),
    'AWS::ElastiCache::CacheCluster': ('elasticache', DB), 'AWS::ElastiCache::ReplicationGroup': ('elasticache', DB),
    'AWS::ElastiCache::ServerlessCache': ('elasticache', DB),
    'AWS::ElasticLoadBalancing::LoadBalancer': ('shape:classic_load_balancer', NET),
    'AWS::ElasticLoadBalancingV2::LoadBalancer': ('elastic_load_balancing', NET),
    'AWS::Elasticsearch::Domain': ('elasticsearch_service', ANA), 'AWS::OpenSearchService::Domain': ('elasticsearch_service', ANA),
    'AWS::Events::Rule': ('eventbridge', INT), 'AWS::Events::EventBus': ('eventbridge', INT),
    'AWS::EventSchemas::Registry': ('eventbridge', INT), 'AWS::Pipes::Pipe': ('eventbridge', INT),
    'AWS::Scheduler::Schedule': ('eventbridge', INT),
    'AWS::FSx::FileSystem': ('fsx', STO),
    'AWS::Glue::Job': ('glue', ANA), 'AWS::Glue::Crawler': ('glue', ANA), 'AWS::Glue::Database': ('glue', ANA),
    'AWS::Glue::Workflow': ('glue', ANA),
    'AWS::GuardDuty::Detector': ('guardduty', SEC),
    'AWS::IAM::Role': ('identity_and_access_management', SEC), 'AWS::IAM::User': ('identity_and_access_management', SEC),
    'AWS::InspectorV2::Filter': ('inspector', SEC), 'AWS::InspectorV2::CisScanConfiguration': ('inspector', SEC),
    'AWS::KMS::Key': ('key_management_service', SEC), 'AWS::KMS::ReplicaKey': ('key_management_service', SEC),
    'AWS::Kinesis::Stream': ('kinesis_data_streams', ANA), 'AWS::KinesisFirehose::DeliveryStream': ('kinesis_data_firehose', ANA),
    'AWS::Lambda::Function': ('lambda', CMP),
    'AWS::Logs::LogGroup': ('shape:logs', MGT),
    'AWS::MSK::Cluster': ('managed_streaming_for_kafka', ANA), 'AWS::MSK::ServerlessCluster': ('managed_streaming_for_kafka', ANA),
    'AWS::Macie::Session': ('macie', SEC),
    'AWS::Organizations::Organization': ('organizations', MGT), 'AWS::Organizations::Account': ('organizations', MGT),
    'AWS::RAM::ResourceShare': ('resource_access_manager', SEC),
    'AWS::RDS::DBInstance': ('rds', DB), 'AWS::RDS::DBCluster': ('rds', DB), 'AWS::RDS::GlobalCluster': ('rds', DB),
    'AWS::RDS::DBProxy': ('rds', DB),
    'AWS::Redshift::Cluster': ('redshift', ANA),
    'AWS::Route53::HostedZone': ('route_53', NET), 'AWS::Route53Resolver::ResolverEndpoint': ('shape:route_53_resolver', NET),
    'AWS::S3::Bucket': ('s3', STO),
    'AWS::SES::EmailIdentity': ('simple_email_service', ENG), 'AWS::SES::ConfigurationSet': ('simple_email_service', ENG),
    'AWS::SNS::Topic': ('sns', INT), 'AWS::SQS::Queue': ('sqs', INT),
    'AWS::SSM::Parameter': ('shape:parameter_store', MGT), 'AWS::SSM::Document': ('systems_manager', MGT),
    'AWS::SSM::MaintenanceWindow': ('systems_manager', MGT), 'AWS::SSM::PatchBaseline': ('systems_manager', MGT),
    'AWS::SSM::Association': ('systems_manager', MGT),
    'AWS::SecretsManager::Secret': ('secrets_manager', SEC),
    'AWS::SecurityHub::Hub': ('security_hub', SEC), 'AWS::SecurityHub::HubV2': ('security_hub', SEC),
    'AWS::ServiceCatalog::Portfolio': ('service_catalog', MGT), 'AWS::ServiceCatalog::CloudFormationProduct': ('service_catalog', MGT),
    'AWS::Shield::Protection': ('shield', SEC), 'AWS::Shield::ProtectionGroup': ('shield', SEC),
    'AWS::StepFunctions::StateMachine': ('step_functions', INT),
    'AWS::WAFv2::WebACL': ('waf', SEC),
}
# A connected type without its own entry gets the generic icon in its service's colour;
# borrowing the service icon would draw, say, a security group as an EC2 instance.
SERVICE_COLORS = {}
for _type, (_, _color) in ICONS.items():SERVICE_COLORS.setdefault(_type.split('::')[1], _color)
GENERIC = 'general'
# Services whose resources are not regional.
GLOBAL = {'IAM', 'Organizations', 'CloudFront', 'Route53'}
VPC, SUBNET, SECURITY_GROUP, ATTACHMENT = 'AWS::EC2::VPC', 'AWS::EC2::Subnet', 'AWS::EC2::SecurityGroup', 'AWS::EC2::VPCGatewayAttachment'
LOAD_BALANCERS = {'application': 'shape:application_load_balancer', 'network': 'shape:network_load_balancer',
                  'gateway': 'shape:gateway_load_balancer'}
# References a frame already shows, and targets so many resources reference that their lines would bury the rest.
PLACED = {VPC, SUBNET, SECURITY_GROUP}
SHARED = {'AWS::KMS::Key', 'AWS::Logs::LogGroup', 'AWS::IAM::Role'}
# Settings naming what an alarm watches or where logs are written, like a part named Logging inside a setting: they
# reach across the picture without being a path the system's data takes.
WATCHED = {('AWS::CloudWatch::Alarm', 'Dimensions'), ('AWS::CloudWatch::Alarm', 'Metrics'),
           ('AWS::CloudTrail::Trail', 'S3BucketName'), ('AWS::ElasticLoadBalancingV2::LoadBalancer', 'LoadBalancerAttributes')}

GROUP = 'sketch=0;outlineConnect=0;gradientColor=none;html=1;whiteSpace=wrap;fontSize=12;fontStyle=0;container=1;collapsible=0;shape=mxgraph.aws4.group;verticalAlign=top;align=left;spacingLeft=30;'
STYLES = {'cloud': GROUP + 'grIcon=mxgraph.aws4.group_aws_cloud_alt;strokeColor=#232F3E;fillColor=none;fontColor=#232F3E;dashed=0;',
          'account': GROUP + 'grIcon=mxgraph.aws4.group_account;strokeColor=#CD2264;fillColor=none;fontColor=#CD2264;dashed=0;',
          'region': GROUP + 'grIcon=mxgraph.aws4.group_region;strokeColor=#00A4A6;fillColor=none;fontColor=#147EBA;dashed=1;',
          'vpc': GROUP + 'grIcon=mxgraph.aws4.group_vpc2;strokeColor=#8C4FFF;fillColor=none;fontColor=#8C4FFF;dashed=0;',
          # draw.io's subnet frames: neutral when the input routes nothing for the subnet, else public or private.
          'subnet': GROUP + 'grIcon=mxgraph.aws4.group_security_group;grStroke=0;strokeColor=#879196;fillColor=#F2F3F3;fontColor=#545B64;dashed=0;',
          'subnet-public': GROUP + 'grIcon=mxgraph.aws4.group_security_group;grStroke=0;strokeColor=#7AA116;fillColor=#F2F6E8;fontColor=#248814;dashed=0;',
          'subnet-private': GROUP + 'grIcon=mxgraph.aws4.group_security_group;grStroke=0;strokeColor=#00A4A6;fillColor=#E6F6F7;fontColor=#147EBA;dashed=0;',
          # Holds the AWS Cloud frame and the actors outside it; it draws nothing itself.
          'canvas': 'rounded=0;whiteSpace=wrap;html=1;container=1;collapsible=0;fillColor=none;strokeColor=none;',
          'group': 'rounded=1;arcSize=4;whiteSpace=wrap;html=1;container=1;collapsible=0;fillColor=none;strokeColor=#879196;dashed=1;'
                   'verticalAlign=top;align=left;spacingLeft=10;fontColor=#545B64;fontSize=11;',
          'zone': 'rounded=0;whiteSpace=wrap;html=1;container=1;collapsible=0;fillColor=none;strokeColor=#147EBA;dashed=1;verticalAlign=top;'
                  'align=left;spacingLeft=10;fontColor=#147EBA;fontSize=12;'}
# A tag in each subnet a resource spanning several subnets is placed in, edged in the resource's colour.
TAG_STYLE = 'rounded=1;arcSize=40;html=1;whiteSpace=nowrap;fontSize=10;fontColor=#545B64;fillColor=#FFFFFF;dashed=1;align=center;verticalAlign=middle;'
ICON_STYLE = 'sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=none;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;fontSize=12;fontStyle=0;aspect=fixed;'
NOTE_STYLE = 'text;html=1;whiteSpace=wrap;align=left;verticalAlign=top;fontSize=11;fontColor=#545B64;'
CAPTION_STYLE = 'text;html=1;align=left;verticalAlign=middle;fontSize=11;fontColor=#879196;'
ICON, CELL_W, CELL_H, PAD, HEAD, GAP, MIN_W = 48, 170, 110, 20, 44, 30, 220
# Column spacing, stacking gap, reserved space for a bend, empty frame height, caption height, icons per
# row of items without lines, the width of a name line (a wide character counts two), and lane spacing.
LAYER_GAP, ROW_GAP, BEND_W, BEND_H, EMPTY_H, CAPTION_H, ROW_ICONS, LINE_UNITS, CHANNEL = 60, 10, 40, 20, 40, 24, 4, 24, 14
CLOSING = '）)」』】］]、。，,．.'
OPENING, BREAKS = '（(「『【［[', ' -/_.:・、'
# Room a line label needs on a stretch of its own, the tallest column before it folds into several, the
# widest run of columns before it wraps into a band below, and the height of a placement tag.
LABEL_ROOM, FOLD_H, WRAP_W, TAG_H = 50, 1400, 2400, 24
# How many resources referencing one target through one setting are gathered into a frame with one line, and
# how many icons stand in each of the frame's rows.
FAN, FAN_ICONS = 3, 2
# How far from an icon's middle, where the other lines meet it, a line travelling right to left meets it.
BACK = 12
# Actors' shapes: people and outside systems as draw.io's AWS user and server shapes, an AWS service the input
# cannot model with the generic icon.
ACTOR_ICONS = {'USER': ('shape:users', '#232F3E'), 'OPERATOR': ('shape:user', '#232F3E'),
               'EXTERNAL_SYSTEM': ('shape:traditional_server', '#232F3E'), 'AWS_SERVICE': (GENERIC, '#232F3E')}
ROUTE_TABLE, GATEWAYS = 'AWS::EC2::RouteTable', {'AWS::EC2::InternetGateway'}


def leaves(setting, path=()):
    """(path inside the setting, resource ID) for each resource a setting names through RESOURCE_REF, including
    composite leaves."""
    if setting.status != 'DECIDED':return []
    if setting.mode == 'RESOURCE_REF':return [(path, r) for r in (setting.ref if isinstance(setting.ref, list) else [setting.ref])]
    if setting.mode != 'COMPOSITE':return []
    found = []
    def walk(value, at):
        if isinstance(value, dict):
            if set(value) == {'$design'}:
                found.extend(leaves(SchemaSetting.model_validate(value['$design']), at));return
            for k, v in value.items():walk(v, at + (k,))
        elif isinstance(value, list):
            for v in value:walk(v, at)
    walk(setting.value, path)
    return found


def references(setting):
    """Resource IDs a setting names through RESOURCE_REF, including composite leaves."""
    return [r for _, r in leaves(setting)]


class Box:
    def __init__(self, ident, kind, label, rid=None, rank=()):
        self.id, self.kind, self.label, self.rid, self.rank, self.items = ident, kind, label, rid, rank, []
        self.x = self.y = self.w = self.h = 0
        self.members = {rid} if rid else set()
        # Bend points of the lines this box routes and the heights where lines cross its sides (relative to
        # the box), where each resource inside sits, and the caption row.
        self.routes, self.ports, self.keys, self.where, self.caption, self.label_w = {}, {}, {}, {}, None, 0
        if kind == 'leaf':self.w, self.h = CELL_W, CELL_H


class Reference:
    """A line for a setting that names another resource, or for a resource left off the picture (`via`) that names
    both ends; IDs never hold a dot, so the line's ID is unique."""
    kind, status, ports = 'REFERENCE', 'DECIDED', ''
    def __init__(self, source, target, name='', via=''):
        self.source, self.target, self.name, self.id, self.via = source, target, name, f'{source}.{target}', via
        self.protocol = f'経由：{via}' if via else ''


def units(value):
    return sum(2 if unicodedata.east_asian_width(ch) in 'WFA' else 1 for ch in value)


def script(ch):
    if '぀' <= ch <= 'ゟ':return 'hiragana'
    if '゠' <= ch <= 'ヿ':return 'katakana'
    if '一' <= ch <= '鿿':return 'kanji'
    return 'wide' if units(ch) == 2 else 'narrow'


def breaks(text, i):
    """Whether a line may break before text[i]: after a space or a mark such as a hyphen or slash, before an
    opening bracket, or where scripts change, except before hiragana, which stays with the word it follows."""
    a, b = text[i - 1], text[i]
    if b in CLOSING or a in OPENING:return False
    return a in BREAKS or b in OPENING or script(a) != script(b) and script(b) != 'hiragana'


def wrap(name):
    """At most two lines that fit an icon's column, broken where breaks allows; a word with nowhere to break
    runs a little wide before it is cut, and a longer name ends with an ellipsis."""
    lines, line = [], ''
    for ch in name:
        # A closing bracket or punctuation mark stays on the line it closes.
        if line and units(line + ch) > LINE_UNITS and ch not in CLOSING:
            text = line + ch;cut = max((i for i in range(1, len(text)) if breaks(text, i)), default=0)
            if cut:
                lines.append(text[:cut].rstrip(' '));line = text[cut:].lstrip(' ');continue
            if units(text) <= LINE_UNITS + 2:line = text;continue
            lines.append(line);line = ''
        if ch != ' ' or line:line += ch
    lines.append(line)
    if len(lines) > 2:
        last = lines[1]
        while units(last + '…') > LINE_UNITS:last = last[:-1]
        lines = [lines[0], last.rstrip() + '…']
    return lines


def virtual(n):
    """The far side of a line that continues past the left ('W') or right ('E') of the columns being placed."""
    return isinstance(n, tuple) and n[0] in ('W', 'E')


def place(columns, chains, sizes, hints, folded=()):
    """Order, heights and line routes for a run of columns.

    columns hold item indices and ('bend', ...) nodes. chains maps a line key to (nodes, oa, ob, ra, rb): the
    line's nodes in column order, with a virtual end where it continues past the columns, the heights inside
    the items at its ends, and what its ends are. hints gives a virtual end's far height in an earlier layout.
    folded are the columns a tall column folded into: their items stack from the top, with bends below them.
    Returns item positions, each chain's bend points in column order, the heights of its virtual ends by
    (key, side), and the size.
    """
    layer = {n: k for k, col in enumerate(columns) for n in col}
    up, down, link = {n: [] for n in layer}, {n: [] for n in layer}, {}
    for key, (chain, oa, ob, ra, rb) in chains.items():
        for n in (chain[0], chain[-1]):
            if virtual(n):up[n], down[n] = [], []
        for i, (u, v) in enumerate(zip(chain, chain[1:])):
            if not virtual(u) and not virtual(v) and layer[u] == layer[v]:continue
            if v not in down[u]:down[u].append(v);up[v].append(u)
            if virtual(u) or virtual(v):continue
            link.setdefault((u, v), []).append((oa if i == 0 else BEND_H // 2, ob if i == len(chain) - 2 else BEND_H // 2))
    link = {k: (sum(o[0] for o in v) / len(v), sum(o[1] for o in v) / len(v)) for k, v in link.items()}

    def crossings(cols):
        found = 0
        for left, right in zip(cols, cols[1:]):
            at, pos = {n: i for i, n in enumerate(left)}, {n: i for i, n in enumerate(right)}
            segments = [(at[u], pos[v]) for u in left for v in down[u]]
            found += sum(1 for i, (a, b) in enumerate(segments) for c, d in segments[i + 1:] if (a - c) * (b - d) < 0)
        return found
    def outside(end):
        found = [(chain[end], i) for i, (chain, *_) in enumerate(chains.values()) if virtual(chain[end])]
        return [n for n, i in sorted(found, key=lambda x:(hints.get(x[0][1]) is None, hints.get(x[0][1], 0), x[1]))]
    columns = [outside(0)] + [list(c) for c in columns] + [outside(-1)]
    best, fewest = [list(c) for c in columns], crossings(columns)
    for sweep in range(8):
        steps = range(1, len(columns) - 1) if sweep % 2 == 0 else range(len(columns) - 2, 0, -1)
        for k in steps:
            ref = {n: i for i, n in enumerate(columns[k - 1 if sweep % 2 == 0 else k + 1])}
            def weight(item):
                n = item[1];near = [ref[m] for m in (up[n] if sweep % 2 == 0 else down[n]) if m in ref]
                return (sum(near) / len(near) if near else item[0], item[0])
            columns[k] = [n for _, n in sorted(enumerate(columns[k]), key=weight)]
        count = crossings(columns)
        if count < fewest:best, fewest = [list(c) for c in columns], count
    columns = best[1:-1]
    for k in folded:columns[k] = [n for n in columns[k] if not isinstance(n, tuple)] + [n for n in columns[k] if isinstance(n, tuple)]
    for n in list(up):
        if not virtual(n):up[n], down[n] = [u for u in up[n] if not virtual(u)], [v for v in down[n] if not virtual(v)]

    def size(n):return (0, BEND_H) if isinstance(n, tuple) else sizes[n]
    # Heights: each column keeps its order and spacing and sits as close as it can, in the least-squares
    # sense, to the heights its lines want. First each item follows its sources and each start its targets,
    # then a few rounds balance every item between both sides.
    y = {}
    def stack(col, wanted):
        offsets, total = [], 0
        for n in col:offsets.append(total);total += size(n)[1] + ROW_GAP
        blocks = []
        for n, offset in zip(col, offsets):
            want = wanted(n);blocks.append([(want if want is not None else y.get(n, offset)) - offset, 1])
            while len(blocks) > 1 and blocks[-2][0] / blocks[-2][1] > blocks[-1][0] / blocks[-1][1]:
                tail = blocks.pop();blocks[-1][0] += tail[0];blocks[-1][1] += tail[1]
        i = 0
        for value, count in blocks:
            for _ in range(count):y[col[i]] = round(value / count + offsets[i]);i += 1
    def mean(values):return sum(values) / len(values)
    def before(n):return [y[u] + link[u, n][0] - link[u, n][1] for u in up[n]]
    def after(n):return [y[v] + link[n, v][1] - link[n, v][0] for v in down[n]]
    fixed = {n for k in folded for n in columns[k] if not isinstance(n, tuple)}
    for col in columns:stack(col, lambda n:mean(before(n)) if up[n] and n not in fixed else None)
    for col in reversed(columns):stack(col, lambda n:mean(after(n)) if not up[n] and down[n] and n not in fixed else y[n])
    for sweep in range(4):
        for col in (columns if sweep % 2 == 0 else columns[::-1]):
            stack(col, lambda n:mean(before(n) + after(n)) if (up[n] or down[n]) and n not in fixed else y[n])
    lowest = min(y.values())
    for n in y:y[n] -= lowest
    # A line travelling right to left meets an icon off its middle, on the side it comes from or goes to: above
    # when its next bend is higher, otherwise below. A line straight between two items keeps to one side of the
    # lines going the other way between them: above at both ends when it climbs from left to right. Neither rule
    # suits every picture, so the lines are also routed with all such lines above, and all below, and the
    # routing with the fewest crossings is kept.
    def side(chain, i, own):
        n = chain[1 if i == 0 else -2]
        if virtual(chain[i]) or virtual(n) or not isinstance(n, tuple):return BACK
        return -BACK if y[n] + BEND_H // 2 < y[chain[i]] + own else BACK
    def shifted(policy):
        found = {}
        for key, (chain, oa, ob, ra, rb) in chains.items():
            # In a band of a wrapped flow, an end in another band is virtual here.
            if not (ra and ra[0] == 'back'):found[key] = (chain, oa, ob, ra, rb);continue
            if policy:sa = sb = policy * BACK
            elif len(chain) == 2 and not virtual(chain[0]) and not virtual(chain[-1]):
                sa = sb = -BACK if y[chain[0]] + oa > y[chain[-1]] + ob else BACK
            else:sa, sb = side(chain, 0, oa), side(chain, -1, ob)
            found[key] = (chain, oa + sa if ra[2] and not virtual(chain[0]) else oa, ob + sb if rb[2] and not virtual(chain[-1]) else ob, ra, rb)
        return found
    def route(chains):
        # A bend at the height where another line meets the next or previous column would make the two run
        # together in the gap between, so it moves a little within its reserved slot.
        lift, used = {}, {}
        for key, (chain, oa, ob, ra, rb) in chains.items():
            for i, n in enumerate(chain):
                if not virtual(n) and not isinstance(n, tuple):used.setdefault(layer[n], []).append((y[n] + (oa if i == 0 else ob), n))
        for k, col in enumerate(columns):
            for n in col:
                if isinstance(n, tuple):used.setdefault(k, []).append((y[n] + BEND_H // 2, n))
        for k, col in enumerate(columns):
            for n in col:
                if not isinstance(n, tuple):continue
                near = {h for j in (k - 1, k + 1) for h, m in used.get(j, []) if m != n};base = y[n] + BEND_H // 2
                lift[n] = next((d for d in (0, 4, -4, 8, -8) if base + d not in near), 0)
                used[k] = [(base + lift[n] if m == n else h, m) for h, m in used[k]]
        def height(chain, i, oa, ob):
            n = chain[i]
            if virtual(n):return height(chain, i + 1 if i == 0 else i - 1, oa, ob)
            return y[n] + (BEND_H // 2 + lift[n] if isinstance(n, tuple) else oa if i == 0 else ob)
        # Lines turn in vertical channels in the gaps between columns: one channel for each end's lines leaving
        # an item, one for each bend, and one beside a frame whose side faces away from the line. Gap -1 and the
        # last gap are margins beside the first and last columns.
        last = len(columns) - 1
        def turn(chain, i, ra, rb, oa, ob):
            u, v = chain[i], chain[i + 1]
            if layer[u] == layer[v]:return (layer[u] - 1, (u, ra, 'side')) if i == 0 else (layer[v], (v, rb, 'side'))
            # An end's lines going up and going down turn in channels of their own, so that each spans only one side
            # of the end and the channels of two ends need not cross each other's runs.
            return layer[u], (u, ra, height(chain, 1, oa, ob) < height(chain, 0, oa, ob)) if i == 0 else (u,)
        slots, turns = {k: [] for k in range(-1, last + 1)}, {}
        for key, (chain, oa, ob, ra, rb) in chains.items():
            for i, (u, v) in enumerate(zip(chain, chain[1:])):
                if virtual(u) or virtual(v):continue
                k, lane = turn(chain, i, ra, rb, oa, ob)
                if lane not in slots[k]:slots[k].append(lane)
                # Which way each of the turn's two horizontal runs leaves the channel: a turn beside a frame's own
                # column has both runs on the side of that column.
                ways = ('L', 'R') if layer[u] != layer[v] else ('R', 'R') if i == 0 else ('L', 'L')
                turns.setdefault((k, lane), []).append((height(chain, i, oa, ob), height(chain, i + 1, oa, ob), *ways))
        widths = [max([size(n)[0] for n in col] + [BEND_W]) for col in columns]
        gaps = {k: max(LAYER_GAP, (len(s) + 1) * CHANNEL) if 0 <= k < last or s else 0 for k, s in slots.items()}
        left = [gaps[-1]]
        for k in range(last):left.append(left[k] + widths[k] + gaps[k])
        channel = {}
        for k, keys in slots.items():
            start = left[k] + widths[k] if k >= 0 else 0
            def order_key(key):
                ends = turns[k, key];begin, finish = mean([e[0] for e in ends]), mean([e[1] for e in ends])
                # Lines going up turn nearest their column, lines going down farthest, so their turns do not cross.
                return (0, begin) if finish < begin else (1, begin) if finish == begin else (2, -begin)
            def cost(p, q):
                # p turns left of q: a run of p's going right may cross q's turn, a run of q's going left may cross
                # p's turn, and the two would run together at the same height.
                found = 0
                for bp, fp, *wp in turns[k, p]:
                    for bq, fq, *wq in turns[k, q]:
                        right = [h for h, w in zip((bp, fp), wp) if w == 'R'];left = [h for h, w in zip((bq, fq), wq) if w == 'L']
                        found += sum(min(bq, fq) < h < max(bq, fq) for h in right) + sum(min(bp, fp) < h < max(bp, fp) for h in left)
                        found += 3 * sum(h in left for h in right)
                return found
            # Starting from that order, move single channels to where they meet the fewest conflicts until none moves.
            conflict = {(p, q): cost(p, q) for p in keys for q in keys if p != q}
            lanes = sorted(keys, key=order_key);better = True
            while better:
                better = False
                for lane in list(lanes):
                    rest = [x for x in lanes if x != lane];score = sum(conflict[lane, x] for x in rest);scores = [score]
                    for x in rest:score += conflict[x, lane] - conflict[lane, x];scores.append(score)
                    here, best = lanes.index(lane), min(range(len(scores)), key=lambda i:(scores[i], i))
                    if scores[best] < scores[here]:lanes, better = rest[:best] + [lane] + rest[best:], True
            for i, key in enumerate(lanes):channel[k, key] = start + (i + 1) * gaps[k] // (len(keys) + 1)
        position = {n: (left[layer[n]] + (widths[layer[n]] - size(n)[0]) // 2, y[n]) for col in columns for n in col if not isinstance(n, tuple)}
        routes, ends = {}, {}
        for key, (chain, oa, ob, ra, rb) in chains.items():
            points = []
            for i, (u, v) in enumerate(zip(chain, chain[1:])):
                yu, yv = height(chain, i, oa, ob), height(chain, i + 1, oa, ob)
                # A line travelling right to left keeps its turn even when straight, so that its height is drawn.
                if not virtual(u) and not virtual(v) and (yu != yv or layer[u] == layer[v] or ra and ra[0] == 'back'):
                    x = channel[turn(chain, i, ra, rb, oa, ob)];points += [(x, yu), (x, yv)]
            routes[key] = points
            if virtual(chain[0]):ends[key, 'W'] = height(chain, 0, oa, ob)
            if virtual(chain[-1]):ends[key, 'E'] = height(chain, len(chain) - 1, oa, ob)
        width = left[-1] + widths[-1] + gaps[last]
        extent = (width, max(y[n] + size(n)[1] for col in columns for n in col))
        # The crossings of the lines as drawn, from the side of the item or box where each starts to where it ends.
        drawn = []
        for key, (chain, oa, ob, ra, rb) in chains.items():
            a, b = chain[0], chain[-1]
            path = [(0 if virtual(a) else position[a][0] + sizes[a][0], height(chain, 0, oa, ob)), *routes[key],
                    (width if virtual(b) else position[b][0], height(chain, len(chain) - 1, oa, ob))]
            drawn.append(list(zip(path, path[1:])))
        def cross(s, t):
            if s[0][1] == s[1][1] and t[0][0] == t[1][0]:s, t = t, s
            if not (s[0][0] == s[1][0] and t[0][1] == t[1][1]):return False
            return min(t[0][0], t[1][0]) < s[0][0] < max(t[0][0], t[1][0]) and min(s[0][1], s[1][1]) < t[0][1] < max(s[0][1], s[1][1])
        crossed = sum(cross(s, t) for i, p in enumerate(drawn) for q in drawn[i + 1:] for s in p for t in q)
        return crossed, (position, routes, ends, extent)
    tried = [route(shifted(0))]
    if any(ra and ra[0] == 'back' and (ra[2] or rb[2]) for _, _, _, ra, rb in chains.values()):tried += [route(shifted(1)), route(shifted(-1))]
    return min(tried, key=lambda x:x[0])[1]


def arrange(nodes, lines, sizes, hints, leaves=()):
    """Layered placement of one connected group of items: columns follow the lines from left to right.

    lines are (key, a, b, oa, ob, ra, rb, sa, sb, reverse): the items a and b at the ends of a chain that
    runs left to right ('W' or 'E' for the box's left or right side), the heights inside them where the line
    ends, what the ends are (lines from one end share their channels and bends), the sides of a and b the
    line meets when they are frames, and whether the line travels the chain from b to a. hints gives, for a
    line crossing the box's side, the height of its far end in a previous layout, so that lines cross the side
    in the order of where they go. leaves are the items that are icons. Returns item positions, each line's
    bend points, where lines cross the box's sides, and the group's size.
    """
    pairs = []
    for _, a, b, *_ in lines:
        if a in sizes and b in sizes and (a, b) not in pairs:pairs.append((a, b))
    west, east = {b for _, a, b, *_ in lines if a == 'W'}, {a for _, a, b, *_ in lines if b == 'E'}
    succ, indegree = {n: [] for n in nodes}, {n: 0 for n in nodes}
    for a, b in pairs:succ[a].append(b);indegree[b] += 1
    # A line that closes a cycle runs back through the columns it spans. Cycles are entered from where lines
    # start, so the first steps of a loop stay forward.
    state, back = {}, set()
    def visit(n):
        state[n] = 1
        for m in succ[n]:
            if state.get(m) == 1:back.add((n, m))
            elif m not in state:visit(m)
        state[n] = 2
    for n in [n for n in nodes if not indegree[n]] + [n for n in nodes if n in west] + nodes:
        if n not in state:visit(n)
    preds, succs = {n: [] for n in nodes}, {n: [] for n in nodes}
    for a, b in pairs:
        if (a, b) not in back:succs[a].append(b);preds[b].append(a)
    order, waiting = [], {n: len(preds[n]) for n in nodes}
    ready = [n for n in nodes if not waiting[n]]
    while ready:
        n = ready.pop(0);order.append(n)
        for m in succs[n]:
            waiting[m] -= 1
            if not waiting[m]:ready.append(m)
    layer = {}
    for n in order:layer[n] = max((layer[p] + 1 for p in preds[n]), default=0)
    last = max(layer.values())
    # Starts sit just before their first target, and items that only lead out of the box sit last.
    for n in reversed(order):
        if not preds[n] and succs[n] and n not in west:layer[n] = min(layer[m] for m in succs[n]) - 1
        elif not succs[n] and n in east:layer[n] = last
    # In a group more than twice as tall as wide, a column taller than FOLD_H folds into several side by side,
    # keeping items with the same source together; folding costs crossings, so only lopsided groups fold.
    def extent():
        cols = [[n for n in nodes if layer[n] == k] for k in range(last + 1)]
        return (sum(max([sizes[n][0] for n in col] + [BEND_W]) + LAYER_GAP for col in cols),
                max(sum(sizes[n][1] + ROW_GAP for n in col) for col in cols))
    wide, tall = extent()
    rank, k, folded = {n: i for i, n in enumerate(order)}, 0, set()
    while tall > 2 * wide and k <= last:
        col = sorted((n for n in nodes if layer[n] == k), key=lambda n:(min((rank[p] for p in preds[n]), default=-1), n))
        parts = min(len(col), -(-(sum(sizes[n][1] for n in col) + ROW_GAP * (len(col) - 1)) // FOLD_H)) if col else 1
        if parts > 1:
            share = -(-len(col) // parts)
            for n in nodes:
                if layer[n] > k:layer[n] += parts - 1
            for j, n in enumerate(col):layer[n] = k + j // share
            folded = {f + (parts - 1 if f > k else 0) for f in folded} | set(range(k, k + parts));last += parts - 1
        k += max(parts, 1)
    # In a group more than three times as wide as tall, columns wider than WRAP_W in all wrap into bands placed
    # one below another.
    widths = [max([sizes[n][0] for n in nodes if layer[n] == k] + [BEND_W]) for k in range(last + 1)]
    wide, tall = extent();bands, start, run = [], 0, 0
    for k in range(last + 1):
        if k > start and run + widths[k] > WRAP_W and wide > 3 * tall:bands.append((start, k - 1));start, run = k, 0
        run += widths[k] + LAYER_GAP
    bands.append((start, last))
    band = {k: i for i, (s, e) in enumerate(bands) for k in range(s, e + 1)}
    # A line that passes a column goes through a bend reserved in it, so it never runs through an item; in
    # folded columns, lines from one end share their bends. A line crossing the box's side does so in the band
    # of its item.
    chains, flipped = {}, set()
    for key, a, b, oa, ob, ra, rb, sa, sb, reverse in lines:
        if (a, b) in back:a, b, oa, ob, ra, rb, sa, sb, reverse = b, a, ob, oa, rb, ra, sb, sa, not reverse
        # A line travelling right to left turns in channels of its own and meets an icon off its middle (see
        # place), so it never runs on top of the lines leaving or entering the icon the other way.
        # An icon whose line crosses the box's side already has its height from layout.
        if reverse:flipped.add(key);ra, rb = ('back', ra, a in leaves and b != 'E'), ('back', rb, b in leaves and a != 'W')
        # A frame whose side faces away from the line is passed in its own column through a bend first.
        first = bands[band[layer[b]]][0] if a == 'W' else layer[a] + (sa != 'W')
        end = bands[band[layer[a]]][1] + 1 if b == 'E' else layer[b] + (sb == 'E')
        share = ('from', a, ra) if a != 'W' and not reverse else ('only', key)
        chains[key] = ([('W', key) if a == 'W' else a] + [('bend', share if k in folded else ('only', key), k) for k in range(first, end)]
                       + [('E', key) if b == 'E' else b], oa, ob, ra, rb)
    columns = [[n for n in nodes if layer[n] == k] for k in range(last + 1)]
    for chain, *_ in chains.values():
        for n in chain:
            if isinstance(n, tuple) and n[0] == 'bend' and n not in columns[n[2]]:columns[n[2]].append(n)
    for k, col in enumerate(columns):
        for n in col:layer[n] = k
    position, routes, ports, ends, placed = {}, {key: [] for key in chains}, {}, {}, []
    for i, (s, e) in enumerate(bands):
        mine, local = {}, {}
        for key, (chain, oa, ob, ra, rb) in chains.items():
            inside = [n for n in chain if not virtual(n) and s <= layer[n] <= e]
            if not inside:continue
            mine[key] = (([] if chain[0] in inside else [('W', key)]) + inside + ([] if chain[-1] in inside else [('E', key)]), oa, ob, ra, rb)
            # A line wrapping in from the band above is ordered by where it left that band.
            local[key] = ends.get((key, 'E', i - 1), hints.get(key))
        found = place(columns[s:e + 1], mine, sizes, local, {k - s for k in folded if s <= k <= e})
        placed.append((found, mine))
        for key, side in found[2]:ends[key, side, i] = found[2][key, side]
    # Bands stack with a corridor between them; a line wrapping to the next band leaves its band to the
    # right, runs left along the corridor and enters the next band from the left.
    wraps = [[key for key in chains if (key, 'E', i) in ends and (key, 'W', i + 1) in ends] for i in range(len(bands) - 1)]
    lead = (max([len(w) for w in wraps] + [0]) + 1) * CHANNEL if len(bands) > 1 else 0
    top, width = [0], 0
    for i, (found, mine) in enumerate(placed):
        w, h = found[3];width = max(width, lead + w + lead)
        if i < len(wraps):top.append(top[i] + h + (len(wraps[i]) + 1) * CHANNEL)
    for i, (found, mine) in enumerate(placed):
        dx, dy = lead, top[i]
        for n, (x, y) in found[0].items():position[n] = (x + dx, y + dy)
        for key in mine:
            routes[key] += [(x + dx, y + dy) for x, y in found[1][key]]
            if i < len(wraps) and key in wraps[i]:
                down = sorted(wraps[i], key=lambda k:(ends[k, 'E', i], ends[k, 'W', i + 1]));j, n = down.index(key), len(down)
                bottom = top[i] + found[3][1];right = dx + found[3][0]
                routes[key] += [(right + (n - j) * CHANNEL, ends[key, 'E', i] + dy), (right + (n - j) * CHANNEL, bottom + (n - j) * CHANNEL),
                                (lead - (j + 1) * CHANNEL, bottom + (n - j) * CHANNEL), (lead - (j + 1) * CHANNEL, ends[key, 'W', i + 1] + top[i + 1])]
        for key, side in found[2]:
            chain = chains[key][0]
            if virtual(chain[0] if side == 'W' else chain[-1]):ports[key] = side, found[2][key, side] + dy
    for key in flipped:routes[key] = routes[key][::-1]
    height = top[-1] + placed[-1][0][3][1]
    return position, routes, ports, (width if len(bands) > 1 else placed[0][0][3][0], height)


def anchor(item, rid, way):
    """Where a line to ('in') or from ('out') the resource meets the item: the frame side it crosses ('W', 'E',
    or None for an icon or the frame itself), the height, and the end the line has there, which lines from
    the same end share their channels and bends by."""
    if item.kind == 'leaf':return None, ICON // 2, ('rid', item.rid)
    if rid == item.rid:return None, item.h // 2, ('rid', rid)
    return item.ports[way, rid]


def layout(box, lines, far):
    """Lay out a box: connected items in left-to-right columns, then the items without lines in rows below."""
    box.members, box.routes, box.ports, box.keys, box.caption = {box.rid} if box.rid else set(), {}, {}, {}, None
    for item in box.items:
        if item.kind not in ('leaf', 'tag'):layout(item, lines, far)
        box.members |= item.members
    box.where = where = {r: i for i, item in enumerate(box.items) for r in item.members}
    chains, wired, sides, beyond = {}, set(), {}, {}
    for s, t in lines:
        a, b = where.get(s), where.get(t)
        wired.update(x for x in (a, b) if x is not None)
        # A line to this frame itself, or one that stays inside a single item, is not routed here.
        if (a is None and b is None) or a == b or (a is None and s in box.members) or (b is None and t in box.members):continue
        if a is not None and b is not None:
            (sa, oa, ea), (sb, ob, eb) = anchor(box.items[a], s, 'out'), anchor(box.items[b], t, 'in')
            key = box.keys['line', s, t] = ('line', ea, eb);chains[key] = (key, a, b, oa, ob, ea, eb, sa, sb, False)
        elif b is None:
            side, offset, end = anchor(box.items[a], s, 'out');key = box.keys['out', s] = ('out', end)
            sides[key] = (a, offset, end, side);beyond.setdefault(key, []).append(t);chains.setdefault(key, None)
        else:
            side, offset, end = anchor(box.items[b], t, 'in');key = box.keys['in', t] = ('in', end)
            sides[key] = (b, offset, end, side);beyond.setdefault(key, []).append(s);chains.setdefault(key, None)
    # A line crossing this box's side crosses the side that faces its far end in the previous layout, in
    # the order of the far ends' heights.
    hints = {}
    for key, (i, offset, end, side) in sides.items():
        westward = None
        if far:
            hints[key] = sum(far[x][1] for x in beyond[key]) / len(beyond[key])
            westward = sum(far[x][0] for x in beyond[key]) / len(beyond[key]) < box.cx
            # Such a line travelling right to left meets an icon off its middle, on one side for both its ends:
            # above when it climbs from left to right (see place).
            if box.items[i].kind == 'leaf' and westward == (key[0] == 'out'):
                here = far[box.items[i].rid][1];left, right = (hints[key], here) if westward else (here, hints[key])
                offset += -BACK if left > right else BACK
        if key[0] == 'out':
            chains[key] = (key, 'W', i, None, offset, None, end, None, side, True) if westward else (key, i, 'E', offset, None, end, None, side, None, False)
        else:
            chains[key] = (key, i, 'E', offset, None, end, None, side, None, True) if westward is False else (key, 'W', i, None, offset, None, end, None, side, False)
    group = list(range(len(box.items)))
    def find(i):
        while group[i] != i:i = group[i]
        return i
    for _, a, b, *_ in chains.values():
        if a not in ('W', 'E') and b not in ('W', 'E'):group[max(find(a), find(b))] = min(find(a), find(b))
    components = {}
    for i in sorted(wired):components.setdefault(find(i), []).append(i)
    sizes = {i: (item.w, item.h) for i, item in enumerate(box.items)}
    outer = {c[2] for c in chains.values() if c[1] == 'W'} | {c[1] for c in chains.values() if c[2] == 'E'}
    stacked, shelved, sided = [], [], {}
    # Groups with lines crossing the box's sides are placed together, so that small ones fill the columns of
    # large ones instead of stacking below them.
    outward = sorted(i for nodes in components.values() if outer & set(nodes) for i in nodes)
    for nodes in ([outward] if outward else []) + [nodes for nodes in components.values() if not outer & set(nodes)]:
        found = arrange(nodes, [c for c in chains.values() if c[1] in nodes or c[2] in nodes], {i: sizes[i] for i in nodes}, hints,
                        {i for i in nodes if box.items[i].kind == 'leaf'})
        (stacked if outer & set(nodes) else shelved).append(found)
    def put(found, x, y):
        position, routes, ports, size = found
        for i, (px, py) in position.items():box.items[i].x, box.items[i].y = PAD + x + px, y + py
        for key, points in routes.items():box.routes[key] = [(PAD + x + px, y + py) for px, py in points]
        for key, (side, py) in ports.items():sided[key] = side, y + py
    # The groups with lines crossing the box's sides, placed together, stand at the top left, so those lines run
    # clear to the sides; groups without such lines fill rows below them.
    y, width = HEAD, 0
    for found in stacked:put(found, 0, y);y += found[3][1] + GAP;width = max(width, found[3][0])
    limit, x, row = max([width, ROW_ICONS * CELL_W] + [found[3][0] for found in shelved]), 0, 0
    for found in shelved:
        w, h = found[3]
        if x and x + w > limit:y += row + GAP;x = row = 0
        put(found, x, y);x += w + GAP;row = max(row, h);width = max(width, x - GAP)
    if shelved:y += row + GAP
    # A frame gathering resources that share one line stands in a column of the flow, so it stays narrow.
    limit = max(width, (FAN_ICONS if box.kind == 'group' else ROW_ICONS) * CELL_W)
    def rows(items, gap):
        nonlocal y, width
        x = row = 0
        for item in items:
            if x and x + item.w > limit:y += row + ROW_GAP;x = row = 0
            item.x, item.y = PAD + x, y;x += item.w + gap(item);row = max(row, item.h);width = max(width, x - gap(item))
        y += row + GAP
    # Placement tags come first, in a row of their own; then the items without lines under their caption.
    tags = [item for item in box.items if item.kind == 'tag']
    rest = sorted((item for i, item in enumerate(box.items) if i not in wired and item.kind != 'tag'), key=lambda item:item.rank)
    if tags:rows(tags, lambda item:ROW_GAP)
    if rest:
        if wired:box.caption = y;y += CAPTION_H
        rows(rest, lambda item:0 if item.kind == 'leaf' else GAP)
    if not box.items:box.w, box.h = max(MIN_W, box.label_w), EMPTY_H
    else:box.w, box.h = max(width + 2 * PAD, MIN_W, box.label_w), y - GAP + PAD
    for way_rid, key in box.keys.items():
        if way_rid[0] != 'line':box.ports[way_rid] = (*sided[key], key[1])


def render_drawio(document):
    """The draw.io file of one page: the whole environment."""
    env = next(e for e in document.design.environments if e.id == document.environment_id)
    root = ET.Element('mxfile', host='aws-design-sheet')
    root.append(page(document, 'architecture', f'{env.name}（{env.id}）'))
    ET.indent(root)
    return ET.tostring(root, encoding='unicode') + '\n'


def render_pages(document, others=()):
    """The draw.io file of the environment: the whole environment first, then, when there are two or more, a page
    for each declared account and each region with only the resources placed there, and a whole page for each
    other environment's document in `others`. Cells of the later pages carry a page prefix, so that an ID names one
    cell in the file."""
    spec = document.design;env = next(e for e in spec.environments if e.id == document.environment_id)
    root = ET.Element('mxfile', host='aws-design-sheet')
    root.append(page(document, 'architecture', f'{env.name}（{env.id}）'))
    pages = []
    accounts = {a.id: a for a in getattr(spec, 'accounts', None) or []}
    placed = getattr(document, 'resource_accounts', None) or {}
    held = sorted({placed.get(r.id) for r in spec.resources}, key=lambda a:(a is None, a or ''))
    if len(held) > 1:
        for a in held:
            name = f'{accounts[a].name}（{a}）' if a else 'アカウント未決定'
            pages.append((f'account-{a or "undecided"}', f'アカウント：{name}', {r.id for r in spec.resources if placed.get(r.id) == a},
                          f'このページはアカウント「{name}」に置いたリソースだけを描きます。'))
    regional = {r.id: document.resource_regions.get(r.id, env.region) for r in spec.resources if r.type.split('::')[1] not in GLOBAL}
    if len(set(regional.values())) > 1:
        for name in sorted(set(regional.values()), key=lambda x:(x != env.region, x)):
            pages.append((f'region-{name}', f'リージョン：{name}', {r for r, at in regional.items() if at == name},
                          f'このページはリージョン {name} に置いたリソースだけを描きます（グローバルなサービスを除く）。'))
    for ident, title, keep, scope in pages:root.append(prefixed(page(document, ident, title, keep, scope), ident))
    for other in others:
        there = next(e for e in other.design.environments if e.id == other.environment_id)
        ident = f'environment-{there.id}'
        root.append(prefixed(page(other, ident, f'環境：{there.name}（{there.id}）'), ident))
    ET.indent(root)
    return ET.tostring(root, encoding='unicode') + '\n'


def prefixed(diagram, prefix):
    """The page with its cell IDs, and the parents, sources and targets naming them, prefixed."""
    for cell in diagram.iter('mxCell'):
        for key in ('id', 'parent', 'source', 'target'):
            if cell.get(key) not in (None, '0', '1'):cell.set(key, f'{prefix}:{cell.get(key)}')
    return diagram


def page(document, ident, title, keep=None, scope=''):
    """One page: the environment, or with `keep` only those resources, the actors their connections reach and the
    lines among them."""
    spec = document.design;env = next(e for e in spec.environments if e.id == document.environment_id)
    items = document.items
    if keep is not None:
        ends = {e for c in spec.connections if c.source in keep or c.target in keep for e in (c.source, c.target)}
        kept = [a for a in getattr(spec, 'actors', None) or [] if a.id in ends]
        spec = spec.model_copy(update={'resources': [r for r in spec.resources if r.id in keep], 'actors': kept,
                                       'connections': [c for c in spec.connections
                                                       if all(e in keep or e in {a.id for a in kept} for e in (c.source, c.target))]})
        items = [i for i in items if i.resource_id in keep]
    resources = {r.id: r for r in spec.resources};types = {r.id: r.type for r in spec.resources}
    refs = {r.id: [] for r in spec.resources};literal, undecided = {}, set()
    # Actors hold no settings: a type of their own kind, no references, and a name like a resource's.
    actors = {a.id: a for a in getattr(spec, 'actors', None) or []}
    names = {**{r.id: r.name for r in spec.resources}, **{a.id: a.name for a in actors.values()}}
    for a in actors.values():types[a.id] = 'ACTOR::' + a.kind;refs[a.id] = []
    for item in items:
        # On a page of some resources, references to the others leave the picture.
        refs[item.resource_id] += [x for x in references(item.expected) if x in resources]
        if item.expected.status == 'DECIDED' and item.expected.mode == 'LITERAL':literal[item.resource_id, item.name] = item.expected.value
        if item.expected.status == 'UNDECIDED':undecided.add((item.resource_id, item.name))
    def linked(rid, kind):return [x for x in refs[rid] if types[x] == kind]
    def vpc_of(rid):
        found = linked(rid, VPC);return found[0] if len(found) == 1 else None
    attached = {}
    for rid, kind in types.items():
        if kind == ATTACHMENT and len(linked(rid, VPC)) == 1:
            for x in refs[rid]:attached.setdefault(x, set()).add(linked(rid, VPC)[0])
    def subnets_of(rid):
        return {s for x in refs[rid] for s in ([x] if types[x] == SUBNET else linked(x, SUBNET) if types[x].endswith('SubnetGroup') else [])}
    def container(rid):
        subnets, vpcs = subnets_of(rid), set(attached.get(rid, ()))
        for x in refs[rid]:
            if types[x] == VPC:vpcs.add(x)
            elif types[x] == SECURITY_GROUP:vpcs.update(linked(x, VPC))
        if len(subnets) == 1 and not vpcs - {vpc_of(next(iter(subnets)))}:return next(iter(subnets))
        owners = vpcs | {vpc_of(s) for s in subnets}
        if len(owners) == 1 and None not in owners:return next(iter(owners))
        # A database instance that names nothing of its own network sits where the one cluster it names sits.
        cluster = linked(rid, 'AWS::RDS::DBCluster') if types[rid] == 'AWS::RDS::DBInstance' and not owners else []
        return container(cluster[0]) if len(cluster) == 1 else None
    def zone_of(subnet):
        found = literal.get((subnet, 'AvailabilityZone')) or literal.get((subnet, 'AvailabilityZoneId'))
        return found if isinstance(found, str) and found else None
    connected = {x for c in spec.connections for x in (c.source, c.target)}
    drawn = [r.id for r in spec.resources if r.type in (VPC, SUBNET) or r.type in ICONS or r.id in connected]
    omitted = [r.id for r in spec.resources if r.id not in set(drawn)]
    drawn += list(actors)
    # A setting naming another drawn resource is drawn as a reference line, unless a declared connection joins
    # the two, the frames already show it, the target is a key, log group or role that many resources share, or
    # the setting names what is watched or where logs go.
    joined, shown = {(c.source, c.target) for c in spec.connections}, set(drawn)
    derived = []
    for item in items:
        for path, target in leaves(item.expected):
            pair = (item.resource_id, target)
            if (target in shown and item.resource_id in shown and target != item.resource_id and pair not in joined
                    and pair[::-1] not in joined and types[target] not in PLACED | SHARED and not types[target].endswith('SubnetGroup')
                    and (types[item.resource_id], item.name) not in WATCHED and 'Logging' not in path):
                joined.add(pair);derived.append(Reference(*pair, item.name))
    # Resources left off the picture that name one another form groups; a group naming two drawn resources joins
    # them: a listener its load balancer and certificate, a domain its user pool and certificate. A group naming
    # subnets is a route table with its associations and routes: each subnet leads to where the routes go.
    hidden = [r for r in omitted if types[r] not in PLACED | SHARED and not types[r].endswith('SubnetGroup')]
    group = {r: r for r in hidden}
    def root_of(r):
        while group[r] != r:r = group[r]
        return r
    for r in hidden:
        for x in refs[r]:
            if x in group:group[root_of(x)] = root_of(r)
    def ends(x):return x in shown and types[x] not in {VPC, SECURITY_GROUP} | SHARED and not types[x].endswith('SubnetGroup')
    # The environment's effective settings, in the order the input writes them, so that a listener's load balancer
    # comes before its certificate.
    effective = {}
    for item in items:effective.setdefault(item.resource_id, []).append(item)
    def written(m):
        order = list(resources[m].settings)
        return sorted(effective.get(m, []), key=lambda i:order.index(i.name) if i.name in order else len(order))
    public, private = set(), set()
    for head in dict.fromkeys(root_of(r) for r in hidden):
        members = [r for r in hidden if root_of(r) == head]
        named = list(dict.fromkeys(x for m in members for i in written(m) for x in references(i.expected) if ends(x)))
        naming = [d for d in shown if d not in actors and ends(d) and any(x in members for x in refs[d])]
        subnets = [x for x in named if types[x] == SUBNET]
        if subnets:
            targets = [x for x in dict.fromkeys(named + naming) if types[x] != SUBNET]
            if any(types[x] in GATEWAYS for x in targets):public.update(subnets)
            elif any(types[m] == ROUTE_TABLE for m in members):private.update(subnets)
            pairs = [(s, t) for s in subnets for t in targets];via = 'ルート'
        else:
            pairs = [(named[0], t) for t in named[1:]] if named else []
            via = names[members[0]] + (f' ほか{len(members) - 1}件' if len(members) > 1 else '')
        for pair in pairs:
            if pair not in joined and pair[::-1] not in joined:joined.add(pair);derived.append(Reference(*pair, '', via))
    # FAN or more resources of one type in one region, whose only line is the same setting naming the same target,
    # sit together in a dashed frame from which one line leaves: a row of alarms sends one line to its topic.
    count, fans = Counter(x for c in [*spec.connections, *derived] for x in (c.source, c.target)), {}
    # With declared accounts, each account is a frame inside AWS Cloud holding its regions and global services.
    placement = getattr(document, 'resource_accounts', None) or {}
    framed = any(r in placement for r in resources)
    def account_of(rid):
        if rid in actors:return actors[rid].account or env.account
        return placement.get(rid)
    def home_of(rid):
        return (account_of(rid), 'cloud' if types[rid].split('::')[1] in GLOBAL else document.resource_regions.get(rid, env.region))
    for r in derived:
        if count[r.source] == 1 and container(r.source) is None:fans.setdefault((r.target, r.name, types[r.source], home_of(r.source)), []).append(r)
    groups = {f'{refs[0].source}.group': (refs, key) for key, refs in fans.items() if len(refs) >= FAN}
    grouped = {r.source: gid for gid, (refs, _) in groups.items() for r in refs}
    derived = [r for r in derived if r.source not in grouped] + [Reference(gid, target, name) for gid, (_, (target, name, *_)) in groups.items()]

    def text(value):return html.escape(str(value), quote=False)
    def frame(ident, kind, name, rid=None, rank=()):
        box = Box(ident, kind, text(name), rid, rank);box.label_w = units(name) * 7 + 40;return box
    # A frame shows a decided literal value, or says the value is undecided.
    def value(rid, name, word):return literal.get((rid, name)) or (f'{word} 未決定' if (rid, name) in undecided else None)
    def label(rid, *details):
        extra = '・'.join(str(d) for d in details if isinstance(d, str) and d)
        return names[rid] + (f'（{extra}）' if extra else '')
    def icon(rid):
        if rid in actors:return ACTOR_ICONS[actors[rid].kind]
        name, color = ICONS.get(types[rid]) or (GENERIC, SERVICE_COLORS.get(types[rid].split('::')[1], '#232F3E'))
        if types[rid] == 'AWS::ElasticLoadBalancingV2::LoadBalancer' and literal.get((rid, 'Type')) in LOAD_BALANCERS:
            name = LOAD_BALANCERS[literal[rid, 'Type']]
        return name, color
    cloud = frame('cloud', 'cloud', 'AWS Cloud');boxes = {};regions = {};parent = {};frames = {}
    declared = {a.id: a for a in getattr(spec, 'accounts', None) or []}
    def account(a):
        if a not in frames:
            name = (f'{declared[a].name}（{a}' + (f'・{declared[a].account_id}' if declared[a].account_id else '') + '）') if a else 'アカウント未決定'
            frames[a] = frame(f'account-{a or "undecided"}', 'account', name)
        return frames[a]
    def outer_of(a):return account(a) if framed else cloud
    def region(name, a=None):
        key = (a if framed else None, name)
        if key not in regions:regions[key] = frame('region-' + (f'{a or "undecided"}-' if framed else '') + name, 'region', name)
        return regions[key]
    # Without accounts the environment's region frame is drawn even when empty, as it always was.
    if not framed:region(env.region)
    # Resource cells get a prefix so that a resource ID never collides with a frame, line or note.
    def cell(rid):return 'resource-' + rid
    index = {rid: i for i, rid in enumerate(drawn)}
    for rid in drawn:
        if types[rid] == VPC:boxes[rid] = frame(cell(rid), 'vpc', label(rid, value(rid, 'CidrBlock', 'CIDR')), rid, (1, '', '', index[rid]))
        elif types[rid] == SUBNET:
            kind = 'subnet-public' if rid in public else 'subnet-private' if rid in private else 'subnet'
            boxes[rid] = frame(cell(rid), kind, label(rid, value(rid, 'CidrBlock', 'CIDR'), value(rid, 'AvailabilityZone', 'AZ')),
                               rid, (1, '', '', index[rid]))
    zones, fanned = {}, {}
    # People and outside systems stand beside the AWS Cloud frame, in a frame that draws nothing.
    outside = [a for a in actors.values() if a.kind != 'AWS_SERVICE']
    canvas = frame('canvas', 'canvas', '') if outside else None
    if canvas:canvas.items.append(cloud);parent['cloud'] = 'canvas'
    for rid in drawn:
        if rid in actors:
            home = canvas if actors[rid].kind != 'AWS_SERVICE' else region(actors[rid].region or env.region, account_of(rid))
        elif types[rid] == VPC:home = region(document.resource_regions.get(rid, env.region), account_of(rid))
        elif types[rid] == SUBNET:
            owner = vpc_of(rid)
            home = boxes[owner] if owner in boxes else region(document.resource_regions.get(rid, env.region), account_of(rid))
            # Subnets whose availability zone is decided sit in a frame for that zone inside their VPC.
            if owner in boxes and zone_of(rid):
                if (owner, zone_of(rid)) not in zones:
                    zone = zones[owner, zone_of(rid)] = frame(f'zone-{owner}-{zone_of(rid)}', 'zone', zone_of(rid), None, (1, '', '', index[rid]))
                    home.items.append(zone);parent[zone.id] = home.id
                home = zones[owner, zone_of(rid)]
        elif rid in grouped:
            gid = grouped[rid];members, (_, name, kind, (owner, where)) = groups[gid]
            if gid not in fanned:
                outer = outer_of(owner) if where == 'cloud' else region(where, owner)
                fanned[gid] = frame(cell(gid), 'group', f"{' '.join(kind.split('::')[1:])} {len(members)}件（{name}）", gid, (1, '', '', index[rid]))
                outer.items.append(fanned[gid]);parent[fanned[gid].id] = outer.id
            home = fanned[gid]
        else:
            owner = container(rid)
            home = (boxes[owner] if owner in boxes else outer_of(account_of(rid)) if types[rid].split('::')[1] in GLOBAL
                    else region(document.resource_regions.get(rid, env.region), account_of(rid)))
        # Items without lines are listed by icon colour and type, so that alike resources sit together.
        home.items.append(boxes.get(rid) or Box(rid, 'leaf', '', rid, (0, icon(rid)[1], types[rid], index[rid])))
        parent[cell(rid)] = home.id
    # A resource placed in a VPC because it spans several of its subnets leaves a tag in each of them; a subnet
    # group is itself the list of its subnets and leaves none.
    for rid in drawn:
        owner = container(rid) if types[rid] not in (VPC, SUBNET) and not types[rid].endswith('SubnetGroup') else None
        spread = [s for s in drawn if s in subnets_of(rid)] if owner in boxes and types[owner] == VPC else []
        for s in spread if len(spread) > 1 else []:
            lines = wrap(names[rid]);name = lines[0] if len(lines) == 1 else lines[0][:-1] + '…'
            tag = Box(f'placement-{s}-{rid}', 'tag', text(name), None, (2, index[rid]));tag.of = rid
            tag.w, tag.h = units(name) * 6 + 20, TAG_H;boxes[s].items.append(tag)
    if framed:
        # The environment's account and region first, then the others by ID; an undecided account last.
        def first(key, own):return (key != own, key is None, key or '')
        for (a, name), box in sorted(regions.items(), key=lambda kv:(first(kv[0][0], env.account), first(kv[0][1], env.region))):
            box.rank = (1, '', '', -1) if name == env.region else ();account(a).items.append(box);parent[box.id] = account(a).id
        for i, a in enumerate(sorted(frames, key=lambda a:first(a, env.account))):
            frames[a].rank = (1, '', '', i - len(frames));cloud.items.append(frames[a]);parent[frames[a].id] = 'cloud'
    else:
        main = regions[None, env.region];main.rank = (1, '', '', -1)
        cloud.items += [main, *[regions[k] for k in sorted(regions, key=lambda k:k[1]) if k[1] != env.region]]
        for r in regions.values():parent[r.id] = 'cloud'

    def ancestors(ident):
        found, current = set(), parent.get(ident)
        while current in parent:found.add(current);current = parent[current]
        return found | ({current} if current else set())
    # A reference already shown by placing the resource inside its target adds no line.
    lines = [c for c in spec.connections if not (c.kind == 'REFERENCE' and cell(c.target) in ancestors(cell(c.source)))] + derived
    # A second layout lets each line cross a frame's side toward where the first layout put its far end.
    top = canvas or cloud
    pairs = [(c.source, c.target) for c in lines];layout(top, pairs, None);far = {}
    def measure(box, ox, oy):
        box.cx = ox + box.w // 2
        for item in box.items:
            x, y = ox + item.x, oy + item.y
            if item.kind != 'leaf':measure(item, x, y)
            if item.rid:far[item.rid] = (x + item.w // 2, y + (ICON // 2 if item.kind == 'leaf' else item.h // 2))
    measure(top, 0, 0);layout(top, pairs, far)

    diagram = ET.Element('diagram', id=ident, name=title)
    model = ET.SubElement(diagram, 'mxGraphModel', grid='1', gridSize='10', guides='1', tooltips='1', connect='1', arrows='1',
                          fold='1', page='0', pageScale='1', math='0', shadow='0')
    cells = ET.SubElement(model, 'root')
    ET.SubElement(cells, 'mxCell', id='0');ET.SubElement(cells, 'mxCell', id='1', parent='0')
    def vertex(ident, value, style, owner, x, y, w, h):
        cell = ET.SubElement(cells, 'mxCell', id=ident, value=value, style=style, vertex='1', parent=owner)
        ET.SubElement(cell, 'mxGeometry', {'x': str(x), 'y': str(y), 'width': str(w), 'height': str(h), 'as': 'geometry'})
    def icon_style(rid):
        name, color = icon(rid)
        if name.startswith('shape:'):return ICON_STYLE + f'fillColor={color};strokeColor=none;pointerEvents=1;shape=mxgraph.aws4.{name[6:]};'
        return ICON_STYLE + f'fillColor={color};strokeColor=#ffffff;shape=mxgraph.aws4.resourceIcon;resIcon=mxgraph.aws4.{name};'
    origin, shape = {}, {}
    def emit(box, owner, ox, oy):
        vertex(box.id, box.label, STYLES[box.kind], owner, box.x, box.y, box.w, box.h);origin[box.id] = (ox + box.x, oy + box.y)
        shape[box.id] = (*origin[box.id], box.w, box.h)
        if box.caption is not None:
            vertex('unconnected-' + box.id, '線のないリソース', CAPTION_STYLE, box.id, PAD, box.caption, 200, CAPTION_H)
        for item in box.items:
            if item.kind == 'tag':
                vertex(item.id, item.label, TAG_STYLE + f'strokeColor={icon(item.of)[1]};', box.id, item.x, item.y, item.w, item.h);continue
            if item.kind != 'leaf':emit(item, box.id, *origin[box.id]);continue
            name = '<br>'.join(text(line) for line in wrap(names[item.rid]))
            vertex(cell(item.rid), f'{name}<br><font style="font-size:10px" color="#545B64">{text(item.rid)}</font>',
                   icon_style(item.rid), box.id, item.x + (CELL_W - ICON) // 2, item.y, ICON, ICON)
            shape[cell(item.rid)] = (origin[box.id][0] + item.x + (CELL_W - ICON) // 2, origin[box.id][1] + item.y, ICON, ICON)
    emit(top, '1', 0, 0)
    def clip(rect, toward):
        # Where a line from the middle of the shape toward the point leaves the shape.
        x, y, w, h = rect;cx, cy = x + w / 2, y + h / 2;dx, dy = toward[0] - cx, toward[1] - cy;t = 1.0
        if dx:t = min(t, w / 2 / abs(dx))
        if dy:t = min(t, h / 2 / abs(dy))
        return cx + dx * t, cy + dy * t

    status = {'UNDECIDED': '未決定', 'NOT_APPLICABLE': '適用外'}
    def inward(item, rid):
        found = []
        while item.kind != 'leaf' and item.rid != rid:found.append(item);item = item.items[item.where[rid]]
        return found
    def placed(box, key):ox, oy = origin[box.id];return [(ox + x, oy + y) for x, y in box.routes.get(key, [])]
    labelled = []
    for c in lines:
        # A line leaves the frames around its source, crosses the innermost frame that holds both ends,
        # and enters the frames around its target, turning only in the gaps between columns.
        box = top
        while True:
            a, b = box.where.get(c.source), box.where.get(c.target)
            if a is None or a != b or box.items[a].kind == 'leaf':break
            box = box.items[a]
        points = []
        if a is not None and b is not None and a != b:
            for inner in reversed(inward(box.items[a], c.source)):points += placed(inner, inner.keys.get(('out', c.source)))
            points += placed(box, box.keys.get(('line', c.source, c.target)))
            for inner in inward(box.items[b], c.target):points += placed(inner, inner.keys.get(('in', c.target)))
        # A line meeting an icon below its middle leaves or enters it level, from the icon's side.
        for rid, at in ((c.source, 0), (c.target, -1)):
            x, y, w, h = shape[cell(rid)]
            if rid not in boxes and rid not in groups and points and points[at][1] != y + h / 2 and y <= points[at][1] <= y + h:
                points.insert(0 if at == 0 else len(points), (x + w if points[at][0] > x + w / 2 else x, points[at][1]))
        points = [p for i, p in enumerate(points) if not i or p != points[i - 1]]
        style ='html=1;endArrow=block;endFill=1;fontSize=10;labelBackgroundColor=#FFFFFF;'
        style += {'TRAFFIC': '', 'REFERENCE': 'dashed=1;', 'DEPENDENCY': 'strokeWidth=3;'}[c.kind]
        style += 'strokeColor=#232F3E;' if c.status == 'DECIDED' else 'strokeColor=#AAB7B8;fontColor=#879196;'
        words = ' '.join(x for x in (c.protocol, c.ports) if x) + (f'（{status[c.status]}）' if c.status in status else '')
        edge = ET.SubElement(cells, 'mxCell', id=('reference-' if isinstance(c, Reference) else 'connection-') + c.id,
                             value=text(words), style=style, edge='1', parent='1',
                             source=cell(c.source), target=cell(c.target))
        geometry = ET.SubElement(edge, 'mxGeometry', {'relative': '1', 'as': 'geometry'})
        ends = [shape[cell(c.source)], shape[cell(c.target)]];middle = [(x + w / 2, y + h / 2) for x, y, w, h in ends]
        labelled.append((geometry if words else None, [clip(ends[0], points[0] if points else middle[1]), *points,
                                                    clip(ends[1], points[-1] if points else middle[0])]))
        if points:
            array = ET.SubElement(geometry, 'Array', {'as': 'points'})
            for x, y in points:ET.SubElement(array, 'mxPoint', {'x': str(x), 'y': str(y)})

    # A label sits on the stretch nearest the target that no other line runs along, so it names one line.
    def free(segment, others):
        (x1, y1), (x2, y2) = segment;axis = 0 if y1 == y2 else 1 if x1 == x2 else None
        if axis is None:return [(0, 1)]
        lo, hi = sorted((segment[0][axis], segment[1][axis]));gaps = [(lo, hi)]
        for p, q in others:
            if (p[1 - axis] == q[1 - axis] == segment[0][1 - axis]):
                a, b = sorted((p[axis], q[axis]));gaps = [g for x, y in gaps for g in ((x, min(y, a)), (max(x, b), y)) if g[1] > g[0]]
        return [((x - lo) / (hi - lo), (y - lo) / (hi - lo)) for x, y in gaps] if hi > lo else []
    for k, (geometry, path) in enumerate(labelled):
        if geometry is None:continue
        others = [s for j, (g, p) in enumerate(labelled) if j != k for s in zip(p, p[1:])]
        steps = [abs(p[0] - q[0]) + abs(p[1] - q[1]) for p, q in zip(path, path[1:])];at = len(steps) - 1;where = 0.5
        for k in range(len(steps) - 1, -1, -1):
            spans = [s for s in free((path[k], path[k + 1]), others) if (s[1] - s[0]) * steps[k] >= LABEL_ROOM]
            if spans:at, where = k, sum(max(spans, key=lambda s:s[1] - s[0])) / 2;break
        if sum(steps):geometry.set('x', str(round(2 * (sum(steps[:at]) + steps[at] * where) / sum(steps) - 1, 3)))

    listed = '、'.join(f'{text(r)}（{text(types[r])}）' for r in omitted)
    note = [f'{text(spec.system.name)} の構成図（環境：{text(env.name)}）。設計入力から生成しました。修正は入力ファイルに行い、再生成してください。'
            + (text(scope) + 'ほかのリソースとの線は省いています。' if scope else ''),
            '線は宣言した接続と、設定が参照するリソースへの参照（点線）です。参照の線は、枠で示す VPC・サブネットと、枠への配置を決めるのに使うセキュリティグループ・サブネットグループ、'
            '多くのリソースが共通に参照する KMS キー・ロググループ・IAM ロールへのもの、アラームの監視対象やログの出力先を指すものを省きます。'
            '図に出さないリソース（リスナー、ドメイン、ルートテーブルなど）が図上の2つのリソースを参照するときは、その名前を「経由：」に添えた点線で結びます。'
            'サブネットからの「経由：ルート」の点線は、関連付けたルートテーブルの経路の行き先です。'
            f'同じ種類の{FAN}つ以上のリソースが同じ設定で同じ相手だけを参照するときは、点線の枠にまとめ、枠から1本の線で示します。'
            '実線は通信、点線は参照、太線は依存、灰色は未決定または適用外を示します。'
            '配置は自動で、接続をたどって左から右へ並べ、線は列の間で直角に曲げ、線のないリソースは各枠の下段に色と種類の順でまとめています。長い名前は図の上だけ省略しています。'
            '見せ方の調整は draw.io で行ってください。',
            'VPC・サブネットへの配置は、各リソースの設定が参照する VPC・サブネット・セキュリティグループ・サブネットグループと、VPC へのゲートウェイのアタッチだけから決めています。'
            'ネットワークを参照しない DB インスタンスは、参照する DB クラスターと同じ枠に置きます。'
            '複数のサブネットを参照するリソースは VPC の直下に置き、参照する各サブネットに点線の札で名前を示します。'
            'AZ の点線の枠は、サブネットの AZ が決定済みのときだけ描きます。'
            + ('アカウントの枠は、各リソースに宣言したアカウント（宣言がなければ環境のアカウント）で決めています。' if framed else '') +
            'インターネットゲートウェイへの経路を持つルートテーブルを関連付けたサブネットは緑（パブリック）、それ以外のルートテーブルを関連付けたサブネットは青（プライベート）、'
            'ルートテーブルの関連付けが入力にないサブネットは灰色で示します。'
            '外部の相手のうち、利用者・運用者・外部システムは AWS Cloud の枠の外に、入力でリソースとして扱えない AWS サービスはリージョンの枠の中に描きます。外部の相手は設定値を持ちません。'
            '到達性や設定の正しさを示す図ではありません。',
            f'図に出していないリソース：{listed}' if omitted else '図に出していないリソース：なし']
    width = max(top.w, 800);rows = sum(-(-units(line) * 6 // width) for line in note)
    vertex('note', '<br>'.join(note), NOTE_STYLE, '1', 0, top.h + 20, width, rows * 15 + 10)
    return diagram
