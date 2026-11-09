"""Service mentions: the AWS services the CURRENT documents name in their cells and drawings, against the design input.

The diagram coverage makes every drawing answer for itself, but a service named only in prose
or a table (an audit trail, a key, a notification topic, a secret store) reached the input only
if the author noticed it. This check reads every cell and drawing text of the CURRENT documents
of the approved source set, finds AWS service names with a fixed dictionary (official names and
their usual abbreviations, normalised to the CloudFormation types that realise them), and says
for each service whether the input holds it:

- IN_DESIGN: a resource of a matching type, or an AWS_SERVICE actor naming the service;
- CITED: not a resource, but a setting, resource, connection, actor, account or environment cites a
  cell or drawing that names it: the service is used through a setting (X-Ray tracing on a
  function, IAM database authentication on a cluster), and the author read that cell;
- NOTED: not modelled, but a requirement, operation, issue or decision of the input cites a cell
  or drawing that names it, so the input says in words why (out of scope, run by another team,
  not used, not an AWS service in that sentence);
- NOT_IN_DESIGN: none of these. The gate fails until the author models the service, writes such a
  note citing one of the listed cells, or opens a decision for people.

Role words (監査ログ, 暗号鍵, 通知) only suggest candidates: they are listed as hints and never
fail. The check reports service names, document IDs and cell or drawing IDs only, never cell text,
and it says nothing about whether a service is configured correctly.
"""
import re
import unicodedata
from collections import defaultdict

# (key, label, CloudFormation types that hold it, name patterns). A type ending in `::` or `*` is a prefix;
# otherwise it is exact. Patterns are matched case-sensitively unless they say (?i:...); abbreviations stay
# upper case so ordinary words (ram, config, batch) are not read as services.
SERVICES = (
    ('cloudwatch-logs', 'CloudWatch Logs', ('AWS::Logs::',), (r'(?i:cloud\s*watch\s*logs?)',)),
    ('eventbridge', 'EventBridge', ('AWS::Events::', 'AWS::Scheduler::', 'AWS::Pipes::'), (r'(?i:event\s*bridge)', r'(?i:cloud\s*watch\s*events)')),
    ('cloudwatch', 'CloudWatch', ('AWS::CloudWatch::', 'AWS::Logs::'), (r'(?i:cloud\s*watch)', 'クラウドウォッチ')),
    ('sns', 'SNS', ('AWS::SNS::',), ('SNS', r'(?i:simple\s+notification\s+service)')),
    ('sqs', 'SQS', ('AWS::SQS::',), ('SQS', r'(?i:simple\s+queue\s+service)')),
    ('ses', 'SES', ('AWS::SES::',), ('SES', r'(?i:simple\s+email\s+service)')),
    ('cloudtrail', 'CloudTrail', ('AWS::CloudTrail::',), (r'(?i:cloud\s*trail)',)),
    ('config', 'AWS Config', ('AWS::Config::',), (r'(?i:aws\s*config)',)),
    ('secretsmanager', 'Secrets Manager', ('AWS::SecretsManager::',), (r'(?i:secrets?\s*manager)',)),
    ('ssm', 'Systems Manager', ('AWS::SSM::',), (r'(?i:systems\s*manager)', 'SSM', r'(?i:parameter\s*store)', 'パラメータストア', r'(?i:session\s*manager)')),
    ('kms', 'KMS', ('AWS::KMS::',), ('KMS', r'(?i:key\s+management\s+service)')),
    ('iam-identity-center', 'IAM Identity Center', ('AWS::SSO::',), (r'(?i:iam\s*identity\s*center)', r'(?i:aws\s*sso)')),
    ('iam', 'IAM', ('AWS::IAM::',), ('IAM',)),
    ('acm-pca', 'Private CA', ('AWS::ACMPCA::',), (r'(?i:private\s*ca)', r'(?i:private\s+certificate\s+authority)', r'ACM\s*PCA')),
    ('acm', 'Certificate Manager', ('AWS::CertificateManager::',), ('ACM', r'(?i:certificate\s*manager)')),
    ('route53', 'Route 53', ('AWS::Route53::', 'AWS::Route53Resolver::'), (r'(?i:route\s*53)',)),
    ('cloudfront', 'CloudFront', ('AWS::CloudFront::',), (r'(?i:cloud\s*front)',)),
    ('waf', 'WAF', ('AWS::WAFv2::', 'AWS::WAF::', 'AWS::WAFRegional::'), ('WAF',)),
    ('shield', 'Shield', ('AWS::Shield::',), (r'(?i:aws\s*shield)', r'(?i:shield\s+advanced)')),
    ('apigateway', 'API Gateway', ('AWS::ApiGateway::', 'AWS::ApiGatewayV2::'), (r'(?i:api\s*gateway)', r'(?i:api)\s*ゲートウェイ')),
    ('elb', 'Elastic Load Balancing', ('AWS::ElasticLoadBalancingV2::', 'AWS::ElasticLoadBalancing::'),
     ('ALB', 'NLB', 'ELB', 'CLB', 'GWLB', r'(?i:elastic\s*load\s*balanc\w*)', r'(?i:application\s+load\s+balancer)', r'(?i:network\s+load\s+balancer)')),
    ('autoscaling', 'Auto Scaling', ('AWS::AutoScaling::', 'AWS::ApplicationAutoScaling::'), (r'(?i:auto\s*scaling)', 'オートスケーリング', 'ASG')),
    ('ec2', 'EC2', ('AWS::EC2::Instance', 'AWS::EC2::LaunchTemplate', 'AWS::EC2::Host', 'AWS::EC2::EC2Fleet', 'AWS::EC2::SpotFleet', 'AWS::AutoScaling::'), ('EC2',)),
    ('ebs', 'EBS', ('AWS::EC2::Volume', 'AWS::EC2::Instance', 'AWS::EC2::LaunchTemplate'), ('EBS',)),
    ('eip', 'Elastic IP', ('AWS::EC2::EIP',), (r'(?i:elastic\s*ip)', 'EIP')),
    ('vpc-endpoint', 'VPC Endpoint', ('AWS::EC2::VPCEndpoint*',), (r'VPC\s*(?i:end\s*points?)', r'VPC\s*エンドポイント', r'(?i:private\s*link)')),
    ('vpc-peering', 'VPC Peering', ('AWS::EC2::VPCPeeringConnection',), (r'VPC\s*(?i:peering)', r'VPC\s*ピアリング')),
    ('flow-logs', 'VPC Flow Logs', ('AWS::EC2::FlowLog',), (r'(?i:(?:vpc\s*)?flow\s*logs?)', r'(?:VPC\s*)?フローログ')),
    ('vpc', 'VPC', ('AWS::EC2::VPC',), ('VPC',)),
    ('subnet', 'Subnet', ('AWS::EC2::Subnet',), (r'(?i:subnets?)', 'サブネット')),
    ('security-group', 'Security Group', ('AWS::EC2::SecurityGroup',), (r'(?i:security\s*groups?)', 'セキュリティグループ')),
    ('nat-gateway', 'NAT Gateway', ('AWS::EC2::NatGateway',), (r'NAT\s*(?i:gateway)', r'NAT\s*ゲートウェイ', r'NAT\s*GW')),
    ('internet-gateway', 'Internet Gateway', ('AWS::EC2::InternetGateway',), (r'(?i:internet\s*gateway)', 'インターネットゲートウェイ', 'IGW')),
    ('transit-gateway', 'Transit Gateway', ('AWS::EC2::TransitGateway*',), (r'(?i:transit\s*gateway)', 'トランジットゲートウェイ', 'TGW')),
    ('client-vpn', 'Client VPN', ('AWS::EC2::ClientVpn*',), (r'(?i:client\s*vpn)',)),
    ('vpn', 'Site-to-Site VPN', ('AWS::EC2::VPNConnection', 'AWS::EC2::VPNGateway', 'AWS::EC2::CustomerGateway'),
     (r'(?i:site[\s-]*to[\s-]*site\s*vpn)', r'(?i:aws\s*vpn)', r'(?i:virtual\s*private\s*gateway)', 'VGW', '仮想プライベートゲートウェイ')),
    ('direct-connect', 'Direct Connect', ('AWS::DirectConnect::',), (r'(?i:direct\s*connect)',)),
    ('network-firewall', 'Network Firewall', ('AWS::NetworkFirewall::',), (r'(?i:network\s*firewall)',)),
    ('global-accelerator', 'Global Accelerator', ('AWS::GlobalAccelerator::',), (r'(?i:global\s*accelerator)',)),
    ('glacier', 'S3 Glacier', ('AWS::S3::', 'AWS::Glacier::'), (r'(?:S3\s*)?(?i:glacier)',)),
    ('s3', 'S3', ('AWS::S3::', 'AWS::S3Express::'), ('S3', r'(?i:simple\s+storage\s+service)')),
    ('efs', 'EFS', ('AWS::EFS::',), ('EFS', r'(?i:elastic\s*file\s*system)')),
    ('fsx', 'FSx', ('AWS::FSx::',), (r'(?i:fsx)',)),
    ('backup', 'AWS Backup', ('AWS::Backup::',), (r'(?i:aws\s*backup)',)),
    ('aurora', 'Aurora', ('AWS::RDS::DBCluster', 'AWS::RDS::DBInstance', 'AWS::RDS::GlobalCluster'), (r'(?i:aurora)',)),
    ('rds', 'RDS', ('AWS::RDS::',), ('RDS', r'(?i:relational\s+database\s+service)')),
    ('dynamodb', 'DynamoDB', ('AWS::DynamoDB::',), (r'(?i:dynamo\s*db)',)),
    ('elasticache', 'ElastiCache', ('AWS::ElastiCache::',), (r'(?i:elasti\s*cache)',)),
    ('memorydb', 'MemoryDB', ('AWS::MemoryDB::',), (r'(?i:memory\s*db)',)),
    ('redshift', 'Redshift', ('AWS::Redshift::', 'AWS::RedshiftServerless::'), (r'(?i:redshift)',)),
    ('opensearch', 'OpenSearch Service', ('AWS::OpenSearchService::', 'AWS::Elasticsearch::', 'AWS::OpenSearchServerless::'),
     (r'(?i:open\s*search)', r'(?i:elasticsearch\s*service)')),
    ('documentdb', 'DocumentDB', ('AWS::DocDB::',), (r'(?i:document\s*db)',)),
    ('neptune', 'Neptune', ('AWS::Neptune::',), (r'(?i:amazon\s*neptune)',)),
    ('lambda', 'Lambda', ('AWS::Lambda::', 'AWS::Serverless::Function'), (r'(?i:lambda)',)),
    ('fargate', 'Fargate', ('AWS::ECS::', 'AWS::EKS::'), (r'(?i:fargate)',)),
    ('ecs', 'ECS', ('AWS::ECS::',), ('ECS', r'(?i:elastic\s+container\s+service)')),
    ('eks', 'EKS', ('AWS::EKS::',), ('EKS', r'(?i:elastic\s+kubernetes\s+service)')),
    ('ecr', 'ECR', ('AWS::ECR::',), ('ECR', r'(?i:elastic\s+container\s+registry)')),
    ('app-runner', 'App Runner', ('AWS::AppRunner::',), (r'(?i:app\s*runner)',)),
    ('beanstalk', 'Elastic Beanstalk', ('AWS::ElasticBeanstalk::',), (r'(?i:elastic\s*beanstalk)',)),
    ('batch', 'AWS Batch', ('AWS::Batch::',), (r'(?i:aws\s*batch)',)),
    ('step-functions', 'Step Functions', ('AWS::StepFunctions::',), (r'(?i:step\s*functions?)',)),
    ('kinesis', 'Kinesis', ('AWS::Kinesis::', 'AWS::KinesisFirehose::', 'AWS::KinesisAnalyticsV2::', 'AWS::KinesisVideo::'), (r'(?i:kinesis)', r'(?i:firehose)')),
    ('msk', 'MSK', ('AWS::MSK::',), ('MSK', r'(?i:managed\s+streaming\s+for\s+(?:apache\s+)?kafka)')),
    ('mq', 'Amazon MQ', ('AWS::AmazonMQ::',), (r'(?i:amazon\s*mq)',)),
    ('appsync', 'AppSync', ('AWS::AppSync::',), (r'(?i:app\s*sync)',)),
    ('cognito', 'Cognito', ('AWS::Cognito::',), (r'(?i:cognito)',)),
    ('guardduty', 'GuardDuty', ('AWS::GuardDuty::',), (r'(?i:guard\s*duty)',)),
    ('securityhub', 'Security Hub', ('AWS::SecurityHub::',), (r'(?i:security\s*hub)',)),
    ('inspector', 'Inspector', ('AWS::InspectorV2::', 'AWS::Inspector::'), (r'(?i:amazon\s*inspector)', r'(?i:inspector\s*v2)')),
    ('macie', 'Macie', ('AWS::Macie::',), (r'(?i:macie)',)),
    ('detective', 'Detective', ('AWS::Detective::',), (r'(?i:amazon\s*detective)',)),
    ('firewall-manager', 'Firewall Manager', ('AWS::FMS::',), (r'(?i:firewall\s*manager)',)),
    ('organizations', 'Organizations', ('AWS::Organizations::',), (r'(?i:aws\s*organizations)', 'Organizations')),
    ('control-tower', 'Control Tower', ('AWS::ControlTower::',), (r'(?i:control\s*tower)',)),
    ('ram', 'Resource Access Manager', ('AWS::RAM::',), (r'(?i:resource\s*access\s*manager)',)),
    ('codepipeline', 'CodePipeline', ('AWS::CodePipeline::',), (r'(?i:code\s*pipeline)',)),
    ('codebuild', 'CodeBuild', ('AWS::CodeBuild::',), (r'(?i:code\s*build)',)),
    ('codedeploy', 'CodeDeploy', ('AWS::CodeDeploy::',), (r'(?i:code\s*deploy)',)),
    ('codecommit', 'CodeCommit', ('AWS::CodeCommit::',), (r'(?i:code\s*commit)',)),
    ('xray', 'X-Ray', ('AWS::XRay::',), (r'(?i:x-ray)',)),
    ('glue', 'Glue', ('AWS::Glue::',), (r'(?i:aws\s*glue)', 'Glue')),
    ('athena', 'Athena', ('AWS::Athena::',), (r'(?i:athena)',)),
    ('emr', 'EMR', ('AWS::EMR::', 'AWS::EMRServerless::'), ('EMR',)),
    ('quicksight', 'QuickSight', ('AWS::QuickSight::',), (r'(?i:quick\s*sight)',)),
    ('sagemaker', 'SageMaker', ('AWS::SageMaker::',), (r'(?i:sage\s*maker)',)),
    ('bedrock', 'Bedrock', ('AWS::Bedrock::',), (r'(?i:bedrock)',)),
    ('transfer', 'Transfer Family', ('AWS::Transfer::',), (r'(?i:transfer\s*family)',)),
    ('datasync', 'DataSync', ('AWS::DataSync::',), (r'(?i:data\s*sync)',)),
    ('storage-gateway', 'Storage Gateway', ('AWS::StorageGateway::',), (r'(?i:storage\s*gateway)',)),
    ('dms', 'Database Migration Service', ('AWS::DMS::',), ('DMS', r'(?i:database\s+migration\s+service)')),
    ('cloudmap', 'Cloud Map', ('AWS::ServiceDiscovery::',), (r'(?i:cloud\s*map)',)),
    ('mediaconvert', 'MediaConvert', ('AWS::MediaConvert::',), (r'(?i:media\s*convert)', r'(?i:elemental\s*mediaconvert)')),
    ('medialive', 'MediaLive', ('AWS::MediaLive::',), (r'(?i:media\s*live)',)),
    ('mediapackage', 'MediaPackage', ('AWS::MediaPackage::', 'AWS::MediaPackageV2::'), (r'(?i:media\s*package)',)),
    ('ivs', 'Interactive Video Service', ('AWS::IVS::',), (r'(?i:interactive\s+video\s+service)', r'(?i:amazon\s*ivs)')),
    ('amplify', 'Amplify', ('AWS::Amplify::',), (r'(?i:amplify)',)),
    ('connect', 'Amazon Connect', ('AWS::Connect::',), (r'(?i:amazon\s*connect)',)),
    ('workspaces', 'WorkSpaces', ('AWS::WorkSpaces::',), ('WorkSpaces',)),
)
LABELS = {key: label for key, label, _, _ in SERVICES}
TYPES = {key: types for key, _, types, _ in SERVICES}

# Role words that suggest a service without naming it: hints for the author, never failures.
ROLE_WORDS = (
    ('監査ログ', ('cloudtrail',)), ('操作ログ', ('cloudtrail',)), ('証跡', ('cloudtrail',)),
    ('ロググループ', ('cloudwatch-logs',)), ('ログ保管', ('cloudwatch-logs', 's3')), ('メトリクス', ('cloudwatch',)),
    ('アラーム', ('cloudwatch',)), ('死活監視', ('cloudwatch', 'route53')), ('ヘルスチェック', ('route53', 'elb')),
    ('通知トピック', ('sns',)), ('メール通知', ('sns', 'ses')), ('通知', ('sns',)),
    ('秘密情報', ('secretsmanager', 'ssm')), ('シークレット', ('secretsmanager',)), ('パスワード管理', ('secretsmanager',)),
    ('暗号鍵', ('kms',)), ('暗号化キー', ('kms',)), ('鍵管理', ('kms',)), ('マスターキー', ('kms',)),
    ('実行ロール', ('iam',)), ('ロール権限', ('iam',)),
    ('サーバ証明書', ('acm',)), ('サーバー証明書', ('acm',)), ('証明書', ('acm', 'acm-pca')), ('認証局', ('acm-pca',)),
    ('名前解決', ('route53',)), ('CDN', ('cloudfront',)),
    ('ロードバランサ', ('elb',)), ('負荷分散', ('elb',)), ('キュー', ('sqs',)), ('オブジェクトストレージ', ('s3',)),
    ('ファイアウォール', ('waf', 'network-firewall', 'security-group')), ('シングルサインオン', ('iam-identity-center', 'cognito')),
    ('バックアップ', ('backup',)), ('コンテナ', ('ecs', 'eks')),
)
STATUSES = ('NOT_IN_DESIGN', 'NOTED', 'CITED', 'IN_DESIGN')
STATUSES_JA = {'IN_DESIGN': '入力にある', 'CITED': '設定などが引用', 'NOTED': '入力の注記・判断が引用', 'NOT_IN_DESIGN': '入力にない'}
NOTE_GROUPS = ('requirements', 'operations', 'issues', 'decisions')
SHOWN = 10


def _compile():
    found = []
    for key, _, _, patterns in SERVICES:
        for pattern in patterns:
            # ASCII names stop at ASCII letters and digits; Japanese text around them is fine (S3バケット).
            found.append((key, re.compile(r'(?<![A-Za-z0-9])(?:' + pattern + r')(?![A-Za-z0-9])')))
    return found


PATTERNS = _compile()


def detect(text):
    """Service keys a text names, the longest name winning where names overlap (CloudWatch Logs is not CloudWatch too)."""
    plain = unicodedata.normalize('NFKC', str(text))
    spans = sorted(((m.start(), -(m.end() - m.start()), key) for key, rx in PATTERNS for m in rx.finditer(plain)))
    taken, end = [], -1
    for start, negative, key in spans:
        if start >= end:taken.append(key);end = start - negative
    return list(dict.fromkeys(taken))


def hint_groups(text):
    """The candidate services of each role word a text holds."""
    plain = unicodedata.normalize('NFKC', str(text))
    return [keys for word, keys in ROLE_WORDS if word in plain]


def hints(text):
    """Service keys the role words of a text suggest."""
    return list(dict.fromkeys(k for keys in hint_groups(text) for k in keys))


def type_holds(key, resource_type):
    for t in TYPES[key]:
        if t.endswith(('::', '*')):
            if resource_type.startswith(t.rstrip('*')):return True
        elif resource_type == t:return True
    return False


def in_design(design):
    """Service keys the input holds: through its resource types and the AWS_SERVICE actors it names."""
    held = set()
    types = {str(r.get('type', '')) for r in design.get('resources', []) or [] if isinstance(r, dict)}
    for key in LABELS:
        if any(type_holds(key, t) for t in types):held.add(key)
    for actor in design.get('actors', []) or []:
        if isinstance(actor, dict) and actor.get('kind') == 'AWS_SERVICE':
            held |= set(detect(f"{actor.get('service', '')} {actor.get('name', '')}"))
    return held


def source_ids(value):
    """Source IDs named by every `sources` list inside a value (settings, their overrides, objects)."""
    if isinstance(value, dict):
        for key, child in value.items():
            if key == 'sources' and isinstance(child, list):yield from (s for s in child if isinstance(s, str))
            else:yield from source_ids(child)
    elif isinstance(value, list):
        for child in value:yield from source_ids(child)


def cited_refs(design):
    """(notes, others): the (document, cell or drawing ID) pairs that the input's requirements, operations, issues and
    decisions cite, and those every other part of it cites."""
    from .grounding import DRAWING, expand
    locators = {s.get('id'): str(s.get('locator', '')) for s in design.get('sources', []) or [] if isinstance(s, dict)}

    def places(ids):
        found = set()
        for source in ids:
            document, _, place = locators.get(source, '').partition('#')
            if not place:continue
            cells = expand(place)
            if cells is not None:found |= {(document, c) for c in cells};continue
            found |= {(document, p.strip()) for p in place.split(',') if DRAWING.match(p.strip())}
        return found
    notes = places(i for group in NOTE_GROUPS for i in source_ids(design.get(group)))
    others = places(i for key, value in design.items() if key not in NOTE_GROUPS and key != 'sources' for i in source_ids(value))
    return notes, others


def mentions(library):
    """(document, ref, [service keys], [candidate groups of role words]) for every cell and drawing text of the CURRENT documents."""
    for document in sorted(library.entries):
        if library.entries[document].status != 'CURRENT':continue
        texts = list((library.cells.get(document) or {}).items()) + list((library.drawings.get(document) or {}).items())
        for ref, text in texts:
            named, suggested = detect(text), hint_groups(text)
            if named or suggested:yield document, ref, named, suggested


def report(design, library):
    """Each service the CURRENT documents name, with whether the input holds or notes it, and the role-word hints."""
    design = design if isinstance(design, dict) else {}
    held = in_design(design);noted, cited = cited_refs(design)
    where, groups = defaultdict(list), []
    for document, ref, named, suggested in mentions(library):
        for key in named:where[key].append((document, ref))
        groups += [(keys, (document, ref)) for keys in suggested]
    services = []
    for key, refs in where.items():
        status = ('IN_DESIGN' if key in held else 'CITED' if any(r in cited for r in refs)
                  else 'NOTED' if any(r in noted for r in refs) else 'NOT_IN_DESIGN')
        documents = sorted({d for d, _ in refs})
        services.append({'service': key, 'label': LABELS[key], 'status': status, 'mentions': len(refs), 'documents': documents,
                         'refs': [f'{d}#{r}' for d, r in refs[:SHOWN]], 'types': list(TYPES[key])})
    services.sort(key=lambda s: (STATUSES.index(s['status']), s['label'].casefold()))
    # A role word matters only when none of its candidates is in the input or named anywhere (コンテナ with ECS held is answered).
    known, hinted = held | set(where), defaultdict(list)
    for keys, place in groups:
        if not known & set(keys):
            for key in keys:hinted[key].append(place)
    hint_rows = [{'service': key, 'label': LABELS[key], 'mentions': len(refs), 'refs': [f'{d}#{r}' for d, r in refs[:SHOWN]]}
                 for key, refs in sorted(hinted.items(), key=lambda kv: LABELS[kv[0]].casefold())]
    counts = {s: sum(x['status'] == s for x in services) for s in STATUSES}
    status = 'FAIL' if counts['NOT_IN_DESIGN'] else 'PASS'
    return {'contract': 'service-mentions/1', 'status': status, 'counts': {'services_named': len(services), **counts, 'hints': len(hint_rows)},
            'services': services, 'hints': hint_rows,
            'limitations': ['名前の辞書による検出であり、文書が述べるすべてのサービスを見つける保証はない。役割語は手掛かりで、合否に使わない。',
                            'IN_DESIGN はその種類のリソースか相手が入力にあることで、文書の述べる数・配置・設定がそろったことではない。',
                            'CITED はその名前のあるセルを設定などが引用していることで、サービスの利用が設計に表れていることではない。',
                            'NOTED は入力の注記・判断が該当のセルを引用していることで、その理由が正しいことではない。']}


def render(found):
    c = found['counts']
    lines = [f"# 文書が名指すAWSサービス（{found['status']}）", '',
             f"CURRENTの文書のセルと図形の文字が名指すサービス {c['services_named']}種類。"
             + '・'.join(f"{STATUSES_JA[s]} {c[s]}" for s in STATUSES) + '。', '']
    if found['services']:
        lines += ['| サービス | 状態 | 言及 | 文書 | 位置（先頭） |', '|---|---|---:|---|---|']
        for s in found['services']:
            lines.append(f"| {s['label']} | {STATUSES_JA[s['status']]}（{s['status']}） | {s['mentions']} | {'、'.join(s['documents'][:5])} | "
                         f"{'、'.join(s['refs'][:5])} |")
    else:lines.append('名指されたサービスはない。')
    if c['NOT_IN_DESIGN']:
        lines += ['', '入力にないサービスは、リソースか AWS_SERVICE の相手として入力に加えるか、該当のセルを引用する注記（requirements・operations・issues）か'
                  '判断（decisions）で扱わない理由を書くか、人に聞く判断にする。黙って外さない。']
    if found['hints']:
        lines += ['', '## 役割語の手掛かり（合否に使わない）', '', '| 候補 | 言及 | 位置（先頭） |', '|---|---:|---|']
        lines += [f"| {h['label']} | {h['mentions']} | {'、'.join(h['refs'][:5])} |" for h in found['hints']]
    lines += [''] + [f'- {x}' for x in found['limitations']]
    return '\n'.join(lines) + '\n'
