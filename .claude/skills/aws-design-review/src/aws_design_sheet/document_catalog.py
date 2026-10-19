"""Pinned-schema documentation catalog. No evaluation rules are registered here."""
import hashlib
import json
from functools import lru_cache
from pathlib import Path
from zipfile import ZipFile

import regex

ROOT=Path(__file__).resolve().parents[2]
SERVICES={name:(name,) for name in (
    'EC2','IAM','Lambda','RDS','S3','AutoScaling','CloudFront','CloudWatch','DynamoDB','ECR','ECS','EKS',
    'KMS','Logs','SecretsManager','SNS','SQS','SSM','Config','CloudTrail','Backup','CertificateManager',
    'ACMPCA','WAFv2','Shield','GuardDuty','SecurityHub','InspectorV2','Macie','AccessAnalyzer','Organizations',
    'ControlTower','CloudFormation','ResourceGroups','RAM','ServiceCatalog','StepFunctions','Kinesis',
    'KinesisFirehose','Glue','Athena','Redshift','ElastiCache','MSK','SES','Cognito')}
SERVICES.update(APIGateway=('ApiGateway','ApiGatewayV2'),ELB=('ElasticLoadBalancing','ElasticLoadBalancingV2'),
    EventBridge=('Events','EventSchemas','Scheduler','Pipes'),Route53=('Route53','Route53Resolver'),
    OpenSearch=('OpenSearchService','Elasticsearch'))
PIN='70c0dd203208595c033800f3046e6e9513176089a3f903f486b6360bb79235d8'


def token(s):return s.replace('~','~0').replace('/','~1')
def pointer(parts):return '/properties/'+ '/'.join(token(str(p)) for p in parts)
def has_type(node,name):return node.get('type')==name or isinstance(node.get('type'),list) and name in node['type']


def matches(pattern,parts):
    wanted=[p.replace('~1','/').replace('~0','~') for p in pattern.split('/')[2:]]
    return len(parts)>=len(wanted) and all(a=='*' or a==str(b) for a,b in zip(wanted,parts))


class Catalog:
    def __init__(self,root=ROOT/'schemas', *, expected_pin=None, region=None):
        from .schema_bootstrap import resolve_schema_dir, lock_path
        root=Path(root)
        if expected_pin is None:
            locked = lock_path(root,region).exists()
            root = resolve_schema_dir(root,region)
            expected_pin = json.loads((root/'manifest.json').read_text(encoding='utf8'))['zip_sha256'] if locked else PIN
        self.manifest=json.loads((root/'manifest.json').read_text(encoding='utf8'))
        if region is not None and self.manifest['region']!=region:
            raise ValueError('documentation catalog region mismatch')
        raw=(root/self.manifest['archive']).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=expected_pin or self.manifest['zip_sha256']!=expected_pin:
            raise ValueError('documentation catalog schema pin mismatch')
        namespace={n:s for s,ns in SERVICES.items() for n in ns}
        with ZipFile(root/self.manifest['archive']) as archive:
            self.schemas={t:json.loads(archive.read(file)) for t,file in self.manifest['types'].items()
                          if t.startswith('AWS::') and t.split('::')[1] in namespace}
        self.services={t:namespace[t.split('::')[1]] for t in self.schemas}
        ref_raw=(root.parent/'rules/references.json').read_bytes()
        self.references=json.loads(ref_raw)['references']
        self.reference_sha256=hashlib.sha256(ref_raw).hexdigest()
        if not self.schemas or not set(self.services.values())<=set(SERVICES):
            raise ValueError('empty or unsupported documentation service catalog')

    def branches(self,kind,node,seen=()):
        if not isinstance(node,dict):return
        if id(node) in seen:return
        seen=(*seen,id(node));yield node
        if '$ref' in node:
            ref=node['$ref']
            if not ref.startswith('#/'):raise ValueError('non-local schema reference')
            target=self.schemas[kind]
            for part in ref[2:].split('/'):target=target[part.replace('~1','/').replace('~0','~')]
            yield from self.branches(kind,target,seen)
        for key in ('allOf','anyOf','oneOf','if','then','else'):
            value=node.get(key,[])
            for branch in value if isinstance(value,list) else [value]:
                yield from self.branches(kind,branch,seen)

    def at(self,kind,parts):
        nodes=[self.schemas[kind]]
        for part in parts:
            found=[]
            for node in nodes:
                for branch in self.branches(kind,node):
                    if not branch:found.append({});continue
                    if '$ref' in branch and not any(k in branch for k in ('properties','items','additionalProperties')):continue
                    if isinstance(part,int) or part=='*':
                        items=branch.get('items')
                        if isinstance(items,dict):found.append(items)
                        elif isinstance(items,list):
                            found.extend(items if part=='*' else items[part:part+1])
                            if part=='*' or part>=len(items):
                                extra=branch.get('additionalItems',True)
                                if extra is not False:found.append(extra if isinstance(extra,dict) else {})
                        elif has_type(branch,'array'):found.append({})
                    else:
                        props=branch.get('properties',{})
                        if part in props:found.append(props[part]);continue
                        patterns=branch.get('patternProperties',{})
                        matched=[v for p,v in patterns.items() if regex.search(p,str(part),timeout=.05)]
                        if matched:found.extend(matched);continue
                        additional=branch.get('additionalProperties',True)
                        if additional is not False and (has_type(branch,'object') or 'properties' in branch or 'additionalProperties' in branch or not branch):
                            found.append(additional if isinstance(additional,dict) else {})
            nodes=found
        return nodes

    def readonly(self,kind,parts):
        return any(matches(p,parts) for p in self.schemas[kind].get('readOnlyProperties',[]))

    def writable(self,kind):
        return {k:v for k,v in self.schemas[kind]['properties'].items() if not self.readonly(kind,[k])}

    def reference_targets(self,kind,parts):
        return {r['target_type'] for r in self.references if r['source_type']==kind
                and len(r['path'].split('/')[2:])==len(parts) and matches(r['path'],parts)}

    def shape(self,kind,parts,value):
        """Check only property reachability and JSON types, not AWS design validity."""
        if self.readonly(kind,parts):raise ValueError('read-only property cannot be a design input')
        nodes=self.at(kind,parts)
        if not nodes:raise ValueError('property is absent from the pinned schema')
        types=[];unrestricted=False
        for node in nodes:
            branches=list(self.branches(kind,node))
            typed=[b['type'] for b in branches if 'type' in b]
            if not typed:unrestricted=True
            for typ in typed:types.extend(typ if isinstance(typ,list) else [typ])
        predicates={'string':lambda x:isinstance(x,str),'object':lambda x:isinstance(x,dict),
            'array':lambda x:isinstance(x,list),'integer':lambda x:type(x) is int,
            'number':lambda x:type(x) in (int,float),'boolean':lambda x:type(x) is bool,'null':lambda x:x is None}
        if not unrestricted and types and not any(predicates[t](value) for t in types if t in predicates):
            raise ValueError('literal JSON type is incompatible with the schema')

    def paths(self,kind):
        """Finite path inventory; dynamic keys and recursion are explicitly marked."""
        records={}
        def walk(node,parts,trail):
            for branch in self.branches(kind,node):
                path=pointer(parts) if parts else '/properties'
                if parts:
                    record=records.setdefault(path,{'path':path,'input':not self.readonly(kind,parts),'types':[],
                        'conditional':False,'dynamic':False,'recursive':False})
                    typ=branch.get('type',[]);record['types']=sorted(set(record['types']+(typ if isinstance(typ,list) else [typ])))
                    record['conditional']|=any(k in branch for k in ('if','then','else','oneOf','anyOf','allOf'))
                if id(branch) in trail:
                    if parts:records[path]['recursive']=True
                    continue
                trail2=(*trail,id(branch))
                for name,child in branch.get('properties',{}).items():walk(child,[*parts,name],trail2)
                children=branch.get('items')
                if isinstance(children,dict):walk(children,[*parts,'*'],trail2)
                elif isinstance(children,list):
                    for i,child in enumerate(children):walk(child,[*parts,i],trail2)
                    extra=branch.get('additionalItems',True)
                    if extra is not False:walk(extra if isinstance(extra,dict) else {},[*parts,'*'],trail2)
                elif has_type(branch,'array'):walk({},[*parts,'*'],trail2)
                for pattern,child in branch.get('patternProperties',{}).items():
                    dynamic=[*parts,'{key:'+pattern+'}'];walk(child,dynamic,trail2);records[pointer(dynamic)]['dynamic']=True
                additional=branch.get('additionalProperties',True if has_type(branch,'object') else False)
                if additional is True or isinstance(additional,dict):
                    dynamic=[*parts,'{additional-key}'];walk(additional if isinstance(additional,dict) else {},dynamic,trail2)
                    records[pointer(dynamic)]['dynamic']=True
        walk(self.schemas[kind],[],())
        return list(records.values())

    def report(self):
        resources={t:{'service':self.services[t],'input_properties':sorted(self.writable(t)),
            'read_only_paths':s.get('readOnlyProperties',[]),'write_only_paths':s.get('writeOnlyProperties',[]),
            'create_only_paths':s.get('createOnlyProperties',[]),'paths':self.paths(t)} for t,s in self.schemas.items()}
        services={g:{'namespaces':list(ns),'resource_types':sum(r['service']==g for r in resources.values()),
            'input_top_level_properties':sum(len(r['input_properties']) for r in resources.values() if r['service']==g),
            'input_path_patterns':sum(sum(p['input'] for p in r['paths']) for r in resources.values() if r['service']==g)} for g,ns in SERVICES.items()}
        return {'catalog_version':'1.1','provenance':{**{k:self.manifest[k] for k in ('region','retrieved_at','source','zip_sha256')},'reference_catalog_sha256':self.reference_sha256},
                'service_count':len(services),'resource_type_count':len(resources),
                'input_top_level_property_count':sum(len(r['input_properties']) for r in resources.values()),
                'path_count_semantics':'finite patterns, not all concrete dynamic keys or recursive instances',
                'services':services,'resources':resources}


@lru_cache(maxsize=8)
def _catalog(root, pin, region, signatures):return Catalog(root, expected_pin=pin, region=region)


def catalog(region=None):
    from .schema_bootstrap import resolve_schema_dir, lock_path, fingerprint
    root = ROOT/'schemas'
    resolved=resolve_schema_dir(root,region)
    manifest=json.loads((resolved/'manifest.json').read_text(encoding='utf8'))
    # resolve_schema_dir verified the cache against its lock, including any recorded drift.
    pin = manifest['zip_sha256'] if lock_path(root,region).exists() else PIN
    signatures=tuple(fingerprint(p) for p in (resolved/'manifest.json',resolved/manifest['archive'],resolved.parent/'rules/references.json'))
    return _catalog(resolved, pin, region, signatures)


catalog.cache_clear=_catalog.cache_clear


def input_type_inventory():
    """JSON contract inventory; runtime still checks the selected regional catalog."""
    from .schema_bootstrap import read_lock
    types=set(catalog().schemas)
    for path in (ROOT/'schemas').glob('schema-lock.*.json'):
        region=path.name[len('schema-lock.'):-len('.json')]
        types.update(read_lock(ROOT/'schemas',region).get('catalog_types',[]))
    return sorted(types)
