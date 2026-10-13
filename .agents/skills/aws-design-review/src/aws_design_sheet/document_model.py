"""Input v1 and normalized document contracts. No AWS calls or value inference."""
from typing import Annotated, Literal

from pydantic import ConfigDict, Field, JsonValue, model_validator

from .models import StrictModel
from .document_services import CATALOG, definition
from .document_requirements import Checklist, InputRequirement, validate_requirements
from .document_evaluation import Evaluation
from .document_policy_model import ProjectPolicy, PolicyException, PolicyEvaluation, validate_policies

ID = Annotated[str, Field(pattern=r'^[a-z][a-z0-9_-]{0,63}$')]
Status = Literal['DECIDED', 'UNDECIDED', 'NOT_APPLICABLE']
ResourceType = Literal['AWS::EC2::VPC','AWS::EC2::Subnet','AWS::EC2::SecurityGroup',
                       'AWS::EC2::Instance','AWS::RDS::DBSubnetGroup','AWS::RDS::DBInstance','AWS::RDS::DBCluster']


class Setting(StrictModel):
    model_config = ConfigDict(json_schema_extra={'allOf':[
        {'if':{'properties':{'status':{'enum':['UNDECIDED','NOT_APPLICABLE']}},'required':['status']},
         'then':{'properties':{k:{'type':'null'} for k in ('mode','value','ref','expression')}},
         'else':{'required':['mode'],'properties':{'mode':{'type':'string'}}}},
        *[{'if':{'properties':{'mode':{'const':mode}},'required':['mode']},
           'then':{'required':[payload],'properties':{payload:{'not':{'type':'null'}},
                    **{k:{'type':'null'} for k in ('value','ref','expression') if k!=payload}}}}
          for mode,payload in [('LITERAL','value'),('EXPRESSION','expression'),('RESOURCE_REF','ref'),('EXTERNAL_REF','ref'),('SECRET_REF','ref')]],
        {'if':{'properties':{'mode':{'enum':['DEFAULT','OMITTED']}},'required':['mode']},
         'then':{'properties':{k:{'type':'null'} for k in ('value','ref','expression')}}},
        {'if':{'properties':{'classification':{'const':'SECRET'}},'required':['classification']},
         'then':{'anyOf':[{'properties':{'status':{'enum':['UNDECIDED','NOT_APPLICABLE']}},'required':['status']},
                          {'properties':{'mode':{'enum':['SECRET_REF','OMITTED']}},'required':['mode']}]}},
        {'if':{'properties':{'mode':{'const':'SECRET_REF'}},'required':['mode']},
         'then':{'required':['classification'],'properties':{'classification':{'const':'SECRET'},'ref':{'type':'string','pattern':'^(secret|ssm)://.+'}}}}
    ]})
    status: Status = 'DECIDED'
    mode: Literal['LITERAL','DEFAULT','OMITTED','RESOURCE_REF','EXTERNAL_REF','EXPRESSION','SECRET_REF'] | None = None
    classification: Literal['PUBLIC','INTERNAL','CONFIDENTIAL','SECRET'] = 'INTERNAL'
    value: JsonValue = None
    ref: str | list[str] | None = None
    expression: JsonValue = None
    rationale: str = ''
    sources: list[ID] = Field(default_factory=list)

    @model_validator(mode='after')
    def shape(self):
        if self.status != 'DECIDED':
            if any(v is not None for v in (self.mode,self.value,self.ref,self.expression)):
                raise ValueError('undecided/not-applicable setting cannot carry a value or mode')
        elif self.mode is None:
            raise ValueError('decided setting requires a mode')
        elif self.mode == 'LITERAL':
            if self.value is None or self.ref is not None or self.expression is not None:
                raise ValueError('literal requires only value')
        elif self.mode == 'EXPRESSION':
            if self.expression is None or self.ref is not None or self.value is not None:
                raise ValueError('expression requires only expression')
        elif self.mode in ('RESOURCE_REF','EXTERNAL_REF','SECRET_REF'):
            if not self.ref or self.value is not None or self.expression is not None:
                raise ValueError('reference mode requires only ref')
            if self.mode != 'RESOURCE_REF' and not isinstance(self.ref,str):
                raise ValueError('external/secret reference must be a string')
        elif any(v is not None for v in (self.value,self.ref,self.expression)):
            raise ValueError('default mode does not assert a resolved value')
        if self.classification == 'SECRET' and self.status == 'DECIDED' and self.mode not in ('SECRET_REF','OMITTED'):
            raise ValueError('secret settings must use a reference, never a value')
        if self.mode == 'SECRET_REF':
            if self.classification != 'SECRET' or not self.ref.startswith(('secret://','ssm://')):
                raise ValueError('secret reference requires SECRET and a secret:// or ssm:// identifier')
        return self


class Source(StrictModel):
    id: ID
    title: str
    locator: str


class System(StrictModel):
    id: ID
    name: str
    description: str = ''


class Resource(StrictModel):
    model_config = ConfigDict(json_schema_extra={'allOf':[
        {'if':{'properties':{'type':{'const':kind}},'required':['type']},
         'then':{'properties':{'settings':{'additionalProperties':False,
                    'properties':{name:{} for name in fields}}}}}
        for kind,(_,fields) in CATALOG.items()
    ]})
    id: ID
    name: str
    type: ResourceType
    cfn_logical_id: Annotated[str,Field(pattern=r'^[A-Za-z][A-Za-z0-9]*$')] | None = None
    settings: dict[str,Setting] = Field(default_factory=dict)
    rationale: str = ''
    sources: list[ID] = Field(default_factory=list)


class Override(StrictModel):
    resource_id: ID
    settings: dict[str,Setting]


class Environment(StrictModel):
    id: ID
    name: str
    region: Annotated[str,Field(pattern=r'^[a-z]{2}(?:-gov)?-[a-z]+-\d+$')]
    description: str = ''
    overrides: list[Override] = Field(default_factory=list)


class Note(StrictModel):
    id: ID
    title: str
    text: str
    status: Status = 'DECIDED'
    resources: list[ID] = Field(default_factory=list)
    sources: list[ID] = Field(default_factory=list)


class Connection(StrictModel):
    id: ID
    source: ID
    target: ID
    kind: Literal['REFERENCE','TRAFFIC','DEPENDENCY']
    property: str | None = None
    protocol: str = ''
    ports: str = ''
    description: str = ''
    rationale: str = ''
    status: Status = 'DECIDED'
    sources: list[ID] = Field(default_factory=list)


class DocumentInput(StrictModel):
    schema_version: Literal['1.0']
    system: System
    environments: list[Environment] = Field(min_length=1)
    sources: list[Source] = Field(default_factory=list)
    requirements: list[Note] = Field(default_factory=list)
    required_inputs: list[InputRequirement] = Field(default_factory=list)
    project_policies: list[ProjectPolicy] = Field(default_factory=list, max_length=256)
    policy_exceptions: list[PolicyException] = Field(default_factory=list, max_length=256)
    resources: list[Resource] = Field(min_length=1)
    connections: list[Connection] = Field(default_factory=list)
    operations: list[Note] = Field(default_factory=list)
    issues: list[Note] = Field(default_factory=list)

    @model_validator(mode='after')
    def integrity(self):
        validate_requirements(self)
        objects=[self.system,*self.environments,*self.sources,*self.resources,*self.requirements,
                 *self.connections,*self.operations,*self.issues]
        ids=[x.id for x in objects]
        if len(ids)!=len(set(ids)):
            raise ValueError('duplicate stable ID')
        resources={r.id:r for r in self.resources}; sources={s.id for s in self.sources}
        logical=[r.cfn_logical_id for r in self.resources if r.cfn_logical_id]
        if len(logical)!=len(set(logical)):
            raise ValueError('duplicate CFN binding')
        def provenance(item):
            if any(s not in sources for s in item.sources):
                raise ValueError('invalid source reference')
        def settings(resource, values):
            for name,item in values.items():
                kind=definition(resource.type,name)
                if kind is None:raise ValueError('unsupported service field')
                provenance(item)
                if kind=='secret' and item.status=='DECIDED' and item.mode!='SECRET_REF':
                    raise ValueError('sensitive field requires a secret reference')
                if item.mode=='RESOURCE_REF':
                    refs=[item.ref] if isinstance(item.ref,str) else item.ref
                    if not kind.startswith(('ref:','refs:')):raise ValueError('field does not accept a resource reference')
                    if kind.startswith('refs:') != isinstance(item.ref,list):raise ValueError('reference cardinality mismatch')
                    if len(refs)!=len(set(refs)) or any(x not in resources or resources[x].type!=kind.split(':',1)[1] for x in refs):
                        raise ValueError('invalid or mistyped resource reference')
                if item.mode=='LITERAL':
                    types={'string':str,'boolean':bool,'integer':int,'array':list}
                    if kind.startswith(('ref:','refs:')):raise ValueError('use explicit reference mode for resource identity')
                    if kind in types and type(item.value) is not types[kind]:raise ValueError('literal field type mismatch')
        for resource in self.resources:
            provenance(resource);settings(resource,resource.settings)
        for env in self.environments:
            overridden=[o.resource_id for o in env.overrides]
            if len(overridden)!=len(set(overridden)):raise ValueError('duplicate environment override')
            for override in env.overrides:
                if override.resource_id not in resources:raise ValueError('invalid override resource')
                settings(resources[override.resource_id],override.settings)
        for note in [*self.requirements,*self.operations,*self.issues]:
            provenance(note)
            if any(r not in resources for r in note.resources):raise ValueError('invalid note resource')
        for conn in self.connections:
            provenance(conn)
            if conn.source not in resources or conn.target not in resources:raise ValueError('invalid connection endpoint')
            if conn.kind=='REFERENCE':
                kind=definition(resources[conn.source].type,conn.property)
                if not kind or not kind.startswith(('ref:','refs:')) or kind.split(':',1)[1]!=resources[conn.target].type:
                    raise ValueError('invalid connection property or target type')
            elif conn.property is not None:raise ValueError('only reference connections have a property')
        validate_policies(self)
        return self


class Observation(StrictModel):
    state: Literal['NO_CFN','NO_BINDING','RESOURCE_MISSING','TYPE_MISMATCH','ABSENT','LITERAL','EXPRESSION','REDACTED','CONDITIONAL']
    value: JsonValue = None
    pointer: str = ''


class Item(StrictModel):
    item_id: str
    row_id: str
    resource_id: str
    name: str
    input_pointer: str
    service: str
    expected: Setting
    common: Setting | None = None
    origin: Literal['common','environment','cfn_only']
    defined: Observation
    comparison: Literal['MATCH','DIFFERENT','UNRESOLVED','NOT_COMPARED']


class Document(StrictModel):
    model_version: Literal['1.0'] = '1.0'
    generation_status: Literal['GENERATED'] = 'GENERATED'
    evaluation_status: Literal['NOT_EVALUATED','COMPLETE','FAILED','SKIPPED'] = 'NOT_EVALUATED'
    environment_id: str
    input_sha256: str
    cfn_sha256: str | None = None
    design: DocumentInput
    items: list[Item]
    resource_comparisons: dict[str,Literal['NO_CFN','NO_BINDING','MISSING','TYPE_MISMATCH','PRESENT','CONDITIONAL']]
    connection_comparisons: dict[str,str]
    notices: list[str]
    checklist: Checklist = Field(default_factory=Checklist)
    evaluation: Evaluation = Field(default_factory=Evaluation)
    project_policy: PolicyEvaluation = Field(default_factory=PolicyEvaluation)
