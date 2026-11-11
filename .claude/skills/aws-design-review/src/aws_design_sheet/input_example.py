"""A small 1.1 design input that shows every shape an author needs, printed by `aws-design document --example`.

The JSON Schema says which keys exist; it cannot show how a cited value, a derived value, an open setting, a
reference and a composite value with open leaves look side by side. This example does, with fictional names. It
generates as it is (`aws-design document FILE --environment prod --output DIR`); its citations point at a document
that does not exist, so with a source set they would not be grounded. Copy the shapes, never the values.
"""

EXAMPLE = {
    'schema_version': '1.1',
    'system': {'id': 'example', 'name': '記入例（架空）'},
    'accounts': [{'id': 'workload', 'name': '本番アカウント', 'sources': ['d-account']}],
    'environments': [{'id': 'prod', 'name': '本番', 'region': 'ap-northeast-1', 'account': 'workload'}],
    # One source per cell (or drawing element) cited: DOCUMENT_ID#s<sheet>-<cell>, or DOCUMENT_ID#s1-d4 for a drawing.
    'sources': [
        {'id': 'c-vpc-cidr', 'title': '基本設計 4.1 VPC', 'locator': '02_基本設計/basic-design.docx#s1-C59'},
        {'id': 'c-subnet', 'title': '基本設計 4.2 サブネット', 'locator': '02_基本設計/basic-design.docx#s1-C66'},
        {'id': 'c-fn', 'title': '基本設計 9.1 関数', 'locator': '02_基本設計/basic-design.docx#s1-B240'},
        {'id': 'c-timeout', 'title': '基本設計 9.1 タイムアウト', 'locator': '02_基本設計/basic-design.docx#s1-D240'},
        {'id': 'c-memory', 'title': '基本設計 9.1 メモリ（空欄）', 'locator': '02_基本設計/basic-design.docx#s1-E240'},
        {'id': 'c-scaling', 'title': '基本設計 6.3 自動スケーリング', 'locator': '02_基本設計/basic-design.docx#s1-B150'},
        {'id': 'c-audit', 'title': '基本設計 11.2 証跡', 'locator': '02_基本設計/basic-design.docx#s1-A380'},
        {'id': 'd-account', 'title': '構成図 アカウントの枠', 'locator': '02_基本設計/system-diagram.xlsx#s1-d1'},
        {'id': 'd-vpc', 'title': '構成図 VPC の枠', 'locator': '02_基本設計/system-diagram.xlsx#s1-d3'},
        {'id': 'd-fn', 'title': '構成図 関数のアイコン', 'locator': '02_基本設計/system-diagram.xlsx#s1-d5'},
        {'id': 'd-line', 'title': '構成図 利用者から関数への線', 'locator': '02_基本設計/system-diagram.xlsx#s1-d7'},
    ],
    'resources': [
        {'id': 'vpc', 'name': '業務VPC', 'type': 'AWS::EC2::VPC', 'sources': ['d-vpc'], 'settings': {
            # A value a cell states: LITERAL, citing that cell.
            'CidrBlock': {'status': 'DECIDED', 'mode': 'LITERAL', 'value': '10.0.0.0/16', 'sources': ['c-vpc-cidr']}}},
        {'id': 'subnet-a', 'name': 'アプリ用サブネット a', 'type': 'AWS::EC2::Subnet', 'settings': {
            # Another resource of this input: RESOURCE_REF with its id (a list of ids where the property takes several).
            'VpcId': {'status': 'DECIDED', 'mode': 'RESOURCE_REF', 'ref': 'vpc'},
            'AvailabilityZone': {'status': 'DECIDED', 'mode': 'LITERAL', 'value': 'ap-northeast-1a', 'sources': ['c-subnet']},
            # The documents leave it blank: UNDECIDED with its cause, never a guessed value.
            'CidrBlock': {'status': 'UNDECIDED', 'cause': 'DESIGNER_TASK', 'rationale': '4.2 の CIDR の欄が空欄。ほかのサブネットから推定しない', 'sources': ['c-subnet']}}},
        {'id': 'fn-report', 'name': '月次レポート', 'type': 'AWS::Lambda::Function', 'sources': ['c-fn', 'd-fn'], 'settings': {
            # A value you derive (minutes to seconds): cite the cell and say in rationale how it was derived.
            'Timeout': {'status': 'DECIDED', 'mode': 'LITERAL', 'value': 300, 'sources': ['c-timeout'], 'rationale': '「5分」を秒に換算'},
            # A decision a person owes: the cause, and the ask that names the decision (one id per decision).
            'MemorySize': {'status': 'UNDECIDED', 'cause': 'WAITS_FOR', 'ask': 'ask-report-memory', 'rationale': '負荷試験の結果で決める', 'sources': ['c-memory']},
            # A structured value: COMPOSITE. Inside it, {"$design": {...}} is a leaf with its own mode or its own open state.
            'VpcConfig': {'status': 'DECIDED', 'mode': 'COMPOSITE', 'sources': ['c-fn'], 'value': {
                'SubnetIds': [{'$design': {'mode': 'RESOURCE_REF', 'ref': 'subnet-a'}}],
                'SecurityGroupIds': {'$design': {'status': 'UNDECIDED', 'cause': 'DESIGNER_TASK', 'rationale': '関数のセキュリティグループは文書にない'}},
                'Ipv6AllowedForDualStack': {'$design': {'status': 'DECIDED', 'mode': 'OMITTED', 'rationale': 'IPv6 は使わないと書かれている'}}}},
            # Required properties the documents do not give are open settings too, never left out (checklist.json lists MISSING rows).
            'Role': {'status': 'UNDECIDED', 'cause': 'DESIGNER_TASK', 'rationale': '実行ロールは文書にない。設計者が権限を決めて作る'},
            'Code': {'status': 'UNDECIDED', 'cause': 'BUILD_NOTE', 'rationale': 'コードの置き場所は構築時に決まる'},
            # The documents decide that the property is not set: OMITTED.
            'ReservedConcurrentExecutions': {'status': 'DECIDED', 'mode': 'OMITTED', 'rationale': '同時実行数は制限しないと書かれている', 'sources': ['c-fn']}}},
    ],
    'actors': [
        {'id': 'user', 'name': '利用者', 'kind': 'USER'},
        # A service whose type the catalog lacks (aws-design document --types): an AWS_SERVICE actor, so that its flows can be drawn.
        {'id': 'app-autoscaling', 'name': 'Application Auto Scaling', 'kind': 'AWS_SERVICE', 'service': 'Application Auto Scaling', 'sources': ['c-scaling']},
    ],
    'connections': [
        {'id': 'cn-user-report', 'source': 'user', 'target': 'fn-report', 'kind': 'TRAFFIC', 'description': '利用者がレポートを要求する', 'sources': ['d-line']},
    ],
    'issues': [
        # A service the documents name that this system does not build: a note citing the cell that names it.
        {'id': 'iss-org-trail', 'title': '組織で有効化済みの証跡', 'text': 'CloudTrail は組織全体で有効化済みで、このシステムでは作らない', 'status': 'NOT_APPLICABLE', 'sources': ['c-audit']},
    ],
}

# Printed beside the example (on standard error, so that standard output stays the JSON): what its shapes mean.
NOTES = """# How to read the example (aws-design document --example prints the JSON alone on standard output):
# - sources: one entry per cell or drawing cited. locator = DOCUMENT_ID#s<sheet>-<cell> (s1-C59) or DOCUMENT_ID#s1-d4 for a drawing.
#   Read the cells and their IDs with aws-design sources cells.
# - A setting is {"status": "DECIDED", "mode": ..., "sources": [...]} or {"status": "UNDECIDED", "cause": ..., "rationale": ...}.
#   mode LITERAL: "value" is a plain JSON value of the type the property takes (a number is 300, never "300"; a list is [...], never {"Items": [...]}).
#   mode RESOURCE_REF: "ref" is the id of a resource of this input, or a list of ids where the property takes a list.
#   mode COMPOSITE: "value" is the property's own JSON structure. Anywhere inside it, {"$design": {a setting}} stands for one value:
#     a reference ({"$design": {"mode": "RESOURCE_REF", "ref": "subnet-a"}}; with a list of ids it stands for the whole list),
#     an open leaf ({"$design": {"status": "UNDECIDED", "cause": ..., "rationale": ...}}),
#     or a leaf the documents decide not to set ({"$design": {"status": "DECIDED", "mode": "OMITTED", ...}}).
#     Never put "mode", "status" or "cause" inside a composite value without the "$design" wrapper.
#   mode OMITTED: the documents decide that the property is not set.
# - UNDECIDED needs "cause": OWNER_DECISION, WAITS_FOR or EXTERNAL_DATA (these also name the decision with "ask"),
#   DESIGNER_TASK or BUILD_NOTE. A required property the documents do not give is UNDECIDED, never left out.
# - A value you derive cites its cell and says in "rationale" how (minutes to seconds, a word to a flag). Documents written in
#   Japan time: windows and schedules AWS reads in UTC are converted (3:00 JST is 18:00 UTC the day before), or the schedule
#   carries its time zone setting. Write a rationale for what you derived only; a value copied as written needs none.
# - actors: USER, OPERATOR, EXTERNAL_SYSTEM, or AWS_SERVICE for a service whose type aws-design document --types does not list.
# - connections: a flow is {"kind": "TRAFFIC", "source": id, "target": id}; only TRAFFIC connections reach an actor.
#   kind DEPENDENCY records that the source depends on the target without sending it requests (it is built, or works, only with it).
#   kind REFERENCE is for a top-level property of the source resource that names the target ("property": "VpcId"); a flow is never a REFERENCE.
# - ids are lower case: a letter, then letters, digits, - or _ (c-vpc-cidr, never C-VPC). A note's status is DECIDED, UNDECIDED or NOT_APPLICABLE.
# - ids are unique across the whole input: accounts, environments, sources, resources, actors, connections and notes
#   (an account and an environment cannot both be "prod").
# - A structure error names the resource, the setting and the place inside a composite value: fix that place, do not search by halves.
#   One error lists the faults of several settings (separated by |): fix them all before generating again.
"""
