"""Regenerate the T1 open-question triage from the current ledger.

Question numbers refer to their order within each type's open_questions array.
Review this mapping when the ledger text or order changes.
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TIERS = ("EC2", "IAM", "Lambda", "RDS", "S3")

# These items have a design-local portion or a concrete documentation/artifact
# investigation that could lead to a rule. This is not a claim that the whole
# ledger entry can be removed without external state.
CANDIDATES: dict[str, dict[str, tuple[int, ...]]] = {
    "EC2": {
        "CapacityReservation": (3,),
        "CapacityReservationFleet": (1,),
        "CustomerGateway": (1,),
        "EC2Fleet": (1, 2, 4, 5),
        "Host": (1,), "IPAMPool": (1,), "IPAMPrefixListResolver": (1,),
        "Instance": (3, 5, 6, 10), "LaunchTemplate": (4, 5, 6, 8),
        "NatGateway": (1, 3), "PlacementGroup": (2,),
        "Route": (1,), "RouteServer": (1,), "SecurityGroup": (2,),
        "SecurityGroupEgress": (1,), "SecurityGroupIngress": (1,),
        "SpotFleet": (3, 4, 6), "SubnetCidrBlock": (1,),
        "TrafficMirrorFilterRule": (1,),
        "TrafficMirrorTarget": (1,),
        "VPCCidrBlock": (1,), "VPCEndpoint": (1, 2),
        "VPCEndpointConnectionNotification": (1,), "VPCEndpointService": (1,),
        "VPCPeeringConnection": (1,), "VPNConnection": (1,),
        "VerifiedAccessEndpoint": (1,),
        "VerifiedAccessTrustProvider": (1,), "Volume": (4,),
    },
    "IAM": {
        "Policy": (2,),
    },
    "Lambda": {
        "Function": (2,), "LayerVersionPermission": (1,), "Url": (1,),
    },
    "RDS": {
        "CustomDBEngineVersion": (1, 3),
        "DBCluster": (1, 2, 3, 7, 10, 14),
        "DBClusterParameterGroup": (2,), "DBInstance": (1, 2, 4, 9, 10),
        "DBParameterGroup": (1, 2), "DBSecurityGroup": (1, 2),
        "DBSecurityGroupIngress": (2,),
        "GlobalCluster": (1, 2), "OptionGroup": (1,),
    },
    "S3": {
        "AccessGrant": (2,), "StorageLens": (1,),
    },
}

# A smaller queue with a concrete implementation path; the remaining
# candidates need source interpretation or capability-data research first.
READY: dict[str, dict[str, tuple[int, ...]]] = {}


def main() -> None:
    ledger = json.loads((ROOT / "rules/ledger.json").read_text(encoding="utf-8"))["types"]
    rows: list[tuple[str, str, str, str]] = []
    totals = defaultdict(lambda: [0, 0])
    ready_total = 0
    for namespace in TIERS:
        for full_type, entry in ledger.items():
            if not full_type.startswith(f"AWS::{namespace}::"):
                continue
            short_type = full_type.split("::")[-1]
            questions = entry.get("open_questions", [])
            candidate_numbers = set(CANDIDATES.get(namespace, {}).get(short_type, ()))
            invalid = candidate_numbers - set(range(1, len(questions) + 1))
            if invalid:
                raise ValueError(f"invalid question numbers for {full_type}: {sorted(invalid)}")
            ready_numbers = set(READY.get(namespace, {}).get(short_type, ()))
            if ready_numbers - candidate_numbers:
                raise ValueError(f"ready questions are not candidates for {full_type}")
            ready_total += len(ready_numbers)
            if not questions:
                continue
            other_numbers = set(range(1, len(questions) + 1)) - candidate_numbers
            totals[namespace][0] += len(candidate_numbers)
            totals[namespace][1] += len(other_numbers)
            rows.append((namespace, short_type,
                         ", ".join(map(str, sorted(candidate_numbers))) or "—",
                         ", ".join(map(str, sorted(other_numbers))) or "—"))
    total_candidate = sum(value[0] for value in totals.values())
    total_other = sum(value[1] for value in totals.values())
    lines = [
        "# T1 未解決事項の仕分け（2026-10-03）", "",
        "対象は `rules/ledger.json` の T1（EC2、IAM、Lambda、RDS、S3）の `open_questions`。",
        "各番号は、そのリソースタイプ内の配列順（1始まり）。台帳の文言や順序を変えたら仕分けを再確認する。", "",
        "## 判定基準", "",
        "- **対応候補**：設計内の複数リソース、テンプレート依存関係、静的な成果物、版を固定した能力表、または追加の公式資料調査によって、少なくとも一部を判定できる可能性がある。資料に曖昧さ・矛盾が残る場合、調査完了まで `FAIL` ルールは作らない。外部状態を含む同じ項目の残りは台帳に残す。",
        "- **現行入力では解決不可**：残りの論点がAWSアカウントの既存状態、外部リソース、デプロイ時刻、更新履歴、動的割当、またはAWS側の仕様確定を要する。入力や検査範囲を広げない限り、自動的な合否は出せない。既存チェックが設計内の部分を扱っていても、この欄には未解決の残部を分類する。", "",
        "| 名前空間 | 対応候補 | 現行入力では解決不可 | 合計 |", "| --- | ---: | ---: | ---: |",
    ]
    for namespace in TIERS:
        yes, no = totals[namespace]
        lines.append(f"| {namespace} | {yes} | {no} | {yes + no} |")
    lines.extend([f"| **合計** | **{total_candidate}** | **{total_other}** | **{total_candidate + total_other}** |", "",
                  f"対応候補{total_candidate}件の内訳は、対応経路を特定できたもの**{ready_total}件**と、資料・能力表の追加調査を要するもの**{total_candidate - ready_total}件**。後者は調査の結果、解決不可側に移る可能性がある。", "",
                  "この件数は台帳の**項目数**であり、未実装ルール数ではない。対応候補も項目全体を解消できると確定した件数ではない。", "",
                  "## 項目別の仕分け", "",
                  "`タイプ` は `AWS::<名前空間>::` を省略した名称。番号は台帳の `open_questions` と対応する。", "",
                  "| 名前空間 | タイプ | 対応候補の番号 | 現行入力では解決不可の番号 |",
                  "| --- | --- | --- | --- |"])
    for namespace, short_type, candidate, other in rows:
        lines.append(f"| {namespace} | {short_type} | {candidate} | {other} |")
    lines.extend(["", "## 対応経路を特定した項目", "",
                  "この一覧にない対応候補は、資料または能力表の調査を先に行う。", "",
                  "| 名前空間 | タイプ | 番号 |", "| --- | --- | --- |"])
    for namespace in TIERS:
        for short_type, numbers in READY.get(namespace, {}).items():
            lines.append(f"| {namespace} | {short_type} | {', '.join(map(str, numbers))} |")
    if not ready_total:
        lines.append(f"| — | 現在なし。追加調査の{total_candidate}項目から次の実装対象を選ぶ | — |")
    lines.extend(["", "## 今回対応した項目（2026-10-03）", "",
                  "元の対応候補12項目に、専用チェック8件と宣言的ルール6件を追加し、既存のRDSログ種別ルール5件を更新した。元の番号で `VPCPeeringConnection#1`・`SpotFleet#6`・`AccessKey#3` を解決して台帳から除いた。以後の番号は現在の台帳に合わせて振り直している。",
                  "CustomerGateway、証明書のIAMロール件数、LaunchTemplateのASGプロファイルとBatch MIMEは設計内の部分を実装し、残る外部状態・未確定版を現行入力では解決不可へ移した。EC2FleetのKMS適用範囲、LaunchTemplateの共有配置・固定スキーマ差分、Volumeのインスタンス能力、RDSのエンジン版対応は追加調査側に残した。",
                  "詳細は [T1進捗](tier1-progress.md) を参照。", "",
                  "## 優先して進められる項目", "",
                  "- 対応経路を特定していた12項目に13件の専用チェックを追加した。テンプレート依存関係、設計内の証明書・SAML・インラインコード、IPAMスコープ、RDSイベント分類の確認済み一覧を扱う。各項目の残る範囲を台帳に書き直した。",
                  "- `EC2::EIP#1`：主NIC配列・NetworkInterface参照・同一テンプレートのLaunchTemplate初期版1からSubnetを解決する経路を実装した。主NICの曖昧さ、別版・外部テンプレート、既定サブネット等は入力不足として残す。",
                  "- `IAM::SAMLProvider#3`：固定した公式XSD5件によるオフライン検証と、単一issuer・SAML 2.0 IdP・署名用証明書の確認を追加した。拡張スキーマ、集約メタデータのissuer選択、署名真正性・外部IdPの信頼情報は入力不足として残す。",
                  "- 経路特定済みだった最後の2項目も、設計内の部分を実装し、残部を現行入力では解決不可へ移した。次は追加調査75項目から根拠と実装範囲を確定する。219項目の全解消・T1の実装完了を意味しない。",
                  "- 追加調査75項目のうち8タイプをAPI文書と照合し、S3ディレクトリID形式・Lambda Layer組織共有の警告、RDS認可元の必須チェックを追加した。ICMPv6ポート省略とLambda URL Qualifier省略には回帰テストを追加した。資料間の矛盾・API受理条件の未確認部分を残したため、追加調査75件・確認事項219件は維持している。詳細はT1進捗の『API文書との照合』を参照。",
                  "- `Lambda::Function#2` のランタイム・SnapStart等の能力調査は追加調査側に残した。残る9項目は入力不足・外部状態等を必要とする残部へ分類し、実装した部分と区別した。確認事項の総数219件は変えず、12件全体の解消とは扱わない。",
                  "- RDSパラメータグループの設計内Family比較と、公式例にある5ファミリーのエンジン照合は実装済み。`DBParameterGroup#2`・`DBClusterParameterGroup#2` の完全な版互換性は能力表の追加調査へ移した。`DBCluster#12` の残りは更新履歴・外部グループの情報を要する。", "",
                  "## 今回の追加調査（Client VPN）", "",
                  "- 一覧順にCapacityReservation、CapacityReservationFleet、ClientVpnEndpointをAPI資料と照合した。前2タイプの作成時条件は未確定のため保留。ClientVpnEndpointの旧#2はAPIに条件付き必須が明記されており、EC2_CLIENT_VPN_FEDERATED_AUTHENTICATION_REQUIREDを実装して解決した。残る証明書の確認は#3から#2へ移動した。",
                  f"- 現在は確認事項{total_candidate + total_other}件（追加調査{total_candidate}件・現行入力では解決不可{total_other}件）。次はCustomerGateway以降の候補を調査する。保留した先頭2タイプは、CloudFormationの作成時受理条件を示す追加根拠が得られた時点で再開する。", "",
                  "## 継続調査の結果", "",
                  "開始時の74候補を[継続調査の記録](tier1-continuation-review.md)に記録した。ParentGroupIdのcluster制限とTransitGatewayのASN範囲を解消し、CEVのKMS対称性・版名一意性は外部情報を要する残部へ移した。既存NIC、Verified Access、IAM構造、SnapStart、CEV、RDS通常作成などの部分検査を追加した。",
                  f"現在は確認事項{total_candidate + total_other}件、追加調査候補{total_candidate}件、現行入力では解決不可{total_other}件。残候補を実装完了とは扱わず、資料の曖昧さ・CFNハンドラー受理条件・能力データの不足を記録している。", "",
                  "## 解決できない理由の例", "",
                  "- 既存リソース・権限：`IAM::User#1`、`S3::AccessGrantsInstance#1`、`RDS::DBProxy#2` はAWSアカウント内の既存状態が必要。",
                  "- 実行時点・更新履歴：`Lambda::EventSourceMapping#2`、`IAM::AccessKey#2`、`EC2::PrefixList#1` は静的な作成設計だけでは判定できない。",
                  "- 外部の値・動的割当：`EC2::Volume#2` のスナップショット容量、`EC2::VPC#1` のIPAM割当結果、`RDS::DBCluster#8` のスナップショット暗号化状態は外部情報が必要。",
                  "- 公式資料の矛盾：`S3::StorageLensGroup#1` は上限が資料間で異なるため、どちらかを選んで `FAIL` にしない。", ""])
    target = ROOT / "docs/tier1-open-questions-triage.md"
    target.write_text("\n".join(lines), encoding="utf-8")
    print(f"{target}: {total_candidate} candidates, {total_other} require external information")


if __name__ == "__main__":
    main()
