# AWS Design Review — Agent / Skill distribution

AWS設計書の生成、必要入力の確認、人が登録した案件方針の照合、Checkerとcfn-lintによるローカル静的評価を行う配布候補です。バージョン0.5.1。生成成功と設計の承認は別の結果です。

## 導入

利用するホストの **aws-design-reviewフォルダー全体** をプロジェクトへ配置してください。既存のSkillや設定は上書きせず、新しい場所で確認します。

|ホスト|配置するSkill|任意のAgent|
|---|---|---|
|Claude Code|`.claude/skills/aws-design-review/`|`.claude/agents/aws-design-review.md`、外部シート取込み用の`aws-sheet-extract-worker.md`・`aws-sheet-extract-reviewer.md`|
|Codex|`.agents/skills/aws-design-review/`|Skillを直接指定|
|GitHub Copilot|`.github/skills/aws-design-review/`|`.github/agents/aws-design-review.agent.md`、`aws-sheet-extract-worker.agent.md`・`aws-sheet-extract-reviewer.agent.md`|

旧Codexの`.codex/skills`を使っている場合は新配置へ移行し、同名Skillを二重登録しないでください。ホストのバージョン・信頼設定によって実行許可が必要です。CLI検証と実ホスト呼び出しは別の証拠です。

固定依存にはPython 3.12以上（3.14.1を除く）が必要です。検証対象はWindows / Python 3.12.10。Skillフォルダーで実行します。

```powershell
& .\scripts\install.ps1
& .\.venv\Scripts\aws-design-document.exe .\examples\project-policies\design.json --environment prod --output .\output\first-review --evaluate
```

インストーラーは新しい`.venv`を作り、PyPIから固定制約付き依存を取得します。導入前に旧版を一覧表示し、確認してから削除します。対象は次の3つです。

- このコピーの既存の`.venv`
- 同じプロジェクトと利用者プロファイルの`.claude`・`.agents`・`.github`・旧`.codex`の`skills/aws-design-review`のうち、導入する版より古いもの。同じ版・新しい版・版が読めないものは表示だけして残します。
- 導入に使うPythonへ入っている`aws-design-sheet`

フォルダーはWindowsのごみ箱へ移します。そのコピーのスキーマキャッシュも一緒に移るため、新しいコピーは公式URLから現在のZIPを取得します。Pythonのパッケージは`pip uninstall`で削除するため、ごみ箱からは戻せません（編集可能インストールの元フォルダーは残ります）。

次の場合は何も変更せずに停止します。

- 確認に「いいえ」と答えた
- フォルダーがごみ箱のないドライブ（ネットワーク上など）にある
- フォルダーがごみ箱の容量を超える
- 使用するPythonが削除対象の中にある

対話できない実行では一覧を表示して停止します。`-Force`を付けると確認せずに削除します。テストも行う場合は`-Tests`を指定します。

Linux/macOSでは`python3 -m venv .venv`、`.venv/bin/python -m pip --isolated install --index-url https://pypi.org/simple -c requirements.lock -e .`、`.venv/bin/python -m aws_design_sheet.schema_bootstrap --all-regions`の順です。この候補の実行検証環境はWindowsです。

## 地域別スキーマの取得

初回はネット接続が必要です。東京・大阪・us-east-1のCloudFormationスキーマを、それぞれAWS公式の公開URLから取得します。AWS資格情報やアカウント操作は不要です。ZIPと生成カタログは配布に含めません。

|地域|ロック|レビュー済み公式ZIPのSHA-256|生成カタログ（レビュー時）|
|---|---|---|---|
|ap-northeast-1|`schemas/schema-lock.json`|`7b9cb45a40a8d508d60bfa09247d334307dcbb705f620a860d6ea0a04cfcbc62`|52サービス・618型・4125上位プロパティ|
|ap-northeast-3|`schemas/schema-lock.ap-northeast-3.json`|`160a73341ff37926f2dfc96262f7ced8d6939d13c625844dcaab8795a4fc6c7b`|52サービス・596型・4003上位プロパティ|
|us-east-1|`schemas/schema-lock.us-east-1.json`|`6083e23a0701c379f90ec2c6bd382ee79e99cb472018460d0645c35aeee98553`|52サービス・648型・4250上位プロパティ|

従来の50サービスを維持してCognitoとFSx（ファイルシステム・SVM・ボリュームなど）を追加しました。件数は生成対象であり、AWS全条件の評価完了を表しません。東京の調査済み判定は、他地域ではそのまま流用しません。大阪では、型スキーマが調査時の東京と同一で、ルール・参照・検査・未解決事項に地域の記述がない687型だけを、`rules/schema-reviews.json` のレビュー記録により引き継ぎます。それ以外の型とus-east-1では、地域適用性の再確認を残します。FSxの共有（SMB共有など）はCloudFormationのリソース型がないため、拡張項目として扱います。

インストーラーは`--all-regions`を実行します。キャッシュは`schemas/.cache/<region>/<ZIP SHA-256>/<lock SHA-256>/`に分離し、取得記録、manifest、カタログ、ルール、変更記録を検証します。

```powershell
# ネット接続なしで全地域を検証
& .\.venv\Scripts\aws-design-bootstrap.exe --check --all-regions
# 初回取得の再試行
& .\.venv\Scripts\aws-design-bootstrap.exe --all-regions
# 一地域のみ
& .\.venv\Scripts\aws-design-bootstrap.exe --check --region us-east-1
```

公式URLは最新版だけを返し、AWSは1日に複数回ZIPを作り直します。そのため取得したZIPがレビュー済みのZIPと異なっても停止せず、型ごとの差分（追加・変更・削除）を `drift.json` と manifest の `review_status: DRIFTED_FROM_REVIEWED` に記録します。差分のある型の規則は、9月29日の基準スナップショットとの照合で要再確認・隔離として扱い、レビュー済みとはみなしません。実行結果の `catalog`・`regional_catalogs` と設計書の注意事項にも、この状態と件数が出ます。一致した場合は `REVIEWED_EXACT` です。

別地域への置換、ZIPの構造検査の解除、不足スキーマを使った成功扱いはしません。生成したキャッシュは取得記録・manifest・カタログ・ルール・差分記録の整合を検証し、改ざんや破損を検出します。旧キャッシュと失敗記録は保持します。検証済みキャッシュがあれば通常生成・ローカル評価はオフラインで再実行できます。同じ版のZIPを後から取得できる保証はないため、取得したキャッシュは保持してください。

## 入力と結果

構造化入力1.0/1.1には`aws-design-document`、規定の行形式には`aws-design-run`、保存済みChecker中間JSONには`aws-design-check`を使います。詳細は各Skillの`references/usage.md`を参照してください。Office/PDFや自由文を生成CLIへ直接渡す契約ではありません。

1.1の資源は`region`を指定でき、省略時は環境の地域を使います。CloudFrontのviewer ACM証明書とCLOUDFRONT WAFはus-east-1への限定的な参照判定を持ちます。通常の地域間参照制約は保持します。複数地域に対する単一CFNファイル比較は拒否します。明示されたDEPENDENCY接続の循環は検査しますが、スタックやデプロイ順を推測しません。

`summary.json`、`checklist.json`、`project-policy.json`、`evaluation.json`をそれぞれ確認します。1.1では`review-report.json`と`review-report.md`が実行状態・元資料の状態・未解決理由・対応機能・未検査範囲をまとめます。同じ情報を設計JSONとExcelにも保存します。

元資料状態と項目対応がある場合は`--source-trace FILE`を渡します。元のFICTIONAL_DECIDEDやNOT_RUNを正規化後のDECIDEDと混同しません。追跡データのない元資料状態は推測しません。RESOURCE_REFは対応済みで、未対応付けのsymbolは入力側の結び付け不足として報告します。APP行とAWS判定も区別します。

## 外部デザインシートの取込み（0.4.0）

ARP4で解析済みの外部Excelデザインシート（`extraction.json`・`document.yml`・承認済みの構造解釈）から、`aws-design-external`で1.1入力と`source-trace.json`を作ります。ARP4は同梱しません。このツール自身もOfficeファイルを直接読みません。

作成担当のエージェントがセルIDを引用した抽出ファイルを書き、別のレビュー担当が照合して受理を記録します。対応付けの提案は利用者が指名した承認者だけが辞書へ承認します。`build`は値を抽出結果から取得し、対応表・未対応一覧・対応範囲も出力します。`import_status: COMPLETE`は変換が終わったことだけを表し、設計の承認ではありません。CodexにはAgent定義を同梱しないため、2つの役割を別セッション・別の担当名で実行します。手順は`references/usage.md`の「External design sheets parsed by ARP4」を参照してください。

## 大阪・再レビュー記録・原本の承認・外部参照値（0.5.0）

大阪リージョン（ap-northeast-3）のロックとFSxの設計書カタログを追加しました。東京で調査した型は、`rules/schema-reviews.json`にその地域の型スキーマ指紋付きのレビュー記録がある場合だけ、地域の再確認なしで引き継ぎます。`review-report.json`の`rule_review_causes`は、要確認ルールを地域適用性・スキーマ変更・既存の未解決事項に分けて数えます。

外部シートの承認欄と項目ごとのレビュー列を引用すると、その記載を`source-trace.json`と`review-report.json`の`source_review`へ転記します。本ツールの承認ではなく、空欄を承認済みと扱いません。`--external-bindings FILE`で外部参照に既知の非秘密値を与えると、型の合う値だけをローカル評価に使います。AWSには接続せず、実在や所有は確認しません。詳細は`references/usage.md`を参照してください。

0.5.1では、ARNの地域検査を加えました。バインディング値のARNがリソースと別の地域・パーティションなら評価に使いません。設計入力に直接書いたARNも`--evaluate`で`DOCUMENT_ARN_REGION`として検査します（CloudFrontの証明書・WebACLはus-east-1、バックアップの地域間コピー先などは別地域を許容）。

## 範囲とデータ

ゼロ終了やGENERATED/COMPLETEは設計全体の承認ではありません。FAIL・要確認・未登録要件・未検査条件を個別に確認してください。CLI結果だけでは実ホスト受入を証明できません。物理IDや秘密参照は取得せず、AWS実環境は変更しません。

秘密値ではなく秘密参照を入力してください。出力には設計値や出典が含まれるため、指定した保存先で管理します。任意の`-Llm`は別途Anthropic認証を必要とし、入力を外部APIへ送信します。既定では利用しません。

配布物は許可リストにある実行コード、ルール、ロック、小規模な架空例、関連テスト、操作文書です。開発Git履歴、大量の評価証跡、案件の全文資料、Officeファイル、キャッシュ、認証情報は含めません。例外として、外部シート取込みのテストが原本のハッシュ照合に使う架空のブック`examples/external-sheet/source/sample-design.xlsx`（試験用の偽パスワード入り）を同梱します。3ホストのSkill内容は同一で、`release-manifest.json`にハッシュを記録します。

## ライセンス

コードは[MIT](LICENSE)。第三者資料は[出典とライセンス案内](THIRD_PARTY_NOTICES.md)に従います。
