# AWS Design Review — Agent / Skill distribution

AWS設計書の生成、必要入力の確認、人が登録した案件方針の照合、Checkerとcfn-lintによるローカル静的評価を行う配布候補です。バージョン0.10.0。生成成功と設計の承認は別の結果です。

## 導入

利用するホストの **aws-design-reviewフォルダー全体** をプロジェクトへ配置してください。既存のSkillや設定は上書きせず、新しい場所で確認します。

|ホスト|配置するSkill|任意のAgent|
|---|---|---|
|Claude Code|`.claude/skills/aws-design-review/`|`.claude/agents/aws-design-author.md`（書く役）・`aws-design-checker.md`（確かめる役）|
|Codex|`.agents/skills/aws-design-review/`|Skillを直接指定|
|GitHub Copilot|`.github/skills/aws-design-review/`|`.github/agents/aws-design-author.agent.md`・`aws-design-checker.agent.md`|

旧Codexの`.codex/skills`を使っている場合は新配置へ移行し、同名Skillを二重登録しないでください。ホストのバージョン・信頼設定によって実行許可が必要です。CLI検証と実ホスト呼び出しは別の証拠です。

固定依存にはPython 3.12以上（3.14.1を除く）が必要です。検証対象はWindows / Python 3.12.10。Skillフォルダーで実行します。

```powershell
& .\scripts\install.ps1
& .\.venv\Scripts\aws-design.exe bootstrap --check --all-regions
```

最初に試すときは、リポジトリ直下の[サンプル資料](samples/aoba-learning-hub/README.md)を使ってください。

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

対話できない実行では一覧を表示して停止します。`-Force`を付けると確認せずに削除します。

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
& .\.venv\Scripts\aws-design.exe bootstrap --check --all-regions
# 初回取得の再試行
& .\.venv\Scripts\aws-design.exe bootstrap --all-regions
# 一地域のみ
& .\.venv\Scripts\aws-design.exe bootstrap --check --region us-east-1
```

公式URLは最新版だけを返し、AWSは1日に複数回ZIPを作り直します。そのため取得したZIPがレビュー済みのZIPと異なっても停止せず、型ごとの差分（追加・変更・削除）を `drift.json` と manifest の `review_status: DRIFTED_FROM_REVIEWED` に記録します。差分のある型の規則は、9月29日の基準スナップショットとの照合で要再確認・隔離として扱い、レビュー済みとはみなしません。実行結果の `catalog`・`regional_catalogs` と設計書の注意事項にも、この状態と件数が出ます。一致した場合は `REVIEWED_EXACT` です。

別地域への置換、ZIPの構造検査の解除、不足スキーマを使った成功扱いはしません。生成したキャッシュは取得記録・manifest・カタログ・ルール・差分記録の整合を検証し、改ざんや破損を検出します。旧キャッシュと失敗記録は保持します。検証済みキャッシュがあれば通常生成・ローカル評価はオフラインで再実行できます。同じ版のZIPを後から取得できる保証はないため、取得したキャッシュは保持してください。

## 入力と結果

構造化入力1.0/1.1には`aws-design document`、規定の行形式には`aws-design run`、保存済みChecker中間JSONには`aws-design check`を使います。詳細は各Skillの`references/usage.md`を参照してください。Office/PDFや自由文を生成CLIへ直接渡す契約ではありません。

1.1の資源は`region`を指定でき、省略時は環境の地域を使います。CloudFrontのviewer ACM証明書とCLOUDFRONT WAFはus-east-1への限定的な参照判定を持ちます。通常の地域間参照制約は保持します。複数地域に対する単一CFNファイル比較は拒否します。明示されたDEPENDENCY接続の循環は検査しますが、スタックやデプロイ順を推測しません。

`summary.json`、`checklist.json`、`project-policy.json`、`evaluation.json`をそれぞれ確認します。1.1では`review-report.json`と`review-report.md`が実行状態・元資料の状態・未解決理由・対応機能・未検査範囲をまとめます。同じ情報を設計JSONとExcelにも保存します。

元資料状態と項目対応がある場合は`--source-trace FILE`を渡します。元のFICTIONAL_DECIDEDやNOT_RUNを正規化後のDECIDEDと混同しません。追跡データのない元資料状態は推測しません。RESOURCE_REFは対応済みで、未対応付けのsymbolは入力側の結び付け不足として報告します。APP行とAWS判定も区別します。

## 外部デザインシートの取込み（0.4.0）

ARP4で解析済みの外部Excelデザインシート（`extraction.json`・`document.yml`・承認済みの構造解釈）から、`aws-design external`で1.1入力と`source-trace.json`を作ります。ARP4は同梱しません。このツール自身もOfficeファイルを直接読みません。

作成担当のエージェントがセルIDを引用した抽出ファイルを書き、別のレビュー担当が照合して受理を記録します。対応付けの提案は利用者が指名した承認者だけが辞書へ承認します。`build`は値を抽出結果から取得し、対応表・未対応一覧・対応範囲も出力します。`import_status: COMPLETE`は変換が終わったことだけを表し、設計の承認ではありません。CodexにはAgent定義を同梱しないため、2つの役割を別セッション・別の担当名で実行します。手順は`references/usage.md`の「External design sheets parsed by ARP4」を参照してください。

## 大阪・再レビュー記録・原本の承認・外部参照値（0.5.0）

大阪リージョン（ap-northeast-3）のロックとFSxの設計書カタログを追加しました。東京で調査した型は、`rules/schema-reviews.json`にその地域の型スキーマ指紋付きのレビュー記録がある場合だけ、地域の再確認なしで引き継ぎます。`review-report.json`の`rule_review_causes`は、要確認ルールを地域適用性・スキーマ変更・既存の未解決事項に分けて数えます。

外部シートの承認欄と項目ごとのレビュー列を引用すると、その記載を`source-trace.json`と`review-report.json`の`source_review`へ転記します。本ツールの承認ではなく、空欄を承認済みと扱いません。`--external-bindings FILE`で外部参照に既知の非秘密値を与えると、型の合う値だけをローカル評価に使います。AWSには接続せず、実在や所有は確認しません。詳細は`references/usage.md`を参照してください。

0.5.1では、ARNの地域検査を加えました。バインディング値のARNがリソースと別の地域・パーティションなら評価に使いません。設計入力に直接書いたARNも`--evaluate`で`DOCUMENT_ARN_REGION`として検査します（CloudFrontの証明書・WebACLはus-east-1、バックアップの地域間コピー先などは別地域を許容）。

## 設計の進め方とレビューの省力化（0.6.0）

デザインシートを作る前の整理と、人のレビュー負担を減らす機能を加えました。各コマンドの詳細は`references/usage.md`、報告の規則は`references/reporting.md`にあります。

- `aws-design flow`：作業フォルダの状態から次の一手を返します。`run all`は人の判断が要る段階まで走査と生成を自動で進め、`people`で登録した担当者名を次の一手のコマンドに入れます。`inbox`／`decide`は保留中の判断を1つのブックに集め、まとめて記録します。
- `aws-design sources`：ARP4が解析した文書を版の系列にまとめ、利用者が指名した人が根拠にする現行版を承認します。旧版を引用した入力の生成を止め、旧版にだけある値を警告します。
- `aws-design system`：AWSリソースの上位にあるシステム概要（要件・利用者・境界・構成要素・データの流れ・非機能目標・未決事項）を記述・図示・検査し、合意を記録します。ARP4の要件正本から始められ、作成担当・レビュー担当のAgentと二重作成の照合を同梱します。
- 生成結果に、収集マトリクス（`collection-matrix.md`）、由来と優先度で人の確認範囲を絞るレビューパック（`review-pack.md`・`.xlsx`・ブラウザだけで使える`review-pack.html`）を加えました。判定は`aws-design review-pack record`／`import`で次回へ引き継ぎ、`recall`で過去のレビュー指摘に対する再現率を測れます。
- `aws-design policy-pack`：採用者を記録して標準の方針パック（同梱`aws-security-baseline`）を案件方針として加えます。`aws-design library`は承認済みの辞書項目・方針パック・概要のひな型（同梱`three-tier-web`）を案件をまたいで使います。`aws-design export`は組織のExcelテンプレートへ生成結果を書きます。
- 外部シート取込みに、承認済み辞書による決定的な候補（`suggest`）と、2つの独立した読取りの照合（`compare`）を加えました。

承認・合意・採用・判定はいずれも利用者が指名した人の名前で記録し、エージェントは判断者になりません。優先度や「完了」は作業の順序と状態であり、設計の承認ではありません。

## 判断の台帳・委任・構成図（0.6.0）

- コマンドは `aws-design` の1つにまとめました（`aws-design flow status …`、`aws-design asks …` のようにサブコマンドで使います。一覧は `aws-design --help`）。Agentは書く役の`aws-design-author`と確かめる役の`aws-design-checker`の2つにし、役割ごとの指示はSkillの`references/roles/`に置きました。人に聞くのは判断の台帳だけで、旧`aws-design-questions`は台帳に統合しました。
- `aws-design asks`：未決の設定を、項目ごとではなく判断ごとに人へ聞きます。作成担当のAgentが判断の台帳を書き、別のレビュー担当が確かめたあと、聞ける判断を順番に宛先ごとの質問票と会議の議題にし、回答を設計入力の写しへ反映します。回答は答えた人の名前でだけ記録します。
- `aws-design delegation`：人が承認した委任方針の範囲で、根拠文書セットの承認やP2行の判定などの定型の判断をエージェントに任せます。引き渡すファイルには契約があり、生成のたびにゲート（`gates.json`）が契約・根拠文書・引用の裏付けを検査します。引用の検査は、値が引用したセルにあるか（GROUNDED）、セルから換算・解釈したか（INTERPRETED）を分けて数えます。
- 1.1の生成は基本設計の文章（`basic-design.md`）とdraw.io形式の構成図（`architecture.drawio`）を出力します。構成図は宣言した配置と接続を描き、設計入力の`actors`に書いた利用者・外部システム・ツールで扱えないAWSサービスも描きます。
- 未記載の任意項目の一覧（`optional-inputs.json`）と、JSONを文字列で持つプロパティの構文検査を加えました。レビューパックは、判断が必要な行を「人の判断・その他・設計者の宿題・構築時の注意」の順に並べます。

## アカウントの配置と構成図の台帳（0.7.0）

- 1.1の設計入力にアカウント（`accounts`）を宣言し、環境・リソース・ツールで扱えないAWSサービスをアカウントに置けます。リソースには存在する環境（`environments`）を書け、ほかの環境の生成物から外れます。アカウントをまたぐ参照は `--evaluate` で要確認として示します。既存の入力はそのまま使え、生成物も変わりません。
- `architecture.drawio` はアカウントの枠を描き、アカウント・リージョン・環境が2つ以上あるときはそれぞれのページを加えます。
- `aws-design diagram`：CURRENTの文書の構成図の図形・画像・接続を、1つも落とさずに台帳にします。作成担当のAgent2つが互いに見ずに各要素へ処置（リソース・相手・枠・接続・注記・凡例・重複・グループ・対象外・未解決・画像の展開）を付け、別のレビュー担当が確かめます。文字のない画像は、ARP4で範囲をPNGに描画して読みます。読めない要素は消さずに、判断の台帳で人に確かめます。
- 生成のたびのゲートに、構成図の対比カバレッジ（`diagram-coverage.md`）を加えました。処置も対応先もない要素、複数のアイコンを1つにまとめた入力、枠と食い違うアカウント・環境・リージョン・AZ・VPC・サブネット、線の両端と合わない接続、レビューのない台帳を不合格にします。AWSサービス種類数・論理リソース数・配置実体数は別に数えます。
- 図形を引用した値は図形の文字で裏付けを確かめ、画像から読んだ値は解釈としてレビューパックで人が確かめます。設定の中に書いたリソース参照を、文書の値として探さないよう直しました。

## 大規模な資料への対応（0.8.0）

- 構成図の台帳を文書ごとに分けました（`diagrams/parts/<文書>/`）。文書ごとに2つの独立した読み取りとレビューを行い、1つの文書を読み直しても、ほかの文書のレビューはそのまま有効です。カバレッジは全文書をまとめて従来どおり照合します。0.7.0の作業フォルダ（`diagrams/ledger.json`）は、そのまま1つの台帳として使えます。
- 操作画面や説明図だけで構成を描かない文書は、要素ごとではなく文書ごとに対象外にできます（`scope: NOT_ARCHITECTURE`）。2つの読み取りとレビューが必要で、構成図らしい線やAWSの名前があれば警告します。
- `aws-design diagram preflight`：作成担当を起動する前に、文字もグラフもない画像、端の記録がない線、ARP4の構造レビューの状態、台帳の推定サイズを文書ごとに示します。
- 台帳の検査・比較は、既定で集計と先頭20件を出します（`--full`、`--output`、`--limit`、`--offset`、`--document`、`--code`）。比較は差異をMAJOR（欠落・リソース・配置・接続・相手・対象外の食い違い）とMINOR（注記などの分類）に分け、文書ごとの一致率を示します。
- 失敗した読み取りの差し替えは `aws-design diagram adopt`・`retire` で行い、差し替えた読み取りと記録（`diagram-adoption/1`）を残します。
- 上限を超えたファイルは、構文の誤りではなく `INPUT_TOO_LARGE`（大きさと上限）と報告します。台帳の上限は64,000,000バイトで、ほかのファイルは従来どおりです。
- `aws-design` の出力はすべてUTF-8です。Windows PowerShell 5.1では、先に `[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)` を実行してください。
- 長い処理の進捗（`--progress`、`AWS_DESIGN_PROGRESS=jsonl`）と、システム概要からの暫定図（`aws-design system diagram`。DRAFT・概要のハッシュ・未確定の件数入りで、正式な `architecture.drawio` とは別）を加えました。
- AZごとのサブネットに1つずつ描いた1つのリソース（2つのAZに置くECSサービスなど）は、リソースのサブネットがどの枠も含むなら、アイコンの集約として止めません。ARP4の画像のグラフで、文字のない線にはラベルを付けません。

## 文書が名指すサービスの照合（0.9.0）

- 生成のたびのゲートに `service_mentions` を加えました。承認済みのCURRENT文書のすべてのセルと図形の文字から、AWSサービスの名前（公式名と通常の略称、約100サービス）を探し、設計入力が扱っているかを照合します。対応する型のリソースか、そのサービスを指すツールで扱えないAWSサービスの相手があればIN_DESIGN、設定などがそのセルを引用していればCITED、要件・運用・課題・判断の注記がそのセルを引用していればNOTED、どれでもなければNOT_IN_DESIGNとして不合格にします。結果は `runs/NNN/service-mentions.md`・`.json` に出ます。
- 不合格の行は、リソースか相手として入力に加えるか、該当のセルを引用する注記で作らない理由を書くか、人に聞く判断にします。合格させるためだけに、文書が決めていないリソースを足さないでください。既存の作業フォルダも、この照合で不合格になることがあります。
- 名前の辞書による照合で、辞書にないサービスや名前を書かない記述は見つけません。「監査ログ」「暗号鍵」などの役割語は手掛かりとして示すだけで、合否に使いません。報告はサービス名・文書ID・セルIDだけを持ち、セルの文字を写しません。
- 根拠文書セットの判定で、課題管理・検討メモ・作業用・製品資料・キャプチャを示す文書を、参考資料の候補（POSSIBLY_REFERENCE）として承認者に示すようにしました。議事録は従来どおりCURRENTの候補です。

## 下書きモード（0.10.0）

- 新しい作業フォルダ（`aws-design flow init`）は下書きモードで始まり、下書きが出るまで人に何も聞きません。`aws-design flow run all` が、未決の文書を規則で仮に決め（提案書・退避フォルダだけの文書はREFERENCE、版の新旧が分からない系列はどれもCURRENT、ARP4で問題のある文書はEXCLUDED）、方針パックを未採用の候補として当て、画像を仕分け、各役割を1回ずつ動かして、最後に `runs/NNN/draft-report.md` を書きます。仮の決定は `agent:aws-design flow draft` の名前と下書きの印で記録され、承認ではありません。
- 文書ごとに種類と関連度（PRIMARY／PERIPHERAL）が付きます。PERIPHERALの文書（画面・帳票・テーブル・計画書など）について、根拠か参考かを人に聞きません。
- 画像は段階的に仕分けます（`diagrams/triage.json`、契約 `diagram-triage/1`）。文字のある画像・ARP4で読み取り済みの画像・小さい画像（アイコン・ロゴ）・重複は機械で外し、残りを役割 `diagram-triager` が1枚1回だけ見ます。要素ごとに読むのは構成を描く文書だけで、読み手は1人です。
- 判断の台帳は検査を通れば質問票になり、独立レビューは確定モードで行います。ゲートは契約と生成の失敗のときだけ止まり、レビューパックの判定は確定モードで行います。
- `aws-design flow mode --workspace WS --set final` で確定モードに切り替えると、仮の文書セットと候補の方針入力は `*.draft.json` へ退き、承認者・採用者の判断待ちになります。`mode` のない既存の `flow.json` は確定モードのままです。確定モードで始めるには `flow init --mode final` とします。
- 設計入力が自分の規則で拒まれたとき、`contract validate` と生成の STRUCTURE_ERROR が、どのIDが原因か（重複したID、知らない参照・アカウント、端のない線など）を示すようになりました。示すのはIDだけで、設定値は写しません。

## サンプル資料

`samples/aoba-learning-hub/` に、架空案件「あおばラーニングハブ」の設計資料（要件定義・基本設計・議事録・提案書のWord文書9ファイル。作成は架空の「ミナトクラウド設計合同会社」）があります。資料の読み取りにはARP4（別配布）が要ります。試し方は[サンプルのREADME](samples/aoba-learning-hub/README.md)を参照してください。回答や採点の仕組みは同梱していません。

## 範囲とデータ

ゼロ終了やGENERATED/COMPLETEは設計全体の承認ではありません。FAIL・要確認・未登録要件・未検査条件を個別に確認してください。CLI結果だけでは実ホスト受入を証明できません。物理IDや秘密参照は取得せず、AWS実環境は変更しません。

秘密値ではなく秘密参照を入力してください。出力には設計値や出典が含まれるため、指定した保存先で管理します。任意の`-Llm`は別途Anthropic認証を必要とし、入力を外部APIへ送信します。既定では利用しません。

各ホストのSkillは、許可リストにある実行コード、ルール、ロック、操作文書です。テストと例は含めません。リポジトリ直下には架空のサンプル資料（Word文書）を1組だけ置きます。開発Git履歴、評価証跡、実案件の資料、キャッシュ、認証情報は含めません。3ホストのSkill内容は同一で、`release-manifest.json`にSkillとルートのファイルのハッシュを記録します。

## ライセンス

コードは[MIT](LICENSE)。第三者資料は[出典とライセンス案内](THIRD_PARTY_NOTICES.md)に従います。
