# サンプル：あおばラーニングハブ（架空案件）

このツールを試すための、架空案件の設計資料一式です。社会人向けオンライン講座「あおば講座」を自社サーバーから AWS へ移す案件で、架空の発注者「あおば人材開発財団」と受注者「ミナトクラウド設計合同会社」が作った体裁の Word 文書です。

**組織・会議・決定・提案はすべて創作です。実在の案件・承認・契約を表しません。資料どおりに AWS へ構築できることも確かめていません。**

## 資料

| フォルダ | ファイル | 内容 |
| --- | --- | --- |
| `docs/01_要件定義/` | `requirements-1.0.docx`、`requirements-draft-0.9.docx` | 要件定義書の2つの版 |
| `docs/02_基本設計/` | `basic-design-0.3.docx`、`basic-design-draft-0.2.docx` | 基本設計書の2つの版 |
| `docs/03_議事録/` | `minutes-2026-09-03.docx`、`minutes-2026-10-01.docx`、`minutes-2026-10-15.docx` | 定例会議の議事録3回（認証、データ・冗長化・DR、バッチ・運用） |
| `docs/00_参考/` | `proposal-2026-06-15.docx` | 受注前の提案書 |
| `docs/old/` | `basic-design-draft-0.2.docx` | 退避フォルダに残ったコピー |

構成は、2つの AZ による冗長化、Cognito の2つのユーザープールと法人の SAML 連携、CloudFront と WAF、ECS on Fargate、Aurora PostgreSQL・ElastiCache・DynamoDB、EventBridge Scheduler と Lambda のバッチ、Step Functions と MediaConvert の動画変換、大阪リージョンへのバックアップコピーです。

実際の案件と同じく、資料はすべてを書いていません。資料から決まる設定のほかに、未決の事項、空欄、文書どうしの食い違い、外部から受け取る値が含まれます。旧版のドラフトや提案書、退避フォルダのコピーも現行版と並んでいます。エージェントがこれらを推測で埋めずに人へ挙げるか、旧版や提案書の値を使わないかが試しどころです。回答や採点の仕組みは同梱していません。

## 試し方

1. 試すプロジェクトのフォルダを作り、使うホストの Skill（Claude Code なら `.claude/skills/aws-design-review/` と `.claude/agents/`）を置いて、Skill フォルダで `scripts/install.ps1` を実行します（リポジトリ直下の README を参照）。
2. このツールは Word を直接読みません。資料の読み取りには ARP4（[livingforge/ai-ready-pipeline4](https://github.com/livingforge/ai-ready-pipeline4)、別配布）を使います。ARP4 を導入し、このフォルダの `docs/` をプロジェクトの `docs/` へコピーして取り込みます。

   ```powershell
   arp4 documents import docs --root . --adopt
   ```

3. 作業フォルダを作ります（`aws-design` は Skill の `.venv\Scripts` にあります）。

   ```powershell
   aws-design flow init --workspace work --environment prod --arp-root <プロジェクトのフォルダ>
   ```

4. エージェントに「aws-design-review スキルで、docs の資料から AWS の設計書を作りたい。作業フォルダは work」と頼みます。作業フォルダは下書きモードで始まり、下書きが出るまで人に何も聞きません。最初に `work/runs/NNN/draft-report.md`（下書きの報告：仮に決めた文書、見ていない画像、不合格のゲート、人への質問）を読んでください。
5. 確定まで進めるときは「確定モードにして」と頼みます（`aws-design flow mode --workspace work --set final`）。根拠文書の承認や回答の記録を求められたら、記録する人の名前を伝えてください。エージェントは自分の名前で承認しません。

生成物は `work/runs/NNN/` に出ます。設計書（`design.xlsx` とサービス別のブック）、基本設計の文章（`basic-design.md`）、構成図（`architecture.drawio`）、レビューパック（`review-pack.html`・`.xlsx`）です。未決の判断は `work/asks/` の質問票になります。

AWS へのデプロイやアカウントの操作は行いません。資料と生成物はこのフォルダの外へ送られません。ただし Claude Code などのエージェントに頼んだ場合は、その会話の範囲でエージェントの提供元に送られます。
