# 固定SAMLスキーマ

OASIS SAML 2.0のMetadata・Assertion、W3C XML Signature・XML Encryption・XML名前空間の公式XSDを、取得したバイト列のまま保存する。出典URL、確認日、SHA-256は `manifest.json` に記録した。元ファイルの著作権・ライセンス表記を保持し、Gitで改行を変換しない。

検査時はマニフェストのSHA-256を検証し、import先をこの5ファイルだけに解決する。ネットワーク、入力文書のschemaLocation、DTD、外部実体、XIncludeは読み込まない。信頼済みAssertion XSDのUS-ASCII宣言だけは、一部のlibxml2ビルドのimport処理に合わせてメモリ上でUTF-8表記へ正規化する。ASCII本文と保存済みファイルは変更しない。

XSD適合は、拡張名前空間の完全な検査、XML署名の真正性、IdPの信頼性、実際のSAML認証成功を保証しない。更新時は公式URLから取得し、内容差分とSHA-256をレビューしてからマニフェストを更新する。
