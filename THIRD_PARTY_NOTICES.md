# Third-party materials

The project's MIT license covers its own code. It does not relicense the following materials or installed dependencies. Source files and pre-existing notices are retained without modification. Schema paths below are relative to each host's `skills/aws-design-review` directory; notice texts are also provided at the distribution repository root.

## CloudFormation provider schemas — acquired by the user

No CloudFormation schema ZIP, unpacked provider schema, generated documentation catalog or generated input-schema JSON is included in this release. The setup tool obtains the reviewed archive directly from [AWS's official Tokyo-region download](https://schema.cloudformation.ap-northeast-1.amazonaws.com/CloudformationSchema.zip), documented in the [resource provider schemas guide](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/resource-type-schemas.html). This public download does not prompt for an AWS account or an additional click-through agreement.

`schemas/schema-lock.json` records source, region, reviewed time, tool version and expected hash. Each user's local manifest records the actual retrieval time and hash. Generated provider-dependent catalogs remain in the local ignored cache. This project does not claim ownership of or relicense AWS materials. Their use remains subject to the applicable [AWS terms](https://aws.amazon.com/legal/aws-ip-license-terms/). The acquisition design avoids assuming redistribution permission for the archive; it is not legal advice about all possible uses.

The active public tree removes the previously bundled archive and provider-derived catalogs. Earlier public Git commits may still contain them. This release does not rewrite that history. Author-written checks and source-attributed rule evidence retain their original references; the project's MIT license does not relicense third-party quotations.

## OASIS SAML 2.0 schemas

`schemas/saml/saml-schema-assertion-2.0.xsd` and `saml-schema-metadata-2.0.xsd` are unchanged OASIS SAML 2.0 schema files from [the official specification directory](https://docs.oasis-open.org/security/saml/v2.0/). Copyright © OASIS Open 2005. All Rights Reserved.

The specification's copying notice is reproduced in [OASIS-SAML-2.0-NOTICE.txt](licenses/OASIS-SAML-2.0-NOTICE.txt). Its conditions and disclaimers remain applicable; this project claims neither ownership of the schemas nor approval by OASIS. The per-file source URLs and hashes remain in `schemas/saml/manifest.json`.

## W3C XML schemas

`schemas/saml/xmldsig-core-schema.xsd`, `xenc-schema.xsd`, and `xml.xsd` are unchanged files obtained from W3C. Copyright belongs to W3C and the copyright holders identified in the original files; the original XML Signature copyright and license link are retained.

Source URLs and hashes are recorded in `schemas/saml/manifest.json`. The [1998 notice](licenses/W3C-1998.txt) explicitly linked by the XML Signature schema, the [2002 notice](licenses/W3C-2002.txt), and the [current software/document notice](licenses/W3C-2023.txt) are included for users. No stored schema bytes were modified. The XML parser's in-memory handling of the original assertion encoding does not overwrite the source file. These files are not relicensed under the project's MIT license.

## Installed Python dependencies

Python dependencies are downloaded separately from the official PyPI registry, not vendored into this repository. Their own licenses and notices ship in their installed distributions. `requirements.lock` records the tested core and test versions, including cfn-lint 1.57.2 (MIT-0), Pydantic, openpyxl, cryptography, lxml, regex, PyYAML and their dependencies. Optional Anthropic extraction is separate and was not tested. Installing a dependency does not grant permission to redistribute unrelated AWS download archives.

## Excluded material

Developer evaluation corpora, third-party public-template corpora, full fictional project dossiers, Office/PDF files, Library delivery records, generated findings, old archives and development Git history are not part of this minimal release. Their existing development records remain outside the distribution.
