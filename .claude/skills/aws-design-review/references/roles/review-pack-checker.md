# Role: Review pack P2 verdicts (review-pack-checker)

Run by the `aws-design-checker` agent when the flow's handoff names the role `review-pack-checker`.

You check, row by row, whether a generated design value matches the document it cites. Several reviewers do the same packet independently; the flow records OK only for rows every reviewer passed and sends everything else to a person. Some rows were planted with a value that contradicts their own evidence; a reviewer who passes one is void for the whole packet, so judge every row from its source, never from its look, position or neighbours.

The handoff gives the packet path (`runs/NNN/agent-review/packet.json`), the ARP4 root, the approved source set, your actor name, your model name and the output path (`verdicts-<your actor>.json` in the same folder). If the CLI is not on PATH, use the one in the `.venv` of the `aws-design-review` skill folder. Do not read other reviewers' verdict files, and do not look for the packet's key: it is not yours to read and the guard refuses it.

1. Run `aws-design contract schema --kind agent-verdicts` for the output contract and read the packet's `instructions`.
2. For each row, open the cited place (`evidence_at`, `documents`) in the CURRENT documents only (`aws-design sources show --source-set …`; read ARP4 parses, for example `arp4 documents extraction-read`). Never use SUPERSEDED or EXCLUDED documents.
3. `OK` only when the cited text states this exact value for this resource and property (same number and unit, same CIDR, same word, or a conversion the row's evidence itself shows). Otherwise `NG`: a different value, a value the source does not state, a source you cannot open, or any doubt. An NG is not a failure of yours; it sends the row to a person.
4. Give every row a `reason` that names what you compared (cell or section, and why it matches or not) and list the places in `checked`. Do not copy secret values into any text.
5. Write the file with `contract: agent-verdicts/1`, the packet's sha256 as `packet_sha256` (`certutil -hashfile <packet> SHA256` or `python -c "import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" <packet>`), your `actor` and `model`, and one verdict per packet row. Run `aws-design contract validate <your file>` until it passes.

Report to the parent: the output path, the counts of OK and NG, and for each NG its key and reason. Do not run `aws-design flow run all`, record review decisions, or change the design input; the flow agrees the verdicts itself.
