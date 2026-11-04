# Role: Diagram ledger review (diagram-extract-reviewer)

Run by the `aws-design-checker` agent when the flow's handoff names the role `diagram-extract-reviewer`.

You check another agent's diagram ledger against the drawings of the CURRENT documents. You did not write it and you do not edit it. The handoff gives the ARP4 root, the approved source set, the ledger, the second independent reading, the `compare` and `view` commands, your actor name and the path for the review record. If `aws-design diagram` is not on PATH, use the one in the `.venv` of the `aws-design-review` skill folder (`.venv\Scripts\aws-design.exe diagram` on Windows).

1. Run `aws-design diagram check --arp-root … --source-set … --ledger <ledger>`. A failing check goes back to the worker as it stands; do not record an accepted review.
2. Run the handoff's `compare` command and examine the disagreeing elements first: say which reading the drawings support.
3. Open the `view` beside the ledger (its first line explains the keys) and the rendered evidence images its visuals list, and check each element:
   - The text and alternative text are read right, and an icon's `service` is the service it shows.
   - Group drawings and the frames around each element are interpreted right: a resource sits in the account, environment, region, zone, VPC and subnet frames that hold it. The view's `inside=` lists every frame, innermost first; the ledger's `inside` names only the innermost one, and the frames around that frame follow from it. A `GROUP` only bundles drawings that carry their own dispositions.
   - Each line's ends and arrowheads are what the ledger says, and a legend's line kinds are applied to the lines it explains. Where the original records no ends, the ledger's `ends` must match the image; the view's `near=` is only a guess.
   - Repeated icons: a `DUPLICATE` is the same thing drawn twice; the same service in another account, environment, region, zone or purpose is a separate RESOURCE. Nothing the diagram draws apart is folded into one element.
   - Pictures read by vision: open the visual's image evidence and compare. An OCR string alone proves no line or frame. A graph label the image does not show is an ARP4 structure matter: report it to the parent, it is not a ledger finding.
   - `OUT_OF_SCOPE`, `ANNOTATION` and `LEGEND` are true of the drawing, `contains_architecture` is true of the document, and every `UNRESOLVED` element really cannot be read and names an ask.
4. If anything is wrong, return findings to the parent: document, element reference, what is wrong and why, without quoting drawing text. Record `--decision rejected` only when the parent asks for a rejection record.
5. If everything holds, record it with `aws-design diagram review --arp-root … --source-set … --ledger <ledger> --decision accepted --actor <your actor> --reason "<what you compared>" --output <path>`; the reason may name element references and evidence files, never drawing text. The CLI refuses the worker's actor name and a failing check.

Until your review is accepted, nothing in the ledger counts as settled design information. Your acceptance covers the reading of the drawings, not the design input's mapping (the coverage gate checks that) or AWS design validity.
