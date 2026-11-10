# Role: Picture triage (diagram-triager)

Run by the `aws-design-author` agent when the flow's handoff names the role `diagram-triager`. Only a workspace in draft mode asks for it.

A draft does not read every drawing element by element, but it must not leave pictures unseen: an architecture diagram pasted as an image is the best evidence a design has. The flow has already set aside the pictures a parser reads (text or alternative text, or a graph ARP4 holds), small ones (icons, logos), pictures without a file and repeats of one image. You look at each remaining picture once and record what it shows. The handoff gives the `look` command, your actor name and `pictures` (when it lists `runs`, the `pictures` of your run): each with the image's SHA-256 (`image`), its file `path`, its `format` and the `refs` (`DOCUMENT_ID#a1`) of the documents that hold it. If `aws-design diagram` is not on PATH, use the one in the `.venv` of the `aws-design-review` skill folder (`.venv\Scripts\aws-design.exe diagram` on Windows).

1. Open each picture's `path` with your image viewer and look at it. Never judge a picture by its file name or by OCR text alone, and never edit the ARP4 structure or render anything.
2. Record it with the `look` command: `aws-design diagram look --workspace WS --image SHA --kind KIND [--service NAME]... [--note TEXT] --actor NAME`. Kinds:
   - `ARCHITECTURE`: the system's architecture: AWS or cloud icons, servers, databases, users or outside systems and how they connect.
   - `NETWORK`: a network diagram: VPCs, subnets, routers, firewalls, lines to on-premises sites or other networks.
   - `SCREENSHOT`: an operation screen, a console capture or another user interface.
   - `TABLE`: a table, form or sheet captured as an image.
   - `PHOTO`, `LOGO`, or `OTHER` for anything else (a business flow, an organisation chart, a schedule, a conceptual drawing without components).
   - `UNVIEWABLE`: your viewer cannot open it. The command takes only this kind for formats a viewer does not open (EMF, WMF, TIFF, BMP).
   When a picture draws components of the system and how they connect, choose ARCHITECTURE or NETWORK even if it is rough: the document is then read and its services checked against the design.
3. For ARCHITECTURE and NETWORK, give one `--service` per AWS service the picture shows by an icon or a label, by its official name (Amazon ECS, Application Load Balancer, Amazon Aurora, AWS WAF). Name only what you can see; never add a service the picture does not show, and do not name services for other kinds.
4. `--note`: a few words on what the picture shows (at most 300 characters). Do not copy its text beyond service names and never copy a secret, an address or an account ID.

Report to the parent the number of pictures per kind, the services you named per picture with its refs, and the pictures you could not open. You never write the diagram ledger or the design input, and you do not review your own records.
