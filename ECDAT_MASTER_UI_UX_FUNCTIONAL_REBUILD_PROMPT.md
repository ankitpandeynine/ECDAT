# ECDAT — MASTER UI/UX + FUNCTIONALITY REBUILD PROMPT

## Purpose

Use this prompt together with `ECDAT_ANTIGRAVITY_COMPLETE_BUILD_PROMPT.md`.

The previous specification defines the product, architecture, evidence model, scanners, Crypto Asset Graph, quantum risk, migration, verification, Secure Archive Lab, APIs, security and testing.

This document is the correction/rebuild directive for the CURRENT implementation shown in the supplied screenshots. Do not merely restyle it. Audit the real repository, fix data integrity and broken functionality first, then rebuild the UI/UX around the real ECDAT workflow.

---

# 1. CURRENT PROBLEMS TO FIX

The current application already has a strong shell and many useful sections, but it currently feels like a collection of static security panels rather than a finished product.

Observed problems:

- too much unused black space on most pages
- repeated basic rectangular cards
- weak information hierarchy
- not enough data visualization
- several screens are visually empty
- scan failures do not explain the real cause
- core scanners/analysis paths are failing or incomplete
- UI appears to contain populated demo findings even when real project counters show 0
- graph shows `0 Nodes / 8 Edges` and relationship data despite no discovered assets
- dashboard action queue can show specific RSA/PQC recommendations when the real project has no assets
- migration planner can show populated workstreams without current scan-backed inventory
- asset inventory does not guide the user well when empty
- CBOM/report pages are too bare
- Secure Archive Lab needs a complete workflow
- graph is represented more like relationship cards than a real interactive graph
- Quantum Risk is mostly a static table and needs meaningful visual analytics
- Blast Radius is mostly a list and needs graph/path visualization
- Verification is too thin and needs a real before/after comparison surface
- many buttons must be traced all the way from UI -> API -> backend -> persistence -> UI

The most important correction is DATA INTEGRITY:

A real project with no scan results must never display demo findings.

Real project with no data:
- 0 assets
- no risk findings
- no migration recommendations
- no action queue items
- no populated graph
- no fake relationships

Demo project:
- may contain controlled data
- must be clearly labeled DEMO DATA
- must use the same real application pipelines, APIs and components as a real project

Never mix demo state with real project state.

---

# 2. PRODUCT EXPERIENCE

ECDAT should feel like a premium enterprise cybersecurity command center.

Desired qualities:

- professional
- technical
- calm
- precise
- information-dense
- trustworthy
- minimal
- modern
- visually polished

Avoid:

- excessive neon
- sci-fi decoration everywhere
- huge empty black areas
- over-sized cards
- meaningless gradients
- constant glow/pulse animation
- random decorative charts
- fake metrics
- fake system telemetry

Use restrained texture/depth:

- subtle surface-tone variation
- thin borders
- soft shadows
- tiny highlight lines
- optional very subtle grid/noise texture
- clear selected/focused states

The UI should feel sophisticated without becoming visually noisy.

---

# 3. DESIGN SYSTEM

Create a centralized design system instead of styling each page independently.

## Surfaces

Use a small hierarchy:

1. application background
2. sidebar surface
3. primary panel
4. elevated panel

Do not make all surfaces exactly identical.

## Typography

Use clean technical sans-serif typography.

Use monospace for:

- hashes
- UUIDs
- file paths
- source locations
- algorithm IDs
- API routes
- logs
- cryptographic parameters

## Color semantics

Primary:
cyan/blue

Severity:
- critical: red
- high: orange/red
- medium: amber
- low: blue/green-neutral
- verified: green
- unknown/inconclusive: muted gray

Do not use severity colors as decoration.

## Spacing

Use a consistent spacing system. Reduce the current excessive vertical gaps.

Recommended:
- comfortable page padding
- compact controls
- medium-density cards
- strong horizontal alignment
- 2-column/3-column layouts when content supports them

If little data exists, do not stretch the content; provide a useful empty state and next action.

---

# 4. GLOBAL APPLICATION SHELL

Top bar:

- ECDAT logo/name
- organization
- current project
- environment
- global search
- notifications
- theme
- profile

Example context:

`ECDAT / Acme Security / Payment Infrastructure / PRODUCTION`

Sidebar should be grouped rather than a flat 15-item list.

## OVERVIEW
- Executive Overview

## DISCOVER
- Scan Studio
- Scan Jobs

## INVENTORY
- Asset Inventory
- Evidence Explorer
- Crypto Graph

## ASSESS
- Quantum Risk
- Mosca & HNDL
- Crypto Agility
- Blast Radius

## MIGRATE
- Migration Planner
- Closed-Loop Verify

## OUTPUT
- CycloneDX CBOM
- Report Center

## SPECIAL
- Secure Archive Lab
- Knowledge Base

## PROJECT
- Project Settings

Only show live count badges when a real count exists. Do not put `0` badges everywhere.

---

# 5. DASHBOARD / EXECUTIVE OVERVIEW

The dashboard must answer in seconds:

- What crypto exists?
- What is risky?
- What matters?
- What needs action?
- What has changed?
- What is verified?

Header:

- project name
- environment
- criticality
- data sensitivity
- last scan
- freshness
- primary CTA: `Run Discovery`
- secondary actions: `Import Asset`, `View Latest Scan`

## KPI row

Show real values only:

- Crypto Assets
- Quantum-Relevant
- HNDL-Relevant
- Migration Required
- Unknown/Unresolved
- Verified Changes

If no historical scan exists, do not fake trends.

## Risk visualizations

Two-column section:

LEFT: Risk Distribution

RIGHT: Algorithm Family Distribution

Use real charts.

## Discovery coverage

Show:

Source
Dependencies
Binary
Firmware
Certificates
Network
Archive
Runtime
PCAP

For each:
- scanned
- not scanned
- unsupported
- unknown

## Migration readiness

Show:
- total crypto assets
- quantum-relevant
- PQC/hybrid capable
- migration required
- verified

Use stacked bars/donut/status chart only from real data.

## Evidence-driven action queue

Only generate items from real project evidence.

Each item:
- priority
- asset
- reason
- evidence reference
- action
- status

Example:

NOW
RSA-2048 used by production authentication
Reason: public-key quantum relevance + sensitive data + long lifetime
[Inspect]

## Recent activity

Show real scan/job/migration/verification events.

---

# 6. EMPTY PROJECT EXPERIENCE

A new project must not look broken.

Show:

`NO CRYPTOGRAPHIC INVENTORY YET`

"Connect your first cryptographic surface to begin building the project's evidence-backed inventory."

Primary actions:

- Scan Source
- Scan Network
- Upload Asset

Secondary:

- Load Controlled Demo

Also show a short explanation of discoverable surfaces.

---

# 7. PROJECT MANAGEMENT

Projects page:

search/filter/sort

Project row/card:

- name
- owner
- environment
- criticality
- data sensitivity
- assets
- risk
- migration
- last scan
- status

Create Project fields:

- project name
- description
- organization/business unit
- environment
- business criticality
- data sensitivity
- expected data protection lifetime
- migration target date
- owner
- tags

Business context is essential because the scanner cannot infer all business meaning.

After creation, guide the user through:

1. Define context
2. Connect discovery source
3. Run baseline
4. Review inventory
5. Assess risk
6. Understand impact
7. Plan migration
8. Verify

---

# 8. SCAN STUDIO

Replace the current simplistic tab form with a source-selection workflow.

Supported surfaces:

- Source Code
- Dependencies
- Binary
- Firmware
- Network
- Certificate
- Archive
- PCAP

Each scan surface card should tell the user:

- what it analyzes
- required input
- expected output
- limitations

Clicking a card opens a configuration panel.

## Network inputs

- hostname/IP
- port
- protocol where required
- SNI if needed
- timeout
- scope/authorization acknowledgement

Show expected coverage:

TLS versions
cipher suites
key exchange
certificates
PQC/hybrid negotiation
SSH/QUIC where supported

When active scanning is used, make authorization explicit.

## Source inputs

- file
- folder
- ZIP
- repository integration if existing code already supports it
- source snippet

## Binary inputs

- binary upload
- executable upload
- archive containing binary

Display:

format
architecture
size
SHA-256

## Certificate inputs

PEM
DER
P12
JKS/keystore where supported

## Archive inputs

ZIP
7z
supported formats

Show safe-processing limits before execution.

---

# 9. SCAN JOB EXPERIENCE

Every scan must be asynchronous when necessary.

States:

QUEUED
RUNNING
COMPLETED
FAILED
CANCELLED

Every job stores:

- job ID
- project
- user
- scan surface
- input
- input hash
- configuration
- status
- started/finished timestamps
- stage
- logs
- results
- error details
- engine version

Scan progress UI:

Queued
→ Running
→ Resolve/Input validation
→ Discovery stages
→ Evidence normalization
→ Persistence
→ Completed

Do not fake percentage progress when the backend cannot measure it. Use stage progress instead.

FAILED must show:

- exact failure reason
- stage
- target/input
- whether partial results exist
- error type
- logs
- retry
- troubleshooting guidance

Never interpret failure as "no crypto found."

---

# 10. BACKEND FUNCTIONALITY AUDIT

Before visual polishing, trace every important button:

UI button
→ frontend handler
→ API call
→ backend route
→ service/engine
→ database
→ response
→ UI state

Repair all broken chains.

Do NOT replace broken endpoints with hardcoded frontend data.

Audit:

- scanner calls
- project IDs
- database queries
- graph aggregation
- risk calculation
- migration generation
- verification comparison
- archive operations
- report generation
- CBOM export

Fix stale state and project leakage.

---

# 11. EVIDENCE MODEL

All scanner outputs must normalize into a common structure.

Minimum:

```text
id
project_id
asset_id
asset_type
algorithm
cryptographic_role
source_surface
evidence_type
location_or_endpoint
observed_value
confidence
evidence_level
status
timestamp
input_hash
engine_version
rule_version
metadata
```

Evidence levels:

E0 metadata/unverified
E1 heuristic
E2 structural
E3 dynamic/network observation
E4 corroborated
E5 attested/formal/hardware-backed where applicable

Evidence states:

OBSERVED
INFERRED
CORROBORATED
CONTRADICTED
UNKNOWN
INCONCLUSIVE
SCANNER_UNSUPPORTED

Confidence and evidence strength are separate fields.

---

# 12. SOURCE DISCOVERY

Use AST/structural parsing where appropriate.

Python:
- AST
- imports
- aliases
- constants
- crypto APIs
- key-size extraction
- call-site context

Other languages:
- Tree-sitter or equivalent structural parsing

Never treat these as identical:

real function call
comment
string
variable name
documentation
unused import

A crypto library import does not prove an algorithm is used.

---

# 13. DEPENDENCY DISCOVERY

Support existing dependency formats such as:

Node:
package.json
package-lock.json

Python:
requirements.txt
Pipfile
poetry.lock

Java:
pom.xml
build.gradle

Go:
go.mod
go.sum

Rust:
Cargo.toml
Cargo.lock

Map:
package/version
→ library/provider
→ crypto capability
→ actual evidence
→ affected asset

Do not claim execution solely from declaration.

---

# 14. BINARY / FIRMWARE

Binary formats:

ELF
PE/COFF
Mach-O

Analyze:

sections
symbols
imports/exports
known crypto constants
library markers
entropy

Binary signature means possible presence, not execution proof.

Firmware extraction must be bounded:

- recursion depth
- file count
- decompressed size
- timeout
- memory/output

---

# 15. NETWORK DISCOVERY

Network scanner is an observation engine.

Can observe:

TLS versions
cipher suites
key exchange
certificate
PQC/hybrid negotiation
SSH negotiation
QUIC/HTTP3 indicators
OCSP/security headers where supported

Important states:

NEGOTIATED
ADVERTISED
REJECTED
SCANNER_UNSUPPORTED
INCONCLUSIVE

External scan only establishes the observable boundary.

Never say:

"The organization is quantum safe"

from a public domain scan.

If a CDN such as Cloudflare is detected, distinguish:

client → CDN
CDN → origin
origin → internal services

Only make claims supported by evidence at each boundary.

---

# 16. ASSET INVENTORY

Professional asset table with:

Asset
Algorithm
Role
Surface
Environment
Quantum
Criticality
Evidence
Status

Filters:

algorithm
role
risk
quantum
criticality
data sensitivity
surface
environment
migration
verification

Views:

Table
Cards
Graph

Empty state must provide a next action.

---

# 17. ASSET DETAIL

Top:

asset name
asset type
status badges
risk
criticality

Summary metrics:

Evidence strength
Consumers
Data lifetime
Migration status

Tabs:

Overview
Evidence
Relationships
Risk
Agility
Blast Radius
Migration
History

Actions:

Re-scan
Analyze Risk
Generate Migration
Open Graph

---

# 18. EVIDENCE EXPLORER

Table:

Evidence ID
Asset
Surface
Type
Level
Confidence
Location
Timestamp
Engine

Selecting evidence opens a detail drawer.

For source:
show code excerpt + line numbers.

For binary:
show offset/section.

For network:
show protocol observation.

For archive:
show archive path/metadata.

Show input hash, engine version, rule version and related assets.

---

# 19. CRYPTO ASSET GRAPH — REAL GRAPH

Replace the current relationship-card representation with a real interactive graph.

Use an established graph visualization library.

Controls:

- zoom
- pan
- fit
- reset
- layout
- search
- filters
- risk mode
- evidence mode
- path highlight

Nodes:

Application
Service
Library
Algorithm
Key
Certificate
Binary
Firmware
Endpoint
Data Flow
HSM
KMS
Archive
Crypto Module

Edges:

USES
IMPLEMENTS
DEPENDS_ON
SERVES
AUTHENTICATED_BY
PROTECTS
CONTAINS
ISSUED_BY
HOSTED_ON
CALLS
NEGOTIATES
WRAPS_KEY
PROTECTED_BY

Every edge carries evidence + confidence.

Critical data-integrity rule:

Do not render an edge if its referenced nodes do not exist.

If invalid graph data is detected, show:

GRAPH DATA INTEGRITY ISSUE

instead of rendering impossible graph state.

Graph modes:

1. Architecture
2. Cryptographic Risk
3. Blast Radius
4. Evidence

Clicking a node opens an asset drawer.
Clicking an edge opens relationship evidence.

---

# 20. QUANTUM RISK CENTER

Keep the deterministic matrix but upgrade the visual analysis.

Charts:

1. quantum vulnerability distribution
2. Shor vs Grover relevance
3. HNDL exposure
4. migration readiness
5. algorithm family distribution
6. historical trend if enough scan history exists

Main table:

Algorithm
Role
Asset Count
Quantum Relevance
HNDL
Target PQC
Migration Status

Click algorithm → drill down to affected assets.

Do not fabricate quantum timelines.

Clearly separate:

current evidence
assumptions
future threat modeling

---

# 21. MOSCA + HNDL

Split page.

LEFT: Mosca timeline

X = data protection lifetime
Y = migration time
Z = assumed threat horizon

RIGHT: HNDL analysis

Show actual contributing assets, protected data and evidence.

Do not present Z as a certainty.

---

# 22. CRYPTO AGILITY

Use:

Algorithm
Configuration
Dependency
Protocol
Certificate/Key
Deployment
Validation

Visual:

radar chart or 7-dimension status visualization
plus detailed table

States:

SUPPORTED
OBSERVED
PARTIALLY_OBSERVED
CONSTRAINED
BLOCKED
UNKNOWN
NOT_APPLICABLE
SCANNER_UNAVAILABLE

Every result must show evidence or an explanation for lack of evidence.

---

# 23. BLAST RADIUS

Current list should become an investigation surface.

Summary metrics:

- direct consumers
- transitive consumers
- affected services
- affected apps
- affected certificates
- max path depth

Main visualization:
interactive dependency graph

Side panel:

consumer
relationship
path
environment
criticality

Selecting target asset highlights all upstream paths.

---

# 24. MIGRATION PLANNER

Turn current static workstreams into an operational workspace.

Header:

Target primitive
Migration mode
Estimated effort
Operational impact
Risk

Sections:

Migration rationale
Affected systems
Dependencies
Certificates
Protocols
Data flows

Workstreams:

Discovery
Dependency
Development
Staging
Validation
Cutover
Rollback
Verification

Statuses:

BLOCKED
READY
IN_PROGRESS
VALIDATION
COMPLETED
FAILED

Each step:

owner
status
tasks
evidence
blockers
estimated effort
notes

Do not allow a user to mark completed if evidence-backed validation is required and missing.

---

# 25. MIGRATION IMPACT / ECONOMICS

Include:

Engineering effort
Infrastructure impact
HSM/KMS impact
Licensing
Vendor support
Performance
Latency
Downtime
Compatibility
Validation/certification
Rollback complexity

If estimated rather than measured:
mark HEURISTIC / ESTIMATE.

No fake numerical precision.

---

# 26. CLOSED-LOOP VERIFICATION

Create an actual comparison experience.

BASELINE
→ MIGRATION
→ POST-MIGRATION

Show:

removed assets
added assets
unchanged assets
unknowns
contradictions
new target mechanisms
residual risk

Example:

REMOVED
RSA-2048

ADDED
X25519 + ML-KEM hybrid

UNCHANGED
AES-256-GCM

Final status:

VERIFIED
PARTIALLY_VERIFIED
NOT_VERIFIED
INCONCLUSIVE

Verification must be generated from actual before/after evidence, never from manual checkbox state.

---

# 27. CBOM

Add real visual content.

Summary:

components
algorithms
certificates
keys where modeled
protocols
provenance coverage
schema validation

Preview table.

Export history:

timestamp
scope
version
hash
status

Downloads:
CycloneDX JSON
JSON
CSV where useful

---

# 28. REPORT CENTER

Replace bare report cards with:

Report generator

Report types:

Executive
Technical Inventory
Quantum/Mosca/HNDL
Migration
Verification
Archive
CBOM

Options:

project scope
baseline scan
post-migration scan
include evidence
include appendix

Generated report history:

status
created
scope
hash
preview
download

---

# 29. SECURE ARCHIVE LAB

This is an add-on module, not a replacement for the enterprise discovery product.

Create tabs:

ANALYZE
PROTECT
HISTORY

## Analyze workflow

1. Drop archive
2. hash/fingerprint
3. identify format
4. detect encryption
5. inspect metadata
6. optional authorized credential
7. safe extraction
8. crypto discovery
9. risk assessment
10. recommendation

Never automatically brute force or crack passwords.

If no credential:

metadata analyzed
content remains UNKNOWN

If credential is supplied:
process in an isolated/resource-bounded environment.

Inspect:

archive cipher
KDF
password dependency
metadata/header encryption
integrity/authentication
certificates
private keys
crypto libraries
crypto configuration
nested archives

Feed discovered contents into the standard ECDAT discovery/evidence pipeline.

## Protect workflow

Modes:

1. Password Vault
2. Recipient-Key Vault
3. PQC/Hybrid Vault

Show clear cryptographic diagrams.

Password Vault:

random 256-bit data key
→ authenticated encryption
→ payload

password
→ memory-hard KDF
→ wrapped data key

Never store password.

Recipient-Key Vault:

random data key
→ authenticated bulk encryption
→ recipient key protection

PQC/Hybrid Vault:

strong symmetric bulk encryption
+
standardized PQC/hybrid key establishment where supported

Never claim "unbreakable" or "future-proof forever."

## .ecvault

For advanced mode, support a versioned custom container such as `.ecvault`.

Conceptual structure:

manifest
crypto parameters
recipient envelopes
encrypted payload

Manifest can hold non-secret metadata:

format version
cipher
key establishment
KDF
created time
payload hash
recipient count

Do not expose passwords/private keys.

## Verify

After package creation, verify:

payload hash
integrity
decryptability using authorized key
manifest
crypto parameters
key envelope

Result:

VERIFIED
FAILED
INCONCLUSIVE

---

# 30. HSM / KMS / HARDWARE CRYPTO

Make these first-class asset types where data supports it:

HSM
KMS
TPM
Secure Element
Crypto Accelerator
PKCS#11 Provider
Hardware Crypto Module

Fields:

provider
location
algorithm support
key type
key size
key usage
application dependency
certificate dependency
deployment
evidence

If direct integration is not available:

MANUAL IMPORT
NOT CONNECTED
UNKNOWN

Do not pretend the platform has connected access it does not have.

---

# 31. DATA PROTECTION MODEL

Do not treat a database as having one global "encryption" property.

Represent layers:

transport encryption
at-rest/TDE
application/column encryption
backup encryption
key management
KMS/HSM
tokenization
password hashing
application crypto

Questions ECDAT should answer:

What crypto protects this data?
Where is it implemented?
What key system protects it?
What service depends on it?
How long must the data remain protected?

If unknown, report UNKNOWN.

---

# 32. BUSINESS CONTEXT

Explicit project/asset fields:

business criticality
data sensitivity
environment
owner
data lifetime

Do not infer all business context automatically.

Use business context when explaining risk and migration priority.

Every recommendation should be explainable.

---

# 33. KNOWLEDGE BASE

Turn the current sparse page into a real registry.

Show:

Rules version
Last update
Algorithms
PQC standards
Protocol rules
Risk rules
Migration mappings
API sinks
Binary signatures
Attestation/hash
Change history

Each rule should expose:

name
version
source
effective date
description
mapping
hash

---

# 34. DATA VISUALIZATION RULES

Charts must answer actual product questions.

Recommended:

Dashboard:
- risk donut
- algorithm bars
- discovery coverage
- migration readiness
- scan activity timeline

Quantum:
- Shor/Grover
- HNDL
- algorithm distribution
- transition matrix

Agility:
- 7-dimension radar/status chart

Blast Radius:
- dependency graph

Migration:
- workstream progress
- affected asset distribution

Verification:
- before/after change distribution

Archive:
- crypto protection summary
- contents by asset type

Do not add charts just to fill empty space.

If a dataset has no history, do not generate fake trend lines.

---

# 35. ANIMATION

Use restrained functional animation.

Good:

- page transitions
- sidebar expand/collapse
- metric reveal
- chart draw
- scan stage transitions
- graph node appearance
- drawer transitions
- verification success
- archive packaging progress

Bad:

- constant pulsing
- excessive glow
- decorative particles
- continuous movement with no meaning

Respect prefers-reduced-motion.

---

# 36. DETAIL DRAWERS

Use drawers to preserve investigation context.

Good candidates:

Asset
Evidence
Scan Job
Graph Node
Graph Edge
Risk Finding
Migration Step
Report
Archive Analysis

Drawer content should allow quick deep inspection without losing project position.

---

# 37. GLOBAL SEARCH / COMMAND MENU

Add a global command/search interaction, e.g. `Cmd/Ctrl + K`.

Search:

projects
assets
algorithms
certificates
services
evidence
scan jobs
migration plans
reports

Actions:

open project
open asset
run scan
open report

---

# 38. ERROR/EMPTY STATES

Every empty state must explain:

WHY EMPTY
WHAT IT MEANS
WHAT TO DO NEXT

Every error must explain:

WHAT FAILED
WHY
WHAT IS KNOWN
WHAT IS UNKNOWN
WHAT TO DO NEXT

Examples:

NO CRYPTO ASSETS YET
Run a discovery scan or import an asset.

NETWORK SCAN FAILED
TLS negotiation timed out after 15 seconds.
No conclusion about crypto posture can be made.

[Retry] [View Logs]

Do not display "secure" just because discovery failed.

---

# 39. DEMO PROJECT

Create one explicit controlled demo project.

Name example:

`ECDAT Demo — PQC Migration Lab`

Clearly mark:

`DEMO DATA`

It should contain realistic controlled examples:

- RSA
- ECDSA
- X25519
- AES
- certificate
- dependency
- binary finding
- network evidence
- HNDL
- Mosca
- blast radius
- migration plan
- verification
- CBOM

The demo must still use real application pipelines, not separate hard-coded rendering.

---

# 40. PERFORMANCE

Use:

- asynchronous scan workers
- pagination
- lazy graph loading
- indexed DB queries
- incremental graph updates
- bounded file analysis
- caching for versioned knowledge

Large inventories must not freeze the browser.

---

# 41. SECURITY

Maintain strong controls:

- authentication
- authorization
- project isolation
- SSRF protection
- network allowlist/authorization
- DNS validation/pinning where needed
- path traversal protection
- archive extraction limits
- memory limits
- output limits
- timeouts
- safe temp storage
- cleanup
- audit logging
- secret redaction

Never log:

passwords
private keys
API tokens
secrets

---

# 42. TESTING

Before declaring the redesign finished, run actual tests.

Unit:

- scanners
- evidence normalization
- correlation
- graph
- quantum risk
- Mosca
- HNDL
- agility
- blast radius
- migration
- verification
- archive analyzer
- vault builder

Integration:

- auth
- project isolation
- API
- database
- scan jobs
- archive workflow
- report/CBOM export

Security:

- SSRF
- zip-slip
- path traversal
- oversized upload
- archive bomb
- malformed input
- unauthorized project access

Adversarial scanner tests:

- unused crypto import
- algorithm only in comments
- documentation-only algorithm
- declared-but-unused dependency
- configured-but-not-negotiated TLS
- advertised-but-not-selected SSH
- installed-but-inactive PQC library
- unreachable target
- unsupported scanner
- contradictory observations

---

# 43. ACCEPTANCE TEST

Do not stop when pages render.

Run this full workflow using the real product:

1. Login
2. Create project
3. Set Production
4. Set criticality
5. Set data sensitivity
6. Set data lifetime
7. Upload source
8. Upload binary
9. Upload certificate
10. Add authorized network target
11. Run scans
12. Observe jobs
13. Open discovered assets
14. Open evidence
15. Open graph
16. Select quantum-relevant asset
17. Analyze Mosca/HNDL
18. Analyze agility
19. Calculate blast radius
20. Generate migration
21. Review effort/impact
22. Run simulation if supported
23. Create baseline/post scan
24. Run verification
25. Export CBOM
26. Generate report
27. Open Secure Archive Lab
28. Analyze controlled encrypted archive
29. Create protected archive
30. Verify protected archive

Every action should work from actual backend/persistence.

---

# 44. IMPLEMENTATION ORDER

Do not polish the UI before correcting broken behavior.

Priority 1 — correctness/data integrity

- remove mixed mock/demo state
- repair project scoping
- repair scanner/API flows
- repair persistence
- repair graph data integrity
- repair risk/migration/verification data flow

Priority 2 — core UX

- global shell
- navigation groups
- dashboard
- Scan Studio
- Scan Jobs
- Asset Inventory
- Evidence Explorer
- real graph

Priority 3 — analysis UX

- Quantum Risk
- Mosca/HNDL
- Agility
- Blast Radius
- Migration
- Verification

Priority 4 — output

- CBOM
- Reports
- Knowledge

Priority 5 — Secure Archive Lab

Priority 6 — visual polish

- charts
- micro-interactions
- subtle texture
- animation
- responsive behavior

Do not spend time making failed features look beautiful. Make them work.

---

# 45. IMPLEMENTATION BEHAVIOR

START BY AUDITING THE CURRENT REPOSITORY.

Do not blindly create a new application.

Do not replace working scanner engines without understanding them.

Reuse and refactor existing functionality.

For every current page:

1. identify data source
2. identify API
3. identify backend service
4. identify DB source
5. identify whether the page is real or mock
6. fix inconsistencies
7. then redesign the page

Build vertically:

UI
→ API
→ service
→ database
→ tests
→ UI verification

Do not build 20 beautiful pages on top of broken backend flows.

---

# 46. DEFINITION OF DONE

A feature is DONE only if:

1. UI exists
2. frontend action works
3. API works
4. backend logic works
5. result persists
6. refresh preserves state
7. authorization works
8. errors are handled
9. tests exist
10. evidence/provenance is retained where relevant
11. no fake success is shown

The platform is finished when a new user can:

create project
→ add context
→ run real scan
→ see real evidence
→ understand the finding
→ trace it in the graph
→ assess quantum relevance
→ understand impact
→ create migration plan
→ verify migration
→ export evidence
→ optionally analyze/repackage encrypted archives

---

# 47. FINAL QUALITY BAR

The current UI is a starting point, not the target.

The target should feel like a serious enterprise security product.

The user should be able to understand the product within seconds.

Every screen should answer one clear question:

Dashboard:
What is the overall state?

Scan Studio:
What can I inspect?

Scan Jobs:
What is running/failing?

Inventory:
What crypto exists?

Evidence:
Why do you believe it?

Graph:
What depends on what?

Quantum:
What is quantum-relevant?

Mosca/HNDL:
When does it matter?

Agility:
How hard is replacement?

Blast Radius:
What breaks if we change it?

Migration:
How do we change it?

Verification:
Did it actually change?

CBOM:
What can I export?

Reports:
What can I communicate?

Archive Lab:
How is this archive protected and how can it be protected better?

Knowledge:
What rules produced the result?

---

# 48. FINAL EXECUTION COMMAND

Perform the implementation now.

First inspect the repository and existing ECDAT implementation.
Then fix correctness/data integrity.
Then connect all broken functionality.
Then implement the UI/UX redesign.
Then add real charts and meaningful animation.
Then improve the workflows.
Then test the full product end-to-end.

Do not stop at a plan.
Do not stop at a visual redesign.
Do not return only recommendations.

IMPLEMENT THE CHANGES IN THE ACTUAL REPOSITORY.

When complete, report:

1. what existed
2. what was broken
3. what was fixed
4. what was redesigned
5. what was newly implemented
6. which scanners now work
7. which analysis workflows now work
8. test results
9. remaining limitations
10. exact run instructions

Final rules:

PRESERVE WORKING CODE.
INTEGRATE, DON'T DUPLICATE.
NO FAKE DATA IN REAL PROJECTS.
NO FAKE METRICS.
NO FAKE GRAPH RELATIONSHIPS.
NO UNVERIFIED CRYPTO CLAIMS.
UNKNOWN MUST REMAIN UNKNOWN.
EXTERNAL SCANS MUST NOT CLAIM INTERNAL VISIBILITY.
MIGRATION MUST BE EVIDENCE-VERIFIED.
SECURE ARCHIVE MUST NOT BE CALLED UNBREAKABLE.
FUNCTIONAL CORRECTNESS BEFORE VISUAL EFFECTS.
THE FINAL PRODUCT MUST FEEL LIKE ONE COHERENT SYSTEM.
