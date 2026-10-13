# CloudGuard AI presentation outline (7 slides)

**Slide 1. Problem.** Cloud misconfigurations and over-broad identity permissions are common, and teams often lack a clear view of which risks matter most and why.

**Slide 2. The CloudGuard AI solution.** Analyse configuration snapshots, identity permissions, access relationships and audit events. Explain each finding, prioritise it, propose a fix and preview the result before a human approves.

**Slide 3. Architecture.** Show the pipeline from parser through detection, audit analysis, scoring, graph, Risk Story, remediation and simulation to the dashboard. Note that the UI consumes one scanner function.

**Slide 4. Live findings and transparent scoring.** Show the Overview and one finding's factor breakdown. Stress that scores are heuristics, that evidence caps them, and that missing data is UNKNOWN, never SAFE.

**Slide 5. Risk Story and verified relationships.** Show the verified path and the dashed unvalidated edge. Say that a configuration path is not proof of exploitability.

**Slide 6. Proposed remediation and simulated rescan.** Show the proposal for human review and the before/after comparison. Note that the rescan uses the same functions, and that the attack path still remains after the bucket fix.

**Slide 7. Limitations, impact and next steps.** Synthetic schema only, simplified IAM evaluation, no condition evaluation, no live integration. Next steps: native AWS parsing, full policy evaluation and a read-only connector.
