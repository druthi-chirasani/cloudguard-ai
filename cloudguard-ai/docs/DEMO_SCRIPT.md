# CloudGuard AI: 2 to 3 minute demo script

Setup before the demo: `streamlit run app.py`, browser open on the dashboard, nothing loaded.

| Time | Action | What to say |
|---|---|---|
| 0:00 | Show the header and the SYNTHETIC DEMO DATA badge | "CloudGuard AI reviews cloud configuration snapshots and audit events. Everything here is synthetic." |
| 0:15 | Click **Load Demo Dataset**, then **Run Scan** | "The scanner runs the real pipeline. There is no cloud account and no API key involved." |
| 0:30 | On Overview, point to the severity cards and the STOP decision | "STOP means a threshold is met by sufficient evidence. It is advisory. It is not a probability of compromise." |
| 0:50 | Findings tab: open **PUBLIC_SENSITIVE_RESOURCE** | "The customer data bucket is marked sensitive and allows public access. Here is the evidence, the score breakdown and the limitations." |
| 1:10 | Open **IAM_EXCESS_PRIVILEGE** for the app role | "The role is granted four actions but only one is declared as required. The three extra actions are shown as evidence." |
| 1:25 | Audit Timeline | "This successful policy change is an indicator for review. The denied request is marked as not successful access. It is not counted as access." |
| 1:40 | Identity Graph | "The solid cyan path is verified. Every edge is validated in the input. The dashed edge is not validated, so it is not used." |
| 1:55 | Risk Story | "The story connects an exposed entry point, a service identity and a sensitive bucket. It is a configuration path, not proven exploitability. Missing links are listed." |
| 2:10 | Remediation: select the public bucket finding and show the proposal | "This is a proposal for human approval. Nothing is applied to infrastructure." |
| 2:20 | Click **Preview Remediation** | "The patch goes to a copy. The real scanner re-runs. Look at what disappeared and what remains." |
| 2:35 | Point out that the attack path remains | "One finding disappearing does not make the environment secure. The identity still reaches the bucket through the path." |
| 2:45 | Exports tab: download JSON or CSV | "Exports contain the full scan. All remediation was simulated and needs human approval." |

## Expected judge questions and honest answers

- **Is this real AWS?** No. The input is a documented synthetic schema. Real AWS parsing is future work.
- **Is the risk score a probability?** No. It is a deterministic prioritisation heuristic with documented weights.
- **Does the AI decide anything?** The default path is deterministic. The optional LLM only explains one finding and cannot change scores or findings. It is off by default.
- **Did you test it on live infrastructure?** No. The prototype never connects to live infrastructure.
- **Why is the path Critical and the bucket finding Critical too?** They describe different things: the bucket is public, and the path shows the identity reaches it. The Risk Story groups them and does not add the scores together.
- **What is not implemented?** Full IAM evaluation, condition evaluation, live data sources, and a multi-user backend.
