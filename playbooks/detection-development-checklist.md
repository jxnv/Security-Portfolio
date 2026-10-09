# Detection Development Checklist

> Applies to Sigma / SPL / KQL / EQL / YARA-L across Endpoint, Cloud, Identity, Network.
> Treat every detection as version-controlled Detection-as-Code (DaC).
> Flow: **D.E.T.E.C.T.** = Define → Examine → Target → Evaluate → Canary → Throttle

---

## D: Define the Detection Story

- [ ] Write a Detection Story with a clear trigger source: CTI, Red Team post-mortem, IR gap, or hunt hypothesis. No vague mandates.
- [ ] Apply the **Selection Triad**:
  - **Relevance:** does it affect active assets?
  - **Importance:** does it target high-risk adversary behavior?
  - **Feasibility:** sustainable within SIEM log budget and query limits?
- [ ] Map TTPs to MITRE ATT&CK. Prioritize by **CTI Overlap Score ÷ Level of Effort (LoE)**. (CTI Overlap = number of sector-relevant threat actors using the technique.)
- [ ] Weigh in Asset Criticality (DCs, cloud control planes) and kill-chain gaps (execution, lateral movement, persistence).

## E: Examine Telemetry

- [ ] Required logs are active, timely, and normalized (EDR process trees, Win 4688/4624, CloudTrail, SSO logs, NetFlow/DNS).
- [ ] Inspect raw logs: key fields parsed and **not truncated** (parent process path, command line, subject user ID, source IP).
- [ ] Audit policies enforced on all target endpoints (Windows command-line auditing, PowerShell ScriptBlock logging).

## T: Target TTPs ("Goldilocks" Logic)

- [ ] Detect **behaviors** (process injection, token manipulation, anomalous API calls), not brittle IOCs (IPs, hashes).
- [ ] Balance precision: not so broad it burns out analysts, not so narrow that syntax tweaks or spacing bypass it.
- [ ] Normalize strings to **lowercase**. Cover command variants (`cmd.exe /c` vs `cmd /k`, base64 flags, arg ordering).
- [ ] Tailor to domain:

| Domain | Focus |
|---|---|
| Endpoint | Parent/child process relationships |
| Cloud | IAM privilege escalation, multi-region API bursts |
| Identity | SSO token misuse, service account / non-human identity abuse |
| Network | DNS tunneling, JA4 TLS fingerprints |

## E: Evaluate (Back-Test)

- [ ] Run query against **90 days** of production logs (**30 days minimum**). Quantify expected alert volume.
- [ ] **Stack** results on common attributes (process path, user, host role) to isolate benign software and build exclusions.
- [ ] Record in dev notes: execution metrics, alert counts, sample benign hits. This justifies exclusions in peer review.

## C: Canary Test & Document

- [ ] Schedule synthetic canary triggers (e.g., Atomic Red Team) in test env. Alert if the detection stops firing (schema or agent break).
- [ ] Run end-to-end **BAS** in staging: confirm ingestion, correlation, and ticket generation.
- [ ] Write **ADS** documentation:
  - [ ] Goal
  - [ ] ATT&CK mapping
  - [ ] Technical context
  - [ ] Blind spots / evasion vectors
  - [ ] Step-by-step triage instructions
- [ ] Commit rule (Sigma/KQL/SPL YAML) to Git: branch review, static linting, audit trail.

## T: Throttle, Burn-In & Tune

- [ ] **Silent burn-in** in production for **1-2 weeks** (no alerts routed to analysts).
- [ ] Configure throttling/grouping (e.g., by Hostname + Username over 1 hr) so bursts yield one ticket.
- [ ] Monitor KPIs (see targets below), plus MTTD and MTTR.
- [ ] **Recertify every 6-12 months.** Sunset the rule if targets are retired, preventive controls make it redundant, or the threat is obsolete.

---

## Benchmarks

| Phase | Metric | Target |
|---|---|---|
| Requirement | CTI Overlap vs LoE | Prioritize TTPs shared by top sector threat actors |
| Back-test | Duration | 90 days (30 min) |
| Pre-prod | False Positive Rate | **≤ 8%** |
| Production | False Positive Rate | **≤ 6%** overall, **≤ 25%** for critical alerts |
| Canary | Cadence | Scheduled synthetic runs, immediate alert on failure |
| Lifecycle | Recertification | Audit + re-tune every 6-12 months; sunset obsolete rules |