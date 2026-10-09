# Threat Hunting Runbook

> Confidential: SOC / internal security only.
> Flow: **H**ypothesis → **U**nderstand baseline & query → **N**avigate outcome → **T**rack & document

---

## 0. Field Rules

- [ ] **No endless exclusions** (`NOT A AND NOT B`). Over-filtering makes brittle queries.
- [ ] **Start at 7-day lookback**, then scale to 30 days (avoids SIEM timeouts).
- [ ] **Record negative results.** Zero finds still validates controls and exposes logging gaps.
- [ ] Hunt **behaviors / process chains / protocol anomalies**. Leave commodity hash/IP/domain matching to automated tools.

---

## 1. Pre-Flight (before every hunt)

- [ ] Command-line auditing enabled (Win Event **4688**)
- [ ] **Sysmon Event 1** deployed on critical assets
- [ ] Asset inventory current: jump boxes, DCs, backup servers, OT
- [ ] 1-2 hr protected time block reserved
- [ ] (Lab) Query validated with Atomic Red Team / MITRE Caldera

---

## 2. H: Hypothesis & Scope

- [ ] Write an If-Then hypothesis (source: CISA alert, DFIR report, CTI)
- [ ] Map to MITRE ATT&CK technique
- [ ] Confirm required telemetry exists (100%). If not, stop and log as a gap.
- [ ] Set time window (7 / 14 / 30 days)
- [ ] Prioritize critical assets (use inventory)

---

## 3. U: Baseline & Query

- [ ] Establish benign baseline **before** hunting for evil
- [ ] **Rarity analysis:** aggregate process/network counts, flag items on **< 0.5% of hosts**
- [ ] Query parent-child process relationships and named pipes
- [ ] Apply noise filters (see scenarios below)
- [ ] Confirm no query timeouts; target >95% benign filtered

**Data sources**

| Domain | Sources |
|---|---|
| Endpoint | Sysmon 1, 10, 17/18; Win Security 4688, 4624 |
| Network | NDR, NetFlow, Proxy, DNS |
| Identity | Active Directory, Entra ID |

---

## 4. High-Yield Hunt Scenarios

### 4.1 Post-Recon Command Chaining
- **Telemetry:** Win 4688, Sysmon 1, EDR process telemetry
- [ ] Find **3+ recon binaries on one host within 5 min**: `whoami.exe`, `ipconfig.exe`, `nltest.exe`, `net.exe group /domain`, `tasklist.exe`, `systeminfo.exe`
- [ ] Exclude: admin batch scripts, SCCM/Intune deployments

### 4.2 LSASS Credential Dumping (T1003.001)
- **Telemetry:** Sysmon 10, Win 4656
- [ ] `TargetImage = lsass.exe` AND `GrantedAccess` = `0x1410` or `0x1F0FFF`
- [ ] Check `CallTrace` for `dbgcore.dll` / `dbghelp.dll` (regardless of exe name, e.g. `procdump.exe`, `adobe.exe`)
- [ ] Exclude: EDR/AV agents, system crash dumpers

```
index=sysmon EventCode=10 TargetImage="*\\lsass.exe" (CallTrace="*dbgcore.dll*" OR CallTrace="*dbghelp.dll*") | stats count by SourceImage, User, Computer
```

### 4.3 PSExec / Impacket Lateral Movement
- **Telemetry:** Win 7045 (service creation), Sysmon 17/18 (pipes)
- [ ] Service names matching `^[a-zA-Z]{4}$`, or 8-letter `.exe` image paths in `Admin$`
- [ ] Named pipes: `\pipe\remcom*`, `\pipe\PSEXESVC*`
- [ ] Exclude: known IT deployment / management tools

### 4.4 Interactive Service Account Abuse
- **Telemetry:** Win 4624, AD audit logs, UEBA
- [ ] Logon **Type 2** (interactive) or **Type 10** (RDP)
- [ ] Target account matches `svc_*` / `sa_*`, targeting **Domain Controllers**
- [ ] Exclude: designated admin jump servers, change-window maintenance

### 4.5 Unauthorized RMM Tools & Cloud Persistence
- **Telemetry:** Win 4688 / Sysmon 1, proxy/DNS, Entra ID audit logs
- [ ] **Endpoint:** process spawns of `AnyDesk.exe`, `ScreenConnect.exe`, `Splashtop.exe` on critical servers
- [ ] **Cloud:** Entra ID MFA device registration from untrusted IPs, or multiple users' MFA added from one IP
- [ ] Exclude: authorized helpdesk endpoints, approved VPN ranges

---

## 5. N: Navigate Outcome

| Result | Action |
|---|---|
| **Malicious** | - [ ] Scope end-to-end <br> - [ ] **Hand off to IR immediately** |
| **Repeatable pattern** | - [ ] Pass logic to Detection Engineering (DELC) for automated low-noise alert |
| **Clean** | - [ ] Log validated controls <br> - [ ] Document logging gaps |

---

## 6. T: Track & Document

- [ ] Fill in hunt log template (below)
- [ ] Update MITRE ATT&CK Navigator coverage
- [ ] Add to central hunt repository (Excel / Jira / SIEM)
- [ ] Note: **SOC rules** = high confidence, low noise. **Hunt rules** = higher noise tolerance.

### Hunt Log Template

```
Hunt Title & ID:      [e.g., HUNT-2026-04: LSASS Memory Access via CallTrace]
Analyst:              
MITRE ATT&CK:         [e.g., T1003.001]
Time Window:          [7 / 14 / 30 days]
Hypothesis:           If [adversary behavior], we will observe [telemetry].
Query / Syntax:       
Outcome:              [ ] True Positive (escalated to IR)
                      [ ] Benign True Positive (legit admin activity)
                      [ ] Negative (clean, control validated)
Action Items:         (1) 
                      (2) 
```

---

## 7. KPIs (track per quarter)

| KPI | Measure |
|---|---|
| Undetected threats found | Count of true-positive incidents started from hunts |
| Coverage gaps closed | Logging/config gap tickets resolved after hunts |
| New detection rules | Ratio of hunts yielding production low-noise SIEM rules |
| MTTD | Trend of average dwell time across detected incidents |