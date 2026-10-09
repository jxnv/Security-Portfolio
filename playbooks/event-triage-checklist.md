# Alert Triage Checklist

> Confidential: SecOps / IT triage teams only.
> Flow: **Alert → 5 Ws → Disposition → S.A.F.D. ticket**

**Rules:** Context decides. Investigate before escalating. Document as you go.

---

## 1. Enrich: the 5 Ws

- [ ] **WHO**: Username, role, dept, privileges, risk score. Is this role expected to run admin tools? (IT admin / service acct / HR?)
- [ ] **WHAT**: Process, cmd line, hash, parent process, PID. Obfuscated/Base64? `certutil`, `net.exe`, `PSExec` used?
- [ ] **WHEN**: Timestamp, frequency, off-hours? In a maintenance window? Fired 10x this week?
- [ ] **WHERE**: Hostname, IP, domain, port, asset criticality. Crown-jewel / DC or test VM? IP tied to known C2 or TOR exit?
- [ ] **WHY**: Change request, ticket ref, past investigations for this host/user?
- [ ] Checked past tickets / baseline notes for host + user (avoid repeat work)

---

## 2. Pick a disposition

**Does activity match expected business baseline?**

| If | Disposition | Go to |
|---|---|---|
| Malicious | True Positive | [3.1](#31-true-positive-malicious) |
| Privileged user + dual-use tool | Suspicious Admin | [3.2](#32-suspicious-admin--dual-use-tools) |
| Authorized activity | Benign True Positive | [3.3](#33-benign-true-positive-authorized) |
| Low-risk, isolated | Informational | [3.4](#34-informational--low-severity) |
| Rule logic flaw | False Positive | [3.5](#35-false-positive) |

---

## 3. Actions per disposition

### 3.1 True Positive (Malicious)

**Triggers:** ransomware staging (`vssadmin` shadow copy deletion), credential dumping (LSASS access), unauthorized C2, BEC mailbox rules (auto-delete), LotL execution from unauthorized accounts.

- [ ] Isolate endpoint from network (**preserve RAM / volatile memory**)
- [ ] Revoke active SSO / cloud sessions for the user
- [ ] Block C2 IP / domain at perimeter
- [ ] Escalate to Tier 2 / IR Lead
- [ ] Document (S.A.F.D.)

### 3.2 Suspicious Admin / Dual-Use Tools

**Triggers:** admin running PSExec, net.exe, certutil, ScreenConnect, RDP, or off-hours privileged access with no maintenance ticket.

- [ ] Verify identity **out-of-band** (Slack/Teams ping or phone call)
- [ ] Check change management / ITSM for a valid ticket
- [ ] Verified + valid ticket → **Close with context**
- [ ] Unverified or account compromised → treat as **High Severity True Positive** (Compromised Privileged Account / Insider Risk) → run 3.1

### 3.3 Benign True Positive (Authorized)

**Triggers:** rule fired correctly, but activity is authorized (IT deployment script, scheduled backup, vuln scanner).

- [ ] Confirm user identity + scheduled job ticket
- [ ] Document finding in SIEM ticket
- [ ] Close as `True Positive - Authorized Business Activity`
- [ ] Submit tuning request to Detection Engineering (allowlist)

### 3.4 Informational / Low Severity

**Triggers:** isolated low-fidelity events, routine firewall blocks, policy warnings, single low-risk spike.

- [ ] Quick SIEM correlation: not part of multi-stage attack (e.g., password spray → login → rule creation)
- [ ] Isolated → close as `Informational / Low Severity`
- [ ] Part of a chain → re-triage as 3.1

### 3.5 False Positive

**Triggers:** bad signature/regex, flawed logic, misconfiguration; flagged behavior didn't match threat intent.

- [ ] Close as `False Positive`
- [ ] Document the exact rule flaw
- [ ] Route to Detection Engineering for suppression / tuning

---

## 4. Ticket documentation: S.A.F.D. (required on every ticket)

- [ ] **S**ummary: 1-2 sentences: alert + trigger
- [ ] **A**ctions Taken: tools, OSINT queries, logs checked
- [ ] **F**indings: evidence + baseline context
- [ ] **D**ecision: final disposition + justification + next steps

**Example (encoded PowerShell):**

| | |
|---|---|
| **S** | Suspicious Base64 PowerShell executed by WScript on WORKSTATION-09. |
| **A** | Decoded via CyberChef; hash checked in VirusTotal; queried Entra ID role for Bob_IT. |
| **F** | Payload: `start process powershell write-output triage`. Hash = clean Microsoft binary. Bob = confirmed SysAdmin on maintenance. |
| **D** | CLOSED, Benign True Positive. Authorized SysAdmin maintenance. Tuning request submitted for clean MS script hashes. |

---

## 5. Don't

- [ ] **Escalating out of fear.** Floods IR, causes alert fatigue. Gather context first.
- [ ] **Over-investigating low risk.** Close benign low-impact alerts in **< 3 min**.
- [ ] **Skipping context checks.** Check past tickets / baselines before digging.
- [ ] **Vague notes.** Never write "looks fine" or "no threat found" without proof.