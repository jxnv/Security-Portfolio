# Detection Engineering Home Lab

**Wazuh SIEM + Windows & Linux endpoints on VirtualBox, with the endpoints fully isolated from the internet — built for importing and testing Sigma rules**

*Verified against Wazuh 4.14.8, Ubuntu 24.04.4 LTS, and VirtualBox 7.2.18 (late September 2026).*

---

## Table of contents

1. [Lab overview](#1-lab-overview)
2. [Why this stack, right now](#2-why-this-stack-right-now)
3. [Network map: server online, endpoints fully isolated](#3-network-map-server-online-endpoints-fully-isolated)
4. [Host requirements & VM inventory](#4-host-requirements--vm-inventory)
5. [Hypervisor and network setup](#5-hypervisor-and-network-setup)
6. [Install Wazuh on the server VM](#6-install-wazuh-on-the-server-vm)
7. [Deploy the agents](#7-deploy-the-agents)
8. [Turn on the telemetry Sigma rules actually need](#8-turn-on-the-telemetry-sigma-rules-actually-need)
9. [Importing and running Sigma rules against Wazuh](#9-importing-and-running-sigma-rules-against-wazuh)
10. [Validate detections with real technique execution](#10-validate-detections-with-real-technique-execution)
11. [Keeping the lab fast to rebuild](#11-keeping-the-lab-fast-to-rebuild)
12. [Quick reference](#12-quick-reference)

---

## 1. Lab overview

This is the leanest layout that still covers real detection-engineering work: a single Wazuh all-in-one server, one Linux endpoint, one Windows endpoint, all hosted in VirtualBox 7.2. The network is deliberately segmented: only the Wazuh server can reach the internet (to install itself and pull updates); the endpoints sit on a fully isolated internal segment with the manager and have no route out at all, ever. Section 3 has the full network map.

- **Wazuh manager + indexer + dashboard (all-in-one)** — the SIEM/XDR core and rule engine. The only VM with internet access.
- **Linux endpoint** — Ubuntu, agent + auditd, for Linux-side detections. No internet, ever.
- **Windows endpoint** — Windows 11, agent + Sysmon, for the bulk of public Sigma content. No internet, ever.
- **Optional:** a second Windows box (client vs. server telemetry) and a Kali/attacker VM for Atomic Red Team-style testing — both follow the same no-internet rule as the endpoints.

---

## 2. Why this stack, right now

- **VirtualBox 7.2** (currently 7.2.18) is free forever for the base package under the GPLv3 — no account, no login, no license key. Since version 7.0 it emulates TPM 2.0 and Secure Boot, so Windows 11 installs and activates its security features normally. Its per-VM **Internal Network** adapter type is exactly what makes the isolation in this guide possible: a network that exists only between VMs which name it, with zero connectivity to the host or the internet — unlike NAT, Bridged, or even Host-only.
- **Wazuh 4.14.8** (23 Sept 2026) is current stable. The single-node "assisted installer" still does manager + indexer + dashboard in one command.
- **Ubuntu 24.04 LTS** is Wazuh's best-tested Linux target today; Ubuntu 26.04 LTS exists but isn't yet on Wazuh's officially-verified OS list, so 24.04 is the safer pick for the server and the Linux endpoint.
- **Sigma tooling** has no official Sigma→Wazuh backend as of this writing. Section 9 gives the current, realistic workflow instead of pretending otherwise.

---

## 3. Network map: server online, endpoints fully isolated

**The design goal: `wazuh-mgr` is the only VM that can ever reach the internet.** `lin-endpoint`, `win-endpoint`, and the optional attacker VM live entirely on a private internal segment they share with the manager, with no path to the internet, the host, or each other's provisioning adapter. This is what VirtualBox's **Internal Network** adapter type gives you natively — the diagram below is what Section 5 builds, step by step.

```text
                         ┌──────────────────────────┐
                         │         INTERNET         │
                         │   package updates only   │
                         └────────────┬─────────────┘
                                      │  Adapter 1: NAT
                                      │  only NIC with internet
 ┌─ Host PC — Windows 11, VirtualBox 7.2 ─ + port-fwd 8443→443 (host reaches dashboard)
 │                                    │
 │                      ┌─────────────┴──────────────┐
 │                      │         wazuh-mgr          │
 │                      │ Ubuntu 24.04 LTS · Wazuh   │
 │                      │ 4.14.8 (mgr+indexer+dash)  │
 │                      │ Adapter 2: 192.168.100.10  │
 │                      └─────────────┬──────────────┘
 │                                    │
 │   Internal Network "detectionlab"  │  192.168.100.0/24
 │   no NAT · no bridge · no DHCP     │
 │  ══════════════╤═══════════════════╧═══════════╤═══════════════
 │                │                   │           │
 │      ┌─────────┴────────┐ ┌────────┴─────────┐ ┌┴ ─ ─ ─ ─ ─ ─ ─ ─ ┐
 │      │   lin-endpoint   │ │   win-endpoint   │   attacker (opt.)
 │      │   Ubuntu 24.04   │ │    Windows 11    │ │  Kali, rolling   │
 │      │  192.168.100.20  │ │  192.168.100.30  │   192.168.100.40
 │      └──────────────────┘ └──────────────────┘ └ ─ ─ ─ ─ ─ ─ ─ ─ ┘
 │
 │   Each endpoint has ONE NIC: Internal Network only.
 │   No route to the internet, the host, or anything outside this segment.
 │   (A temporary NAT adapter is attached only during one-time installs,
 │    then removed — see 5.5)
 └────────────────────────────────────────────────────────────────────────
```

### Adapter and addressing summary

| VM | Adapter 1 | Adapter 2 | Static IP | Internet? |
|---|---|---|---|---|
| `wazuh-mgr` | NAT (permanent) | Internal Network `detectionlab` | 192.168.100.10 | **Yes** — Adapter 1 only |
| `lin-endpoint` | Internal Network `detectionlab` | NAT — temporary, provisioning only | 192.168.100.20 | **No** — never permanent |
| `win-endpoint` | Internal Network `detectionlab` | NAT — temporary, provisioning only | 192.168.100.30 | **No** — never permanent |
| `attacker` (opt.) | Internal Network `detectionlab` | NAT — temporary, provisioning only | 192.168.100.40 | **No** — never permanent |

> **Host access to the dashboard:** the manager's internal-network adapter is invisible to the host by design, so host access goes through a NAT port-forward on `wazuh-mgr`'s *internet-facing* adapter instead (Section 5.4). That's a host↔guest tunnel through the NAT engine, not a route to the internet, so it doesn't touch the endpoints' isolation at all.

---

## 4. Host requirements & VM inventory

Wazuh's own sizing guidance for an all-in-one node monitoring up to 25 agents is 4 vCPU / 8 GiB RAM / 50 GB disk. Add the two endpoints and you get a comfortable lab that fits on a host with 16–32 GB of RAM and an SSD with ~250 GB free.

| VM | Role | OS / image | vCPU | RAM | Disk |
|---|---|---|---|---|---|
| `wazuh-mgr` | Wazuh server, indexer, dashboard | Ubuntu Server 24.04.4 LTS | 4 | 8 GB | 60 GB |
| `lin-endpoint` | Monitored Linux host | Ubuntu Desktop 24.04 LTS (or Debian 12) | 2 | 4 GB | 40 GB |
| `win-endpoint` | Monitored Windows host | Windows 11 Enterprise Evaluation (90-day) | 4 | 8 GB | 60 GB |
| `attacker` (opt.) | Adversary emulation | Kali Linux (rolling) | 2 | 4 GB | 40 GB |

**Host total (core build, no attacker box):** 10 vCPU allocated, 20 GB RAM allocated, ~160 GB disk. VirtualBox over-subscribes CPU fine for a lab; RAM is the real ceiling — 32 GB on the host lets you run everything concurrently without swapping.

*Download sources: Ubuntu Server/Desktop 24.04 LTS from ubuntu.com/download; Windows 11 Enterprise Evaluation (free, 90-day, resettable) from the Microsoft Evaluation Center; Kali from kali.org/get-kali; VirtualBox from virtualbox.org/wiki/Downloads (no account needed).*

---

## 5. Hypervisor and network setup

### 5.1 Install VirtualBox

- Download the Windows host installer from [virtualbox.org/wiki/Downloads](https://www.virtualbox.org/wiki/Downloads) — current series is 7.2.x. The base package is GPLv3, fully free, no account or key required.
- The optional Extension Pack (USB 3.0 passthrough, RDP, PXE boot) is free for personal/educational use if you want it, but nothing in this guide needs it.
- If Windows asks about Hyper-V conflicts, you can leave Hyper-V enabled — VirtualBox 7.x runs fine on top of it. Only disable Hyper-V (`bcdedit /set hypervisorlaunchtype off`, then reboot) if you hit a specific performance problem later.

### 5.2 Create the isolated internal network

VirtualBox has no central network editor like some other hypervisors — each VM's adapters are configured under its own **Settings > Network**. An Internal Network is created simply by giving two or more VMs' adapters the same network name; VirtualBox creates the segment automatically and it is reachable only by VMs that name it.

- **`wazuh-mgr`** — Adapter 1: *NAT* (enabled). Adapter 2: *Internal Network*, name it exactly `detectionlab`.
- **`lin-endpoint` / `win-endpoint` / `attacker`** — Adapter 1: *Internal Network*, same name `detectionlab`. Leave Adapter 2 disabled permanently (Section 5.5 covers the temporary exception for first-time installs).

Equivalent VBoxManage commands, run with each VM powered off:

```bash
VBoxManage modifyvm "wazuh-mgr" --nic1 nat --nic2 intnet --intnet2 "detectionlab"

VBoxManage modifyvm "lin-endpoint" --nic1 intnet --intnet1 "detectionlab"
VBoxManage modifyvm "win-endpoint" --nic1 intnet --intnet1 "detectionlab"
VBoxManage modifyvm "attacker"     --nic1 intnet --intnet1 "detectionlab"    # optional
```

### 5.3 Static IP addressing

An Internal Network has no DHCP server, so every VM needs a static address on it. On `wazuh-mgr` (Ubuntu Server, netplan), confirm interface names with `ip a` first — VirtualBox typically shows the NAT adapter as `enp0s3` and the internal one as `enp0s8`:

```yaml
# /etc/netplan/01-lab.yaml on wazuh-mgr
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: true
    enp0s8:
      dhcp4: no
      addresses: [192.168.100.10/24]
```

```bash
sudo netplan apply
```

On `lin-endpoint`, the single adapter only ever needs the static internal address — deliberately no gateway and no DNS server, so there is never a default route out even by accident:

```yaml
# /etc/netplan/01-lab.yaml on lin-endpoint (Ubuntu Server)
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: no
      addresses: [192.168.100.20/24]
```

*On Ubuntu **Desktop** instead, set the same values under Settings > Network > (wired) > IPv4 > Manual: address 192.168.100.20, netmask 255.255.255.0, gateway and DNS left blank.*

On `win-endpoint` (elevated PowerShell) — check the adapter name first with `Get-NetAdapter`, then assign the address with no gateway:

```powershell
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 192.168.100.30 -PrefixLength 24
```

### 5.4 Port-forward the dashboard for host access

`wazuh-mgr`'s Internal Network adapter is invisible to the host on purpose. To reach the dashboard (and optionally SSH) from your Windows host browser, add NAT port-forward rules on `wazuh-mgr`'s *NAT* adapter instead — this only opens a host↔guest tunnel through the NAT engine and has no effect on the endpoints' isolation:

```bash
VBoxManage modifyvm "wazuh-mgr" --natpf1 "dashboard,tcp,127.0.0.1,8443,,443"
VBoxManage modifyvm "wazuh-mgr" --natpf1 "ssh,tcp,127.0.0.1,2222,,22"       # optional
```

After this, the dashboard is reachable from the host browser at `https://localhost:8443`, and `ssh -p 2222 user@127.0.0.1` reaches a shell.

### 5.5 Temporary internet for one-time downloads

`lin-endpoint`, `win-endpoint`, and the attacker VM will each need internet exactly once or twice — to install the Wazuh agent, Sysmon, auditd packages, or Atomic Red Team. Rather than leaving a second NIC attached permanently, attach it only for that install, then remove it again. These two commands (VM powered off) are referenced by name later in this guide:

```bash
# Turn ON temporary internet (Adapter 2 = NAT)
VBoxManage modifyvm "win-endpoint" --nic2 nat

# ...install what you need, then turn it back OFF...
VBoxManage modifyvm "win-endpoint" --nic2 none
```

*The same pair of commands works for `lin-endpoint` and `attacker`. The temporary adapter gets an address automatically via VirtualBox's built-in NAT DHCP on both Windows and Ubuntu Desktop — no manual IP configuration needed for it.*

### 5.6 Verify the isolation

Before trusting the lab, prove the network actually behaves as designed:

```bash
# On lin-endpoint
ping -c 3 192.168.100.10          # manager -> should SUCCEED
curl -m 5 -sI https://1.1.1.1     # internet -> should FAIL / time out

# On wazuh-mgr
ping -c 3 8.8.8.8                 # internet -> should SUCCEED (via NAT)
ping -c 3 192.168.100.20          # internal reachability -> should SUCCEED
sysctl net.ipv4.ip_forward        # MUST read 0
```

```powershell
# On win-endpoint (PowerShell)
Test-NetConnection 192.168.100.10 -Port 1514   # manager -> should SUCCEED
Test-NetConnection 8.8.8.8 -Port 443           # internet -> should FAIL
```

> ⚠️ **That last check matters most.** If IP forwarding is ever turned on for `wazuh-mgr`, it becomes a router and could hand the endpoints a path to the internet through it, quietly defeating everything above. Ubuntu ships with it off by default — just don't turn it on.

### 5.7 Using VMware Workstation Pro instead

VMware Workstation Pro (also free since Nov 2024) can build the same topology. In **Edit > Virtual Network Editor**, add a custom network (e.g. VMnet3), set it to *Host-only*, and untick "Connect a host virtual adapter" — that last step is what makes it behave like VirtualBox's Internal Network instead of a normal Host-only network the host can still see. Give `wazuh-mgr` a second adapter on VMnet8 (NAT) for internet, and attach every endpoint only to the isolated VMnet. VMware's NAT editor also supports port-forwarding (Edit > Virtual Network Editor > NAT Settings > Add) for the same host-to-dashboard tunnel described in 5.4.

---

## 6. Install Wazuh on the server VM

On **`wazuh-mgr`** (Ubuntu 24.04.4 LTS, fully updated via its NAT adapter), run the official all-in-one assisted installer. This installs the indexer, the manager, and the dashboard on the same host in one pass:

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

When it finishes, it prints the dashboard URL and the admin password. If you missed it, recover every generated password with:

```bash
sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
```

From the **host** browser, open `https://localhost:8443` (the NAT port-forward from 5.4). From another VM already on the internal network, `https://192.168.100.10` works directly. Accept the self-signed certificate warning and log in as `admin`.

Lock the version in place so a stray `apt upgrade` doesn't silently move the manager ahead of your agents:

```bash
sudo sed -i "s/^enabled=1/enabled=0/" /etc/apt/sources.list.d/wazuh.list
```

*Ports used on the internal segment: TCP/UDP 1514 (agent event data), TCP 1515 (agent enrollment). These stay open between VMs on `detectionlab` by default; you don't need to open anything toward the internet-facing NAT adapter for agent traffic at all.*

---

## 7. Deploy the agents

> `lin-endpoint` and `win-endpoint` only have the Internal Network adapter attached (5.2) — no internet. Before installing the agent below, temporarily attach NAT as Adapter 2 using the commands from 5.5, then remove it again once the agent shows up as enrolled.

### 7.1 Linux endpoint (Ubuntu/Debian)

```bash
# Add the Wazuh package repo
sudo apt-get install -y gnupg apt-transport-https curl
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
  gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
sudo chmod 644 /usr/share/keyrings/wazuh.gpg
WAZUH_REPO="https://packages.wazuh.com/4.x/apt/"
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] $WAZUH_REPO stable main" | \
  sudo tee -a /etc/apt/sources.list.d/wazuh.list
sudo apt-get update

# Install + enroll in one line
sudo WAZUH_MANAGER="192.168.100.10" apt-get install -y wazuh-agent

# Start it
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

### 7.2 Windows endpoint

From an elevated PowerShell prompt on `win-endpoint`:

```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.8-1.msi `
  -OutFile $env:tmp\wazuh-agent.msi

msiexec.exe /i $env:tmp\wazuh-agent.msi /q WAZUH_MANAGER="192.168.100.10"

NET START WazuhSvc
```

Once both agents are enrolled, remove the temporary NAT adapter (`VBoxManage modifyvm ... --nic2 none`) before moving on. Back on the dashboard, **Management > Endpoints** should show both agents as "Active" within a minute or two. If an agent stays "Never connected," re-check the Internal Network name and the manager IP before anything else.

---

## 8. Turn on the telemetry Sigma rules actually need

Sigma content is written against specific log sources — mostly Sysmon on Windows and auditd on Linux. Wazuh's default log collection alone won't match most public Sigma rules until you add these.

### 8.1 Windows: Sysmon + expanded Windows logging

> Needs internet for the download — re-attach the temporary NAT adapter from 5.5 first, and remove it again once Sysmon is installed.

- Install Sysmon (Microsoft Sysinternals) with a maintained community config — SwiftOnSecurity's `sysmon-config` for a solid general baseline, or Olaf Hartong's `sysmon-modular` for broader MITRE ATT&CK technique coverage.
- Enable PowerShell Script Block Logging and process command-line auditing (Local Group Policy > Administrative Templates > Windows Components) — a huge share of Sigma's Windows rules key off these two fields.

```powershell
# On win-endpoint (elevated PowerShell)
Invoke-WebRequest -Uri https://live.sysinternals.com/Sysmon64.exe -OutFile Sysmon64.exe

$url = "https://raw.githubusercontent.com/SwiftOnSecurity/" + `
        "sysmon-config/master/sysmonconfig-export.xml"
Invoke-WebRequest -Uri $url -OutFile sysmonconfig.xml

.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

Then tell the Wazuh agent to read the Sysmon channel. On `win-endpoint`, edit `C:\Program Files (x86)\ossec-agent\ossec.conf` and add inside `<ossec_config>`:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
<localfile>
  <location>Microsoft-Windows-PowerShell/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
<localfile>
  <location>Security</location>
  <log_format>eventchannel</log_format>
</localfile>
```

```powershell
NET STOP WazuhSvc
NET START WazuhSvc
```

### 8.2 Linux: auditd + real-time FIM

> Also needs internet for the package — same temporary-NAT pattern as 8.1.

```bash
sudo apt-get install -y auditd audispd-plugins
sudo systemctl enable auditd --now
```

Add Wazuh's real-time, who-data-capable file integrity monitoring so process/user attribution is captured, not just "a file changed" — edit `/var/ossec/etc/ossec.conf` on `lin-endpoint`:

```xml
<syscheck>
  <directories realtime="yes" whodata="yes">/etc,/bin,/sbin</directories>
  <directories realtime="yes" whodata="yes">/usr/bin,/usr/sbin</directories>
</syscheck>
```

```bash
sudo systemctl restart wazuh-agent
```

---

## 9. Importing and running Sigma rules against Wazuh

**The honest state of this integration:** there is still no official, maintained Sigma→Wazuh backend from either the Wazuh or SigmaHQ teams — a request for one has been open on Wazuh's tracker since 2022. What exists instead is a generic conversion pipeline plus a couple of community converters; treat any converted output as a first draft that needs testing, not a drop-in rule.

### 9.1 Check the default ruleset first

Wazuh already ships a large, MITRE ATT&CK-mapped ruleset covering many of the same detections public Sigma rules describe (brute force, LOLBins, common persistence, etc.). Before importing anything, browse **Threat intelligence > MITRE ATT&CK** in the dashboard so you don't duplicate coverage you already have.

### 9.2 Install the Sigma toolchain

Run this on your analysis workstation — the host, or `wazuh-mgr`, since both have internet:

```bash
pip install sigma-cli --break-system-packages
sigma plugin list
sigma plugin install splunk      # or: opensearch, elasticsearch
sigma plugin install sysmon      # field-mapping pipeline for Sysmon-based rules
```

### 9.3 Convert to see the detection logic, then hand-port it

Since there is no Wazuh backend, convert to a close cousin first — Splunk SPL or an OpenSearch/Lucene query both map cleanly onto Wazuh's field names because the Wazuh indexer is itself built on OpenSearch. Use that output as the logic reference while you write the equivalent Wazuh rule.

```bash
sigma convert -t splunk -p sysmon \
  sigma/rules/windows/process_creation/proc_creation_win_mimikatz_command_line.yml
```

Example: a Sigma rule that flags Mimikatz-style command lines becomes this Wazuh custom rule in `/var/ossec/etc/rules/local_rules.xml` on `wazuh-mgr` (rule IDs 100000+ are reserved for custom rules):

```xml
<group name="local,sigma_import,">
  <rule id="100010" level="12">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.commandLine"
           type="pcre2">(?i)sekurlsa|kerberos::|lsadump::|privilege::debug</field>
    <description>Sigma-derived: possible Mimikatz command-line usage</description>
    <mitre>
      <id>T1003.001</id>
    </mitre>
  </rule>
</group>
```

### 9.4 Community shortcuts (unofficial, still verify)

- **sigwaz** — a community web tool and CLI (sigwaz.com) that takes a pasted Sigma YAML rule and returns draft Wazuh XML. Faster than hand-porting, but it's a third-party project, not an official Wazuh integration, so re-check field names and test every rule before trusting it.
- **SigmaHQ's own pySigma pipelines** (the `sysmon` and `windows-logsource` pipelines) keep field names aligned with what your Sysmon config actually emits, which cuts down on false negatives from mismatched field mapping when you port rules manually.

### 9.5 Test before you trust it

Wazuh ships a built-in rule tester that runs a raw log line through your decoders and rules without touching production data. Use it on every imported or hand-ported rule:

```bash
sudo /var/ossec/bin/wazuh-logtest
```

---

## 10. Validate detections with real technique execution

A rule that has never fired on real telemetry is a hypothesis, not a detection. Atomic Red Team gives you small, single-technique tests mapped to MITRE ATT&CK IDs, which is the fastest way to prove a Sigma-derived rule actually alerts.

> Needs internet for the install — re-attach the temporary NAT adapter from 5.5 on `win-endpoint` (or the attacker VM), and remove it again once Atomic Red Team is installed.

```powershell
# On win-endpoint (elevated PowerShell) - or the optional attacker VM against it
$url = 'https://raw.githubusercontent.com/redcanaryco/' + `
        'invoke-atomicredteam/master/install-atomicredteam.ps1'
IEX (IWR $url -UseBasicParsing)
Install-AtomicRedTeam -getAtomics

Invoke-AtomicTest T1003.001   # e.g. an OS-credential-dumping technique
```

Then check **Threat hunting > Events** and the MITRE ATT&CK dashboard on the Wazuh side for the corresponding alert. No alert means one of: the telemetry isn't being collected (recheck Section 8), the rule's field names don't match what's actually logged (recheck the pySigma pipeline mapping), or the rule logic itself needs correcting.

---

## 11. Keeping the lab fast to rebuild

- **Golden snapshots:** snapshot each endpoint right after OS install, and again right after the agent + Sysmon/auditd steps (with the temporary NAT adapter already removed). Revert to the second snapshot after every red-team run.
- **Linked clones:** once `win-endpoint` and `lin-endpoint` are built, use **Machine > Clone** (choose "Linked clone") from their clean snapshots to spin up additional endpoints in seconds instead of reinstalling — the clone inherits the Internal-Network-only adapter automatically, so it stays isolated with zero extra steps.
- **Agent groups:** in the Wazuh dashboard, put `lin-endpoint` and `win-endpoint` in separate groups so you can push OS-specific `agent.conf` overrides (the Sysmon/auditd blocks above) centrally instead of editing each agent by hand.
- **Never leave the provisioning NIC attached:** the temporary NAT adapter from 5.5 should exist only for the minutes it takes to install something. Get in the habit of running the "turn it off" command from 5.5 in the same breath as the install — don't let it linger between sessions.

---

## 12. Quick reference

### VBoxManage cheat-sheet

```bash
# Temporary internet on / off for an endpoint (see 5.5)
VBoxManage modifyvm "<vm>" --nic2 nat
VBoxManage modifyvm "<vm>" --nic2 none

# Dashboard / SSH port-forward on wazuh-mgr (see 5.4)
VBoxManage modifyvm "wazuh-mgr" --natpf1 "dashboard,tcp,127.0.0.1,8443,,443"
VBoxManage modifyvm "wazuh-mgr" --natpf1 "ssh,tcp,127.0.0.1,2222,,22"

# List a VM's current network config (Windows host)
VBoxManage showvminfo "<vm>" --machinereadable | findstr /i "nic intnet"
```

### Wazuh command cheat-sheet

```bash
# Wazuh manager status / restart
sudo systemctl status wazuh-manager
sudo systemctl restart wazuh-manager

# Agent status from the manager
sudo /var/ossec/bin/agent_control -l

# Rule/decoder syntax test
sudo /var/ossec/bin/wazuh-logtest

# Recover install passwords
sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
```

### Reference links

- Wazuh quickstart & install assistant — <https://documentation.wazuh.com/current/quickstart.html>
- Wazuh release notes (current: 4.14.8) — <https://documentation.wazuh.com/current/release-notes/>
- VirtualBox downloads & docs — <https://www.virtualbox.org/wiki/Downloads>
- VMware Workstation Pro (alternative) — <https://support.broadcom.com>
- Ubuntu 24.04 LTS download — <https://ubuntu.com/download/server> and <https://ubuntu.com/download/desktop>
- Windows 11 Enterprise Evaluation (90-day) — <https://www.microsoft.com/evalcenter>
- SigmaHQ rule repository & sigma-cli — <https://github.com/SigmaHQ/sigma>, <https://github.com/SigmaHQ/sigma-cli>
- SwiftOnSecurity Sysmon config — <https://github.com/SwiftOnSecurity/sysmon-config>
- Olaf Hartong sysmon-modular (broader MITRE coverage) — <https://github.com/olafhartong/sysmon-modular>
- Atomic Red Team — <https://github.com/redcanaryco/atomic-red-team>
- Wazuh custom rules & wazuh-logtest docs — <https://documentation.wazuh.com/current/user-manual/ruleset/>

---

*This guide reflects the state of Wazuh, VirtualBox, and the Sigma ecosystem as of late September 2026. Package versions and download URLs (especially the Wazuh `4.14` paths) will move forward over time — check documentation.wazuh.com for the current release before a fresh build.*
