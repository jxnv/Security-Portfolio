# LimaCharlie × Wazuh — Lab Integration

**Adding LimaCharlie's free-tier EDR sensors, native Sigma engine, and live-response tooling to the isolated VirtualBox detection-engineering lab**

*Companion to `Detection-Engineering-Home-Lab.md` (same VM names, same `192.168.100.0/24` "detectionlab" network).
---

## Table of contents

0. [Read this first](#0-read-this-first)
1. [What LimaCharlie adds to the lab](#1-what-limacharlie-adds-to-the-lab)
2. [The free tier: what you actually get](#2-the-free-tier-what-you-actually-get)
3. [The isolation conflict, and the design decision](#3-the-isolation-conflict-and-the-design-decision)
4. [Setup, phase by phase](#4-setup-phase-by-phase)
5. [Telemetry configuration](#5-telemetry-configuration)
6. [Detection capabilities](#6-detection-capabilities)
7. [Response capabilities](#7-response-capabilities)
8. [Wazuh ↔ LimaCharlie bridges](#8-wazuh--limacharlie-bridges)
9. [Extensions catalog](#9-extensions-catalog)
10. [End-to-end validation plan](#10-end-to-end-validation-plan)
11. [Operating model and lab hygiene](#11-operating-model-and-lab-hygiene)
12. [Troubleshooting](#12-troubleshooting)
13. [Quick reference and links](#13-quick-reference-and-links)
14. [Verification status and open questions](#14-verification-status-and-open-questions)

---

## 0. Read this first

**What you get:** a cloud-managed EDR layer on top of Wazuh — deep process/network/DNS telemetry from the sensors, a **native Sigma engine** (which closes the gap the first guide flagged: Wazuh has no official Sigma backend, LimaCharlie does), 1 year of searchable telemetry, live-response commands, YARA scanning, memory/forensic collection, and Atomic Red Team execution straight from the console. Wazuh keeps what it is best at: log analysis, FIM, SCA, vulnerability detection, and the local SIEM/dashboard.

**Three things you need to know before you build anything:**

1. **LimaCharlie sensors must reach the LimaCharlie cloud.** The sensor needs one outbound TCP/443 connection to a LimaCharlie domain. That directly conflicts with your rule that the workstations get no internet access of any kind. I did not quietly bend your rule — Section 3 lays out the options and recommends one (an allow-listed proxy on `wazuh-mgr`). **You need to decide** whether you accept it.
2. **The free tier covers 2 endpoints.** That is exactly `lin-endpoint` + `win-endpoint`. The attacker VM and `wazuh-mgr` cannot also run sensors on the free tier (Section 2).
3. **LimaCharlie cannot push detections into your lab.** `wazuh-mgr` sits behind NAT with no inbound path, so LimaCharlie's outputs (syslog/webhook) have nowhere to land. The Wazuh bridge in Section 8 therefore **polls** the LimaCharlie API from `wazuh-mgr` instead.

---

## 1. What LimaCharlie adds to the lab

| Capability | Wazuh (existing) | LimaCharlie (new) | Combined value |
|---|---|---|---|
| Endpoint telemetry | Logs, Sysmon channel, auditd, FIM | Kernel-level process, network, DNS, file, module events (eBPF on Linux) | Two independent telemetry sources per host — compare what each sees |
| Sigma rules | No official backend; hand-port to XML | **Native**: LimaCharlie maintains the Sigma backend and a free managed ruleset, re-processed every 15 minutes | Sigma runs natively in LimaCharlie; Wazuh keeps hand-ported rules — two engines, cross-check detections |
| Custom detection | XML rules + decoders | D&R rules (YAML), stateful rules, LCQL hunting, replay against history | Prototype in LimaCharlie, port winners to Wazuh (or vice versa) |
| Response | Active Response scripts | Live console, `deny_tree`, kill/delete/collect, network isolation, automatic D&R responses | Wazuh detects/alerts; LimaCharlie contains/investigates |
| Retention | Local indexer (disk-bound) | 1 year of telemetry included | Long-term history without growing the lab disk |
| Adversary emulation | Atomic Red Team installed by hand | Atomic Red Team **extension** (Windows sensors) runs tests from the console | One-click test, then see both tools' alerts |
| Forensics | — | YARA, Velociraptor, memory dumps, artifact collection, Hayabusa/Plaso | Triage depth Wazuh does not provide |
| Compliance/vuln | SCA, vulnerability detector | Vulnerability reporting extension | Wazuh stays primary here |

---

## 2. The free tier: what you actually get

| Item | Free (Community Edition) | Source / note |
|---|---|---|
| EDR sensors | **Up to 2 endpoints**, free | Current pricing page. Older docs mention "two organizations with two sensors each" — check what your account actually shows |
| Telemetry storage | 1 year | Included |
| Detect & respond at wire speed | Yes (isolate, kill process tree, collect, etc.) | Included |
| Telemetry sources (adapters, logs) | Listed as free on Community | Docs' billing page lists usage rates for these; confirm in your account |
| Sensor price beyond free | $3.00/sensor/month (Windows, macOS, Linux, Docker) | Standard tier |
| Chrome / ChromeOS / Edge sensors | $0.30/sensor/month | Not free |

### Assigning the two free slots

| Slot | VM | Why |
|---|---|---|
| 1 | `win-endpoint` | Windows is where most public Sigma content and the Atomic Red Team extension apply |
| 2 | `lin-endpoint` | Linux eBPF sensor; Ubuntu 24.04's kernel far exceeds the 4.4 minimum |
| — | `wazuh-mgr` | **No sensor.** It joins LimaCharlie as an *adapter* (log ingestion), which is usage-billed telemetry, not an endpoint slot (Section 8) |
| — | `attacker` (optional) | No free slot. Skip it, or temporarily swap it in for an endpoint you uninstall |

### Cost traps to avoid

- **Hayabusa** extension: free to enable, but billed per GB of processed artifacts (about $0.02/GB original, $0.50/GB generated).
- **Zeek** extension: free to enable, $0.02/GB of processed PCAP.
- **Soteria managed rulesets:** $0.50/endpoint/month — not free. Use the free Sigma and Community rulesets instead.
- **Uploading whole `.evtx` files** counts as artifact ingestion. Streaming `wel://` events does **not** — it is included in the sensor price (Section 5).
- **AI sessions / MCP assistants:** you bring your own AI provider; that is your provider's bill, and lab telemetry leaves your environment to reach it.

---

## 3. The isolation conflict, and the design decision

### The problem

*only the server has internet; the workstations gain no access of any kind.*
LimaCharlie's sensor: *needs one outbound TCP/443 connection to a LimaCharlie domain, always.*

These cannot both be 100% true. Documented facts that shape the options:

- The sensor supports **unauthenticated HTTP `CONNECT` proxying** via the `LC_PROXY` environment variable. It does **not** support SSL interception.
- LimaCharlie's own network isolation blocks every destination **except the LimaCharlie cloud**.
- Windows sensors perform certificate-revocation checks that can stall on restricted networks; `LC_LOCAL_CACHE_ONLY_REVOCATION_CHECK=1` stops them reaching out.

### Options

| | Option A — Allow-listed proxy on `wazuh-mgr` (**recommended**) | Option B — Session-based (strict air gap) | Option C — Skip LimaCharlie on endpoints |
|---|---|---|---|
| How | Squid on `wazuh-mgr` allows `CONNECT` to `*.limacharlie.io` only. Endpoints set `LC_PROXY` | Endpoints stay offline. You attach the temporary NAT adapter (guide §5.5) only for deliberate "LimaCharlie sessions" | Only `wazuh-mgr` uses LimaCharlie (adapter) |
| Endpoint internet? | **No routed internet.** They can open a proxied tunnel to LimaCharlie's domain only | None, except during sessions | None |
| Violates your rule? | **Technically yes, narrowly:** endpoints can talk to one vendor cloud via the proxy | No, except during sessions | No |
| Live response / continuous Sigma | Always on | Only while a session is open | None on endpoints |
| LimaCharlie network isolation | **Likely breaks the sensor's own link** (see §7) | Works in a session (direct path) | n/a |
| Effort | Medium | Low, but repetitive | Low |

**Recommendation: Option A.** It keeps the structural guarantees of your design — no default route, no DNS, no IP forwarding, no second NIC — and narrows the exception to a single destination at the application layer. If "any kind of access" is a hard line for you, choose Option B; every procedure in this report still applies, you just open a session first.

### What does not change under Option A

- Endpoints keep **one NIC**: Internal Network `detectionlab`. No gateway, no DNS.
- `net.ipv4.ip_forward` on `wazuh-mgr` **stays 0**. A proxy is an application-layer relay; it does not route.
- Squid binds **only** to `192.168.100.10`, never to the NAT adapter.
- The temporary-NAT pattern (guide §5.5) is still used for installs and downloads.

### Updated network map (Option A)

```text
                         ┌──────────────────────────┐
                         │  INTERNET / LimaCharlie  │
                         │   cloud (*.limacharlie.io)│
                         └────────────┬─────────────┘
                                      │ Adapter 1: NAT (only NIC with internet)
 ┌─ Host PC — Windows 11, VirtualBox 7.2 ─────────────────────────────────────┐
 │                                    │                                        │
 │                      ┌─────────────┴──────────────┐                         │
 │                      │         wazuh-mgr          │                         │
 │                      │ Wazuh 4.14.8 + Squid :3128 │                         │
 │                      │ + LC adapter + LC poller   │                         │
 │                      │ Adapter 2: 192.168.100.10  │                         │
 │                      └─────────────┬──────────────┘                         │
 │   Internal Network "detectionlab"  │  192.168.100.0/24                      │
 │  ══════════════╤═══════════════════╧═══════════╤═════════════════           │
 │                │  1514/1515 (Wazuh agent)      │                            │
 │                │  3128 (proxy → LC cloud only) │                            │
 │      ┌─────────┴────────┐              ┌───────┴──────────┐                 │
 │      │   lin-endpoint   │              │   win-endpoint   │                 │
 │      │ Wazuh agent      │              │ Wazuh agent      │                 │
 │      │ + LC sensor      │              │ + Sysmon         │                 │
 │      │ 192.168.100.20   │              │ + LC sensor      │                 │
 │      └──────────────────┘              │ 192.168.100.30   │                 │
 │                                        └──────────────────┘                 │
 └─────────────────────────────────────────────────────────────────────────────┘
   Endpoints: ONE NIC, no gateway, no DNS. The only path off-segment is the
   proxy, which allows CONNECT to *.limacharlie.io and refuses everything else.
```

---

## 4. Setup, phase by phase

### Phase A — Create the LimaCharlie organization

1. Sign up at [app.limacharlie.io](https://app.limacharlie.io) (Community Edition, no card required for the free tier).
2. Create an **Organization**. **Choose the datacenter region deliberately** — it determines where telemetry is processed/stored and which sensor domain you must allow-list.
3. In the web app, open **Sensors → Add Sensor** (the Sensor Downloads page). Note the **exact hostnames and ports** listed there for your region, including any separate Artifact Collection destination. Section 4, Phase C uses them.
4. Note your **Organization ID (OID)** (Organization settings).

### Phase B — Installation keys and an API key

**Installation keys** enroll sensors into the org and can carry tags that are applied automatically.

1. **Sensors → Installation Keys → Create Installation Key.**
2. Create three keys, so you can filter and write rules by tag:

   | Key description | Tags |
   |---|---|
   | `lab-windows` | `lab`, `windows`, `deploy-sysmon` (the last one only if you later use the payload deployment in §5) |
   | `lab-linux` | `lab`, `linux` |
   | `lab-wazuh-adapter` | `lab`, `wazuh` |

3. **API key** (for the Wazuh poller in §8): **Access Management → API Keys → Create**, with the minimum permission to read detections (the detections-read permission, `insight.det.get` in LimaCharlie's permission scheme — confirm the exact name in the permission picker). Store the key like a password.

### Phase C — Egress proxy on `wazuh-mgr` (Option A only)

Skip this phase entirely for Option B.

On `wazuh-mgr` (internet via its NAT adapter):

```bash
sudo apt-get update
sudo apt-get install -y squid
```

Replace `/etc/squid/squid.conf` with a minimal allow-list (back up the original first with `sudo cp /etc/squid/squid.conf /etc/squid/squid.conf.orig`):

```text
# /etc/squid/squid.conf  — LimaCharlie-only CONNECT relay
http_port 192.168.100.10:3128

acl lab_net    src 192.168.100.0/24
acl ssl_ports  port 443
acl lc_domains dstdomain .limacharlie.io
acl CONNECT    method CONNECT

# The ONLY thing allowed: CONNECT to LimaCharlie on 443, from the lab net
http_access allow CONNECT ssl_ports lc_domains lab_net
http_access deny all

cache deny all
access_log /var/log/squid/access.log
```

```bash
sudo squid -k parse          # syntax check
sudo systemctl enable --now squid
sudo systemctl restart squid
ss -ltnp | grep 3128         # must show 192.168.100.10:3128, NOT 0.0.0.0
sysctl net.ipv4.ip_forward   # must still read 0
```

If the Add Sensor page showed a hostname **outside** `limacharlie.io` for artifact collection, add another `acl lc_domains dstdomain <host>` line.

**Test the allow-list from an endpoint** (once it can reach the proxy — the proxy path needs no NAT adapter):

```powershell
# win-endpoint
curl.exe -I -x http://192.168.100.10:3128 https://app.limacharlie.io   # allowed -> normal response
curl.exe -I -x http://192.168.100.10:3128 https://example.com          # must be REFUSED (403 / connection error)
```

```bash
# lin-endpoint
curl -I -x http://192.168.100.10:3128 https://app.limacharlie.io
curl -I -x http://192.168.100.10:3128 https://example.com               # must be refused
```

If `example.com` goes through, stop and fix Squid before continuing.

### Phase D — Windows sensor on `win-endpoint`

**Order matters:** install while the temporary NAT adapter is attached (direct enrollment, binary download), then switch the sensor to the proxy, then remove the NAT adapter.

1. **Temporarily attach NAT** (VM powered off; guide §5.5):

   ```bash
   VBoxManage modifyvm "win-endpoint" --nic2 nat
   ```

2. In an elevated PowerShell on `win-endpoint`, download and install (the installer is `rphcp.exe`; `-i` installs it as a service with your key):

   ```powershell
   $key = "PASTE_lab-windows_INSTALLATION_KEY"
   Invoke-WebRequest -Uri https://downloads.limacharlie.io/sensor/windows/64 -OutFile $env:TEMP\rphcp.exe
   & $env:TEMP\rphcp.exe -i $key
   ```

   MSI alternative (for scripted installs): `msiexec /i "installer.msi" /qn INSTALLATIONKEY="<key>"`.

3. **Verify the service and enrollment:**

   ```powershell
   Get-Service rphcpsvc | Select-Object Name, Status, StartType     # Running / Automatic
   ```

   In the web app, **Sensors** should list `win-endpoint` as online within a few minutes.

4. **Switch to the proxy** (Option A):

   ```powershell
   setx /M LC_PROXY "192.168.100.10:3128"
   setx /M LC_LOCAL_CACHE_ONLY_REVOCATION_CHECK "1"
   Restart-Service rphcpsvc      # if the sensor does not pick it up, reboot the VM
   ```

5. **Remove the temporary NAT adapter** (VM powered off):

   ```bash
   VBoxManage modifyvm "win-endpoint" --nic2 none
   ```

6. Boot the VM and confirm the sensor is **still online** in the web app. If it is, the proxy path works. Check Squid's log on `wazuh-mgr`:

   ```bash
   sudo tail -f /var/log/squid/access.log      # expect CONNECT lines to *.limacharlie.io:443
   ```

> **Antivirus note:** Defender may flag or quarantine lab tooling and some Atomic Red Team files. In a disposable lab VM, add an exclusion for `C:\Windows\System32\rphcp.exe` and for your test directory rather than disabling Defender.

### Phase E — Linux sensor on `lin-endpoint`

1. **Temporarily attach NAT:**

   ```bash
   VBoxManage modifyvm "lin-endpoint" --nic2 nat
   ```

2. Install with the sensor binary (the Linux sensor uses eBPF; kernel 4.4+ required):

   ```bash
   KEY="PASTE_lab-linux_INSTALLATION_KEY"
   wget https://downloads.limacharlie.io/sensor/linux/64 -O /tmp/lc_sensor
   chmod +x /tmp/lc_sensor
   sudo /tmp/lc_sensor -i "$KEY"
   ```

   A Debian package is also offered (`https://downloads.limacharlie.io/sensor/linux/deb64`); it takes the key through debconf. The binary route above is the simplest for a one-off.

3. Confirm it enrolled (web app → **Sensors**), then find the service name:

   ```bash
   systemctl list-units --type=service | grep -i -E 'lima|rphcp'
   ```

4. **Switch to the proxy** with a systemd drop-in (substitute the service name found above; `limacharlie` is the package name):

   ```bash
   sudo systemctl edit limacharlie
   ```

   ```ini
   [Service]
   Environment=LC_PROXY=192.168.100.10:3128
   ```

   ```bash
   sudo systemctl restart limacharlie
   ```

5. **Remove the temporary NAT adapter** (VM powered off): `VBoxManage modifyvm "lin-endpoint" --nic2 none`, boot, and confirm the sensor stays online.

### Phase F — Verify the whole chain

| Check | Expected |
|---|---|
| Web app → Sensors | `win-endpoint` and `lin-endpoint` both **online**, with the tags from their keys |
| `ping 8.8.8.8` / `curl https://example.com` on an endpoint (no proxy flag) | **Fail** — isolation intact |
| `curl -x http://192.168.100.10:3128 https://example.com` | **Refused** — allow-list working |
| Squid log | Only `CONNECT …limacharlie.io:443` entries |
| `sysctl net.ipv4.ip_forward` on `wazuh-mgr` | `0` |
| Wazuh dashboard → Endpoints | Both Wazuh agents still **Active** |

---

## 5. Telemetry configuration

### 5.1 Subscribe to the extensions you need

In the web app: **Add-ons / Marketplace → subscribe your organization** to each (they are per-org):

| Extension | Why you need it here |
|---|---|
| **Reliable Tasking** | Prerequisite for Artifact |
| **Artifact** | Enables Artifact Collection rules, including streaming Windows Event Logs |
| **Sigma** (managed ruleset) | Free native Sigma rules (Section 6) |
| **Atomic Red Team** | Run ATT&CK tests from the console (Windows sensors) |
| **YARA Manager / YARA** | On-demand and scheduled YARA scanning |
| **Payload Manager** | Upload files (e.g., Sysmon, configs) to push to sensors |

Others (Integrity, Exfil, Dumper, Velociraptor, Hayabusa, Cases, Playbook, Lookup Manager, Git Sync) are covered in Section 9.

### 5.2 Event collection

**Event Collection → Event Collection Rules** (Exfil control): make sure the event types you want are streamed for Windows and Linux, in particular **`WEL`** (Windows Event Log) for Windows. Many managed Sigma rules rely on Windows Event Logs that LimaCharlie does **not** collect by default, so this step is what makes them fire.

### 5.3 Stream Windows Event Logs into the sensor timeline

Go to **Sensors → Artifact Collection** and add rules. A `wel://` rule is a *live* API request from the sensor, not a file at rest; events arrive in the sensor timeline as `WEL` events and are included in the flat sensor price.

| Rule path | Purpose |
|---|---|
| `wel://Security:*` | Logons, process creation (4688), account changes |
| `wel://Microsoft-Windows-PowerShell/Operational:*` | Script-block logging (4104) |
| `wel://Microsoft-Windows-Sysmon/Operational:*` | Sysmon (you already run it for Wazuh) |
| `wel://Microsoft-Windows-Windows Defender/Operational:*` | Defender detections |
| `wel://Microsoft-Windows-Sysmon/Operational:1` | Example of filtering to one event ID |

Allow up to ~10 minutes for a new rule to sync to the sensor. Verify in **Sensors → (sensor) → Timeline**, filter event type `WEL`.

**Overlap note:** LimaCharlie's native EDR events mirror much of what Sysmon provides. You are streaming Sysmon into *both* tools on purpose, so you can compare their coverage; if you want lower overhead, stream only the Sysmon event IDs you need.

### 5.4 Sysmon via LimaCharlie payloads (optional)

Instead of the temp-NAT download in the original guide, you can push Sysmon from LimaCharlie: upload `sysmon.exe` and `sysmon-config.xml` with Payload Manager, tag the sensor `deploy-sysmon`, and use a D&R rule whose actions are `put` the payload, `run --shell-command "C:\Windows\Temp\sysmon.exe -accepteula -i C:\Windows\Temp\sysmon-config.xml"`, then `file_del` the files. You already installed Sysmon in the original guide, so this is only useful for rebuilds.

### 5.5 Linux logs (optional)

The Linux sensor is eBPF-based EDR. For auditd/syslog content, LimaCharlie provides log-collection adapters (file/syslog types) — but an adapter is a separate process that also needs a path to the cloud. In this lab, **Wazuh already ingests those Linux logs**, so don't duplicate them under LimaCharlie unless you want to test that adapter path.

---

## 6. Detection capabilities

### 6.1 Native Sigma — the biggest win for this lab

LimaCharlie maintains the **LimaCharlie backend for Sigma**, so most Sigma rules convert to its D&R format.

**One-click managed ruleset (free):** subscribe the org to the **Sigma** add-on. LimaCharlie re-processes the hundreds of SigmaHQ rules into your org **every 15 minutes**, no management required. Detections from managed Sigma rules have the author **`_sigma`**.

**Convert your own rules** with the public converter service (this sends the rule to LimaCharlie's cloud — run it from the host or `wazuh-mgr`, not an endpoint):

```bash
# single rule -> D&R rule (target: edr by default, or artifact)
curl -X POST https://sigma.limacharlie.io/convert/rule \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode "rule@my-rule-file.yaml"

# a whole SigmaHQ folder
curl -X POST https://sigma.limacharlie.io/convert/repo \
  -d "repo=https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation"
```

If you use `sigma-cli` (from the first guide), check whether the LimaCharlie backend plugin is listed and install it:

```bash
sigma plugin list | grep -i limacharlie
sigma plugin install limacharlie     # only if listed
```

**Workflow that uses both engines:** convert a Sigma rule to LimaCharlie (native, no hand-porting), run the Atomic test, then hand-port the same logic to Wazuh XML (guide §9) and compare which tool fired, when, and with what context.

### 6.2 Other managed rulesets

| Ruleset | Cost | Note |
|---|---|---|
| Sigma | Free | Section 6.1 |
| Community Rules | Free | LimaCharlie's community-maintained rules (see docs → Managed Rulesets) |
| SOC Prime | Varies | Third-party; check pricing |
| Soteria EDR | $0.50/endpoint/month | **Not free** |

Managed rulesets are tuned for general environments. Tune them with the False Positive rules feature instead of deleting rules.

### 6.3 Custom D&R rules

A Detection & Response rule is a `detect:` block (what to match) plus a `respond:` block (what to do). Examples to paste into **Automation → D&R Rules**:

**Detect-only — credential-dumping command lines**

```yaml
# detect
event: NEW_PROCESS
op: and
rules:
  - op: contains
    path: event/COMMAND_LINE
    value: sekurlsa
    case sensitive: false
```

```yaml
# respond
- action: report
  name: lab-credential-dumping-cmdline
- action: add tag
  tag: needs-triage
  ttl: 86400
```

**Detect + contain — kill the process tree (works under Option A)**

```yaml
# detect
event: NEW_PROCESS
op: ends with
path: event/FILE_PATH
value: mimikatz.exe
case sensitive: false
```

```yaml
# respond
- action: report
  name: lab-mimikatz-executed
- action: task
  command: deny_tree <<routing/this>>
```

**Stateful and behavioral rules, sensor variables, and unit tests** are also available — see the D&R documentation. Add **unit tests** to each rule so a rule edit cannot silently break it.

### 6.4 LCQL hunting

LimaCharlie Query Language searches the retained telemetry from the **Query Console**. Typical hunts for this lab (consult the LCQL reference for exact syntax):

```text
-24h | plat == windows | NEW_PROCESS | event/COMMAND_LINE contains "powershell"
-24h | plat == windows | NEW_PROCESS | event/FILE_PATH ends with "rundll32.exe"
-7d  | plat == linux   | NEW_PROCESS | event/COMMAND_LINE contains "curl"
```

### 6.5 Replay and config-as-code

Test a rule against **historical** telemetry before you deploy it, and keep your rules in version control:

```bash
pip install limacharlie
limacharlie login
limacharlie org list                           # find your OID
limacharlie dr list
limacharlie dr export > rules.yaml             # back up D&R rules
limacharlie dr import --input-file rules.yaml  # restore / apply
limacharlie dr replay --name my-rule --start <epoch> --end <epoch>
```

The **Git Sync** extension can keep the org configuration in a Git repository.

---

## 7. Response capabilities

### 7.1 Interactive: the sensor console

In the web app, **Sensors → (sensor) → Console** lets you run endpoint commands live. The Endpoint Commands reference is the authority for exact syntax and platform support; the families you will use most:

| Family | Examples (see reference for availability per OS) |
|---|---|
| Interrogate | list processes, network connections, services, autoruns, drivers, directory listings, registry |
| Collect | pull a file, file info, process memory strings/maps, history dump |
| Contain | kill process, `deny_tree`, delete file, network isolation |
| Scan | YARA scan (files, processes, memory) |

### 7.2 Automatic: D&R response actions

- `report` — create a LimaCharlie detection
- `add tag` / `remove tag` (optional `ttl`)
- `task` — run any sensor command (e.g., `deny_tree <<routing/this>>`)
- `isolate network` / `rejoin network` — persistent isolation (§7.3)
- `add var` / `del var`
- `extension request` — call an extension (e.g., Hayabusa, YARA, Atomic Red Team)

### 7.3 Network isolation — the caveat for this lab

LimaCharlie's isolation blocks all destinations **except the LimaCharlie cloud**. Under Option A, the sensor reaches the cloud *through the proxy at `192.168.100.10`* — and that proxy address is not the LimaCharlie cloud. Expect an isolated sensor to **lose its own connection** and become unreachable. The D&R `isolate network` action is **persistent**, and LimaCharlie warns not to upgrade a sensor while it is isolated. **Treat isolation as unsafe under Option A** and do not wire it into automatic rules. Use `deny_tree`, process kill, and file deletion instead.

**To exercise isolation deliberately (untested here, direct-mode session):**

1. Attach the temporary NAT adapter (guide §5.5).
2. Disable the proxy for the session — on Windows set `LC_PROXY` to `!`; on Linux remove the drop-in override — and restart the sensor service.
3. Run `isolate network` from the console, confirm the host loses its Wazuh link but the sensor stays online, then run `rejoin network`.
4. Restore `LC_PROXY`, remove the NAT adapter, snapshot-revert if anything looks wrong.

**Recovery if a sensor gets stuck isolated:** attach the temporary NAT adapter and disable the proxy as above so the sensor has a direct route, then issue `rejoin network`; failing that, revert the VM to the golden snapshot.

### 7.4 Wazuh Active Response vs LimaCharlie response

| Need | Use |
|---|---|
| Block an IP / disable an account / run a local script on a Wazuh alert | Wazuh Active Response |
| Kill a malicious process tree on detection | LimaCharlie D&R (`deny_tree`) |
| Collect evidence from a live host | LimaCharlie console / artifacts |
| Scan memory or disk with YARA | LimaCharlie YARA |

---

## 8. Wazuh ↔ LimaCharlie bridges

Neither product ships an integration with the other, so these are two small, deliberate bridges. Both run on `wazuh-mgr`, the only VM with direct internet.

### 8.1 Bridge A — Wazuh alerts → LimaCharlie (file adapter)

Ingest `alerts.json` as telemetry so LimaCharlie can search it, write D&R rules over it, and pivot between Wazuh alerts and EDR events by hostname.

1. Create the `lab-wazuh-adapter` installation key (Phase B).
2. Download the adapter on `wazuh-mgr`:

   ```bash
   sudo mkdir -p /opt/lc-adapter /etc/lc-adapter
   sudo wget https://downloads.limacharlie.io/adapter/linux/64 -O /opt/lc-adapter/lc-adapter
   sudo chmod +x /opt/lc-adapter/lc-adapter
   ```

3. Configuration:

   ```yaml
   # /etc/lc-adapter/wazuh.yaml   (chmod 600 — it holds a key)
   file:
     client_options:
       identity:
         oid: "YOUR-ORG-ID"
         installation_key: "PASTE_lab-wazuh-adapter_KEY"
       platform: "json"
       sensor_seed_key: "wazuh-alerts"
       hostname: "wazuh-mgr-alerts"
       mapping:
         event_type_path: "wazuh_alert"
     file_path: "/var/ossec/logs/alerts/alerts.json"
     poll: true
   ```

   `poll: true` is the documented fix for adapters that stop collecting after log rotation — Wazuh rotates `alerts.json` daily.

4. Systemd unit:

   ```ini
   # /etc/systemd/system/lc-adapter-wazuh.service
   [Unit]
   Description=LimaCharlie adapter - Wazuh alerts
   After=network-online.target wazuh-manager.service

   [Service]
   ExecStart=/opt/lc-adapter/lc-adapter file /etc/lc-adapter/wazuh.yaml
   Restart=always

   [Install]
   WantedBy=multi-user.target
   ```

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now lc-adapter-wazuh
   ```

5. In LimaCharlie, a new sensor named `wazuh-mgr-alerts` should appear; its timeline shows the events. If the event type shows as something unexpected, change `event_type_path` to a real JSON field (the mapping accepts field paths and templates).

**Why this is worthwhile:** a LimaCharlie D&R rule can now fire when a specific Wazuh rule ID appears, and the two data sets can be queried together.

### 8.2 Bridge B — LimaCharlie detections → Wazuh (API poller)

LimaCharlie's outputs push to a reachable destination. `wazuh-mgr` has none, so instead it **pulls** detections from the REST API on a timer, writes normalized JSON lines to a file, and Wazuh reads that file like any other log.

**1. Credentials file** (`root`-only):

```bash
sudo install -d -m 700 /etc/lc-bridge
sudo tee /etc/lc-bridge/env >/dev/null <<'EOF'
LC_OID=YOUR-ORG-ID
LC_API_KEY=YOUR-API-KEY
EOF
sudo chmod 600 /etc/lc-bridge/env
sudo apt-get install -y python3-requests
sudo install -d -m 755 /var/log/limacharlie /var/lib/lc-bridge
```

**2. The poller** — `/usr/local/bin/lc-detections-to-wazuh.py`:

```python
#!/usr/bin/env python3
"""Poll LimaCharlie detections and append normalized JSON lines for Wazuh."""
import json, os, time, requests

OID, KEY = os.environ["LC_OID"], os.environ["LC_API_KEY"]
STATE = "/var/lib/lc-bridge/state.json"
OUT = "/var/log/limacharlie/detections.json"
API = f"https://api.limacharlie.io/v1/insight/{OID}/detections"

def jwt():
    r = requests.post("https://jwt.limacharlie.io",
                      data={"oid": OID, "secret": KEY}, timeout=30)
    r.raise_for_status()
    return r.json()["jwt"]

def load():
    try:
        with open(STATE) as f:
            return json.load(f)
    except Exception:
        return {"last_end": int(time.time()) - 3600, "seen": []}

def main():
    st, now = load(), int(time.time())
    seen = set(st["seen"])
    hdr = {"Authorization": f"Bearer {jwt()}"}
    start, cursor, new = st["last_end"] - 120, "-", []   # 2-min overlap, dedup by id
    while cursor:
        r = requests.get(API, headers=hdr, timeout=60, params={
            "start": start, "end": now, "limit": 500, "cursor": cursor})
        r.raise_for_status()
        body = r.json()
        for d in body.get("detects", []) or []:
            did = d.get("detect_id") or d.get("id") or json.dumps(d, sort_keys=True)[:64]
            if did in seen:
                continue
            seen.add(did)
            routing = d.get("routing") or (d.get("detect") or {}).get("routing") or {}
            new.append({
                "integration": "limacharlie",
                "lc_id": did,
                "lc_cat": d.get("cat", "unknown"),
                "lc_author": d.get("author", ""),
                "lc_priority": str(d.get("priority", "")),
                "lc_hostname": routing.get("hostname", ""),
                "lc_sid": routing.get("sid", ""),
                "lc_link": d.get("link", ""),
                "lc_event": json.dumps(d.get("detect", {}))[:2000],
            })
        cursor = body.get("next_cursor") or None
    with open(OUT, "a") as f:
        for n in new:
            f.write(json.dumps(n) + "\n")
    st = {"last_end": now, "seen": list(seen)[-5000:]}
    with open(STATE, "w") as f:
        json.dump(st, f)
    print(f"wrote {len(new)} detections")

if __name__ == "__main__":
    main()
```

```bash
sudo chmod 755 /usr/local/bin/lc-detections-to-wazuh.py
```

**3. Run it every minute** with a service + timer:

```ini
# /etc/systemd/system/lc-bridge.service
[Unit]
Description=LimaCharlie detections to Wazuh

[Service]
Type=oneshot
EnvironmentFile=/etc/lc-bridge/env
ExecStart=/usr/local/bin/lc-detections-to-wazuh.py
```

```ini
# /etc/systemd/system/lc-bridge.timer
[Unit]
Description=Poll LimaCharlie detections every minute

[Timer]
OnBootSec=60
OnUnitActiveSec=60

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now lc-bridge.timer
sudo systemctl start lc-bridge.service && sudo journalctl -u lc-bridge.service -n 20
```

**4. Tell Wazuh to read the file** — add to `/var/ossec/etc/ossec.conf` on `wazuh-mgr`:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/limacharlie/detections.json</location>
</localfile>
```

**5. Add Wazuh rules** to `/var/ossec/etc/rules/local_rules.xml` (IDs 100100+, separate from the 100010 rule in the first guide):

```xml
<group name="limacharlie,edr,">

  <rule id="100100" level="3">
    <decoded_as>json</decoded_as>
    <field name="integration" type="pcre2">^limacharlie$</field>
    <description>LimaCharlie detection: $(lc_cat) on $(lc_hostname)</description>
  </rule>

  <rule id="100101" level="10">
    <if_sid>100100</if_sid>
    <field name="lc_priority" type="pcre2">^([6-9]|10)$</field>
    <description>LimaCharlie high-priority detection: $(lc_cat) on $(lc_hostname)</description>
  </rule>

  <rule id="100102" level="8">
    <if_sid>100100</if_sid>
    <field name="lc_author" type="pcre2">^_sigma$</field>
    <description>LimaCharlie Sigma-ruleset detection: $(lc_cat) on $(lc_hostname)</description>
  </rule>

</group>
```

```bash
sudo systemctl restart wazuh-manager
```

**6. Test before trusting it** with `wazuh-logtest`, pasting a sample line:

```json
{"integration":"limacharlie","lc_id":"x1","lc_cat":"Test detection","lc_author":"_sigma","lc_priority":"8","lc_hostname":"win-endpoint","lc_sid":"abc","lc_link":"","lc_event":"{}"}
```

You should see rule `100100`, then `100101`/`100102` as appropriate.

**Result:** LimaCharlie detections appear in the Wazuh dashboard alongside native Wazuh alerts, with a deep link back to the LimaCharlie console in `lc_link`.

> **Important:** the poller uses the REST endpoint `GET /insight/{oid}/detections` (parameters `start`, `end`, `limit`, `cursor`) and a JWT from `jwt.limacharlie.io`. I confirmed the endpoint and parameters, but I could not confirm the exact **field names** inside each returned detection record. The script uses `.get()` fallbacks so a missing field degrades to an empty value rather than crashing; after the first run, inspect a raw record and adjust the field names if `lc_cat`/`lc_hostname` come through empty.

### 8.3 Ideas that are not turnkey (not built or tested here)

- A Wazuh Active Response script that calls the LimaCharlie CLI/API to run a command on a sensor when a specific Wazuh rule fires.
- A LimaCharlie D&R rule over the Bridge A events that takes action when a high-severity Wazuh rule appears.

Both are plausible but need your own design and testing — particularly because of the isolation caveat in §7.3.

---

## 9. Extensions catalog

Per LimaCharlie's documentation structure. "Lab fit" is my assessment for a 2-sensor free-tier lab. **Check each marketplace listing's current price before subscribing.**

| Extension | What it does | Lab fit |
|---|---|---|
| Reliable Tasking | Queues tasks for sensors that are offline | Required for Artifact |
| Artifact | File / `wel://` / MUL collection rules | **Essential** |
| Atomic Red Team | Runs ATT&CK tests on Windows sensors; results in the `ext-atomic-red-team` adapter timeline | **Essential** for validation |
| YARA Manager / YARA | YARA scanning on demand or scheduled | High |
| Payload Manager | Stores payloads you push to sensors | Medium |
| Integrity | File/registry integrity monitoring | Medium (Wazuh FIM overlaps) |
| Exfil | Controls which event types stream to the cloud | Medium — governs volume |
| Dumper | Memory dump collection | Medium (forensics practice) |
| Velociraptor | Deploys Velociraptor for DFIR artifact collection (e.g., KAPE triage) | Medium; confirm it works under the proxy |
| Hayabusa | Runs Hayabusa on `.evtx` files; results to a timeline | Low — billed per GB |
| Plaso | Super-timeline analysis | Low |
| Zeek / Strelka | Network (PCAP) / file analysis | Low — billed per GB (Zeek) |
| Lookup Manager | Threat-intel lookups usable in rules | Medium |
| OTX | AlienVault OTX feed integration | Medium |
| Cases | Case management | Medium |
| Playbook (LABS) | Scripted response workflows | Experimental |
| Git Sync | Org configuration in Git | Medium |
| Vulnerability Reporting | Vulnerability data from sensors | Low (Wazuh covers) |
| Application Control, DLP, EPP | Allow/deny, DLP, Defender management | Low |
| Sensor Cull, Usage Alerts | Housekeeping and usage notifications | Low |

**AI features:** the documentation describes AI sessions (including D&R-driven sessions) and an MCP server for connecting AI assistants. These use your own AI provider and send data to it — an optional extra I did not test, and one to weigh against the lab's isolation goals.

---

## 10. End-to-end validation plan

Goal: prove that **one technique** is seen by **both** tools and that the LimaCharlie detection reaches Wazuh.

**Preconditions:** Sections 4 and 5 complete; Sigma add-on subscribed; Bridge B running; both agents active in Wazuh; both sensors online in LimaCharlie; `snapshot` taken of `win-endpoint` first.

1. **Prepare the target sensor.** In the Atomic Red Team extension, run the *prepare* step on `win-endpoint`. This installs the Atomic Red Team framework and dependencies on the host. **I could not confirm where the endpoint fetches this from — assume it needs internet.** If it fails under Option A, run the prepare step in a temporary-NAT window with the proxy disabled (§7.3 procedure), then restore.
2. **Run a test.** Select a technique (e.g. T1003.001 as in the first guide) and run it, with cleanup enabled. Sensors must be online. Defender may quarantine test files — expected in the lab.
3. **LimaCharlie side:** check **Detections** (look for author `_sigma` entries) and the sensor **Timeline**. Check the `ext-atomic-red-team` adapter timeline for the test receipt/results and correlate with `RECEIPT` events on the sensor.
4. **Wazuh side (native):** dashboard → Threat Hunting / MITRE ATT&CK for Sysmon-driven alerts and your hand-ported rule `100010`.
5. **Wazuh side (bridge):** within ~1–2 minutes, rules `100100`/`100101`/`100102` should alert for the LimaCharlie detection (Bridge B).
6. **Reverse bridge:** in LimaCharlie, search the `wazuh-mgr-alerts` sensor timeline for the Wazuh alerts from step 4 (Bridge A).
7. **Response test:** apply the `deny_tree` rule from §6.3 to a harmless renamed test binary and confirm the process tree is killed. Do **not** test isolation here (§7.3).
8. **Score it** with a small table you keep per technique:

   | Technique | Wazuh native | Wazuh hand-ported Sigma | LC native Sigma | LC EDR event | Gap / action |
   |---|---|---|---|---|---|

9. **Revert** `win-endpoint` to the golden snapshot.

---

## 11. Operating model and lab hygiene

- **Golden snapshots:** take one after the Wazuh agent + Sysmon steps (guide), and a **new one after the LimaCharlie sensor is installed and the proxy configured** — with the temporary NAT adapter already removed.
- **Cloning warning:** a sensor stores an identity on disk (default `C:\ProgramData\limacharlie` on Windows, `/opt/limacharlie` on Linux). Cloning a VM that already has an enrolled sensor can produce duplicate sensor identities. LimaCharlie documents a **VDI Templates** procedure for this — read it before making linked clones of an endpoint that has the sensor, or clone **before** installing the sensor.
- **Free-tier discipline:** only two sensors may be online. Before enrolling a replacement, uninstall the old one (`rphcp.exe -c` on Windows, or `uninstall` from the console).
- **Keep the proxy allow-list minimal.** Re-run the "example.com must be refused" test after any Squid change.
- **Never enable IP forwarding on `wazuh-mgr`.**
- **Data handling:** lab telemetry — including command lines — goes to LimaCharlie's cloud in the region you chose. Do not put real credentials or personal data on lab VMs.
- **Secrets:** the API key and installation keys are credentials. Keep them out of screenshots and shell history; rotate them if exposed.
- **Resource impact:** LimaCharlie's FAQ puts the sensor footprint at about 2 MB with typically under 1% CPU. The proxy and poller are negligible.

---

## 12. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Sensor installs but never appears in the web app | No path to the cloud during install | Confirm the temporary NAT adapter is attached and the VM has an address; re-run the install |
| Sensor online with NAT attached, **offline after NAT removed** | Proxy not applied or blocked | Check `LC_PROXY` (system-level on Windows, in the unit on Linux) and restart the service; check Squid `access.log` for `TCP_DENIED` |
| Squid denies `limacharlie.io` | Region uses a different hostname | Add the exact hostname from **Sensors → Add Sensor** to `lc_domains` |
| Sensor connects then drops repeatedly | TLS interception somewhere on the path | The sensor does not support SSL interception — the proxy must only tunnel |
| Windows sensor slow to start on the isolated network | Certificate revocation lookups timing out | Set `LC_LOCAL_CACHE_ONLY_REVOCATION_CHECK=1` |
| Sensor logs show it cannot resolve a hostname | The sensor may be resolving names itself before using the proxy | Needs investigation; a DNS forwarder on `wazuh-mgr` would weaken isolation — prefer finding the exact behavior first |
| Many Sigma rules never fire | Needed Windows event logs not streamed | Add the `wel://` Artifact Collection rules (§5.3) and enable `WEL` in Exfil/Event Collection |
| `wel://` events missing | Rule not yet synced | Wait up to ~10 minutes; confirm Artifact + Reliable Tasking are subscribed |
| Atomic Red Team "prepare" fails | Endpoint cannot reach the source it downloads from | Run in a temporary-NAT, proxy-off window (§7.3) |
| Sensor "stuck" after isolation | Persistent isolation + proxy path | Recovery steps in §7.3 |
| Poller writes nothing | Wrong OID/key, missing permission, or no detections yet | `journalctl -u lc-bridge.service`; test the JWT call manually; check the API key's permissions |
| Poller writes lines but Wazuh alerts show empty `lc_cat` | Field names differ from my assumptions | Inspect a raw record and adjust the script (§8.2 note) |
| Rules `100100+` never match | JSON not decoded or integration field missing | Test with `wazuh-logtest`; confirm the `<localfile>` entry and restart the manager |
| Wazuh alerts adapter stops after midnight | Log rotation | Keep `poll: true` |
| Second sensor refuses to enroll | Over the 2-endpoint free quota | Remove an existing sensor |

---

## 13. Quick reference and links

### Commands

```bash
# --- Proxy (wazuh-mgr) ---
sudo squid -k parse && sudo systemctl restart squid
sudo tail -f /var/log/squid/access.log
ss -ltnp | grep 3128
sysctl net.ipv4.ip_forward                     # must be 0

# --- Temporary internet for an endpoint (VM powered off) ---
VBoxManage modifyvm "win-endpoint" --nic2 nat
VBoxManage modifyvm "win-endpoint" --nic2 none

# --- Sensor install ---
#   Windows:  rphcp.exe -i <KEY>        (service: rphcpsvc)
#   Linux:    sudo /tmp/lc_sensor -i <KEY>
#   Remove:   rphcp.exe -c              (Windows, full clean uninstall)

# --- Proxy env var ---
#   Windows:  setx /M LC_PROXY "192.168.100.10:3128"   (set to "!" to disable)
#   Linux:    systemctl edit <service>  -> Environment=LC_PROXY=192.168.100.10:3128

# --- CLI ---
pip install limacharlie
limacharlie login
limacharlie sensor list
limacharlie dr export > rules.yaml
limacharlie dr import --input-file rules.yaml
limacharlie dr replay --name <rule> --start <epoch> --end <epoch>

# --- Bridges (wazuh-mgr) ---
sudo systemctl status lc-adapter-wazuh lc-bridge.timer
sudo journalctl -u lc-bridge.service -n 50
sudo /var/ossec/bin/wazuh-logtest
```

### Rule IDs used

| ID | Meaning |
|---|---|
| 100010 | Hand-ported Sigma (Mimikatz) from the first guide |
| 100100 | Any LimaCharlie detection ingested via the poller |
| 100101 | LimaCharlie high-priority detection |
| 100102 | LimaCharlie Sigma-ruleset detection |

### Links

- LimaCharlie documentation — <https://docs.limacharlie.io/>
- Pricing — <https://www.limacharlie.com/pricing>
- Sensor connectivity & proxy — <https://docs.limacharlie.io/2-sensors-deployment/connectivity/>
- Windows sensor install — <https://docs.limacharlie.io/2-sensors-deployment/endpoint-agent/windows/installation/>
- Linux sensor install — <https://docs.limacharlie.io/2-sensors-deployment/endpoint-agent/linux/installation/>
- Agent CLI & environment reference — <https://docs.limacharlie.io/2-sensors-deployment/endpoint-agent/cli-reference/>
- Sigma converter — <https://docs.limacharlie.io/3-detection-response/managed-rulesets/sigma-converter/>
- Sysmon / Windows Event Log ingestion — <https://docs.limacharlie.io/2-sensors-deployment/tutorials/sysmon-logs/>
- Response actions — <https://docs.limacharlie.io/8-reference/response-actions/>
- Atomic Red Team extension — <https://docs.limacharlie.io/5-integrations/extensions/third-party/atomic-red-team/>
- Adapters — <https://docs.limacharlie.io/2-sensors-deployment/adapters/>
- Python SDK / CLI — <https://docs.limacharlie.io/6-developer-guide/sdks/python-sdk/>
- Wazuh syslog / JSON decoder docs — <https://documentation.wazuh.com/current/user-manual/ruleset/decoders/json-decoder.html>

---

## 14. Verification status and open questions

**Confirmed against current documentation:**
- Free tier: Community Edition, up to 2 endpoints, 1-year retention; Sigma ruleset is free and refreshed every 15 minutes; `_sigma` author label.
- Sensor needs one TCP/443 connection to a LimaCharlie domain; supports unauthenticated HTTP `CONNECT` via `LC_PROXY`; no SSL interception; `LC_LOCAL_CACHE_ONLY_REVOCATION_CHECK`.
- Windows install (`rphcp.exe -i`, MSI properties, service `rphcpsvc`, download URLs); Linux binary download and `-i` install; Linux sensor uses eBPF (kernel 4.4+).
- `wel://` Artifact Collection rules stream Windows/Sysmon events and are included in the sensor price; Artifact requires Reliable Tasking.
- Isolation behavior (blocks all but the LimaCharlie cloud; not persistent as a bare command, persistent as a D&R action).
- Atomic Red Team extension: Windows sensors only, sensors must be online, a prepare step is required.
- File/JSON adapter parameters and adapter download URL; Sigma converter endpoints.
- `GET /insight/{oid}/detections` parameters; CLI verbs (`limacharlie dr export|import|replay`, `sensor list`, `org list`).
