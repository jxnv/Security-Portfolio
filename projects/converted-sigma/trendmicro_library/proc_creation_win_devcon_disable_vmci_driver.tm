// Title: Devcon Execution Disabling VMware VMCI Device
// ID: 85f520e7-6f5e-43ca-874c-222e5bf9c0de
// Status: experimental
// Level: high
// Author: Matt Anderson, Dray Agha, Anna Pham (Huntress)
// Date: 2026-01-02
// Tags: attack.persistence, attack.privilege-escalation, attack.defense-impairment, attack.t1543.003, attack.t1685
// Description: Detects execution of devcon.exe with commands that disable the VMware Virtual Machine Communication Interface (VMCI) device.
// This can be legitimate during VMware Tools troubleshooting or driver conflicts, but may also indicate malware attempting to hijack communication with the hardware via the VMCI device.
// This has been used to facilitate VMware ESXi vulnerability exploits to escape VMs and execute code on the ESXi host.
// Converted by: Sigma Universal SIEM/EDR CLI

((CommandLine: "* disable *") AND ((Image="*\\devcon.exe") OR (OriginalFileName: "DevCon.exe")) AND ((CommandLine: "*15AD&DEV_0740*" OR CommandLine: "*VMWVMCIHOSTDEV*")))
