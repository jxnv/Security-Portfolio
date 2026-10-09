// Title: New Root Certificate Installed Via CertMgr.EXE
// ID: ff992eac-6449-4c60-8c1d-91c9722a1d48
// Status: test
// Level: medium
// Author: oscd.community, @redcanary, Zach Stanford @svch0st
// Date: 2023-03-05
// Tags: attack.defense-impairment, attack.t1553.004
// Description: Detects execution of "certmgr" with the "add" flag in order to install a new certificate on the system.
// Adversaries may install a root certificate on a compromised system to avoid warnings when connecting to adversary controlled web servers.
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine: "*/add*" AND CommandLine: "*root*")) AND ((Image="*\\CertMgr.exe") OR (OriginalFileName: "CERTMGT.EXE")))
