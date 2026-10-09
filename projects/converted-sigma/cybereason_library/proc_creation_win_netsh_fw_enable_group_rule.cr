// Title: Netsh Allow Group Policy on Microsoft Defender Firewall
// ID: 347906f3-e207-4d18-ae5b-a9403d6bcdef
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-01-09
// Tags: attack.defense-impairment, attack.t1686.003
// Description: Adversaries may modify system firewalls in order to bypass controls limiting network usage
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains "advfirewall" AND CommandLine contains "firewall" AND CommandLine contains "set" AND CommandLine contains "rule" AND CommandLine contains "group=" AND CommandLine contains "new" AND CommandLine contains "enable=Yes")) AND ((Image="*\\netsh.exe") OR (OriginalFileName == "netsh.exe")))
