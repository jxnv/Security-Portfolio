// Title: Firewall Configuration Discovery Via Netsh.EXE
// ID: 0e4164da-94bc-450d-a7be-a4b176179f1f
// Status: test
// Level: low
// Author: frack113, Christopher Peacock '@securepeacock', SCYTHE '@scythe_io'
// Date: 2021-12-07
// Tags: attack.discovery, attack.t1016
// Description: Adversaries may look for details about the network configuration and settings of systems they access or through information discovery of remote systems
// Converted by: Sigma Universal SIEM/EDR CLI

(((CommandLine contains "netsh" AND CommandLine contains "show " AND CommandLine contains "firewall ") AND (CommandLine contains "config " OR CommandLine contains "state " OR CommandLine contains "rule " OR CommandLine contains "name=all")) AND ((Image="*\\netsh.exe") OR (OriginalFileName == "netsh.exe")))
