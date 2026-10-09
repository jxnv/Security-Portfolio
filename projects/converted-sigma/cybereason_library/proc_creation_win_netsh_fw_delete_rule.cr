// Title: Firewall Rule Deleted Via Netsh.EXE
// ID: 1a5fefe6-734f-452e-a07d-fc1c35bce4b2
// Status: test
// Level: medium
// Author: frack113
// Date: 2022-08-14
// Tags: attack.defense-impairment, attack.t1686.003
// Description: Detects the removal of a port or application rule in the Windows Firewall configuration using netsh
// Converted by: Sigma Universal SIEM/EDR CLI

((((CommandLine contains "firewall" AND CommandLine contains "delete ")) AND ((Image="*\\netsh.exe") OR (OriginalFileName == "netsh.exe"))) AND NOT (((ParentImage="*\\instup.exe" AND CommandLine contains "advfirewall firewall delete rule name=\"Avast Antivirus Admin Client\"") OR (ParentImage="*\\Dropbox.exe" AND CommandLine contains "name=Dropbox"))))
