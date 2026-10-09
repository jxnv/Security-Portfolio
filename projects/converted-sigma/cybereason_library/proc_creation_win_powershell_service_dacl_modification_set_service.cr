// Title: Suspicious Service DACL Modification Via Set-Service Cmdlet
// ID: a95b9b42-1308-4735-a1af-abb1c5e6f5ac
// Status: test
// Level: high
// Author: Nasreddine Bencherchali (Nextron Systems)
// Date: 2022-10-18
// Tags: attack.privilege-escalation, attack.persistence, attack.t1543.003
// Description: Detects suspicious DACL modifications via the "Set-Service" cmdlet using the "SecurityDescriptorSddl" flag (Only available with PowerShell 7) that can be used to hide services or make them unstopable
// Converted by: Sigma Universal SIEM/EDR CLI

(((Image="*\\pwsh.exe") OR (OriginalFileName == "pwsh.dll")) AND ((CommandLine contains "-SecurityDescriptorSddl " OR CommandLine contains "-sd ")) AND ((CommandLine contains "Set-Service " AND CommandLine contains "D;;") AND (CommandLine contains ";;;IU" OR CommandLine contains ";;;SU" OR CommandLine contains ";;;BA" OR CommandLine contains ";;;SY" OR CommandLine contains ";;;WD")))
